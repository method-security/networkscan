package smb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math/bits"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Windows version constants
const (
	WinUnknown = iota
	WinXP
	WinServer2003
	WinVista
	WinServer2008
	Win7
	WinServer2008R2
	Win8
	WinServer2012
	Win81
	WinServer2012R2
	Win10
	WinServer2016
	WinServer2019
	WinServer2022
	Win11
)

// Global variables for cryptographic operations
var (
	S1         = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	S2         = []byte("0123456789012345678901234567890123456789\x00")
	S3         = []byte("NTPASSWORD\x00")
	BootKey    []byte
	LSAKey     []byte
	NLKMKey    []byte
	VistaStyle bool
)

var aes256Constant = []byte{0x6B, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6F, 0x73, 0x7B, 0x9B, 0x5B, 0x2B, 0x93, 0x13, 0x2B, 0x93, 0x5C, 0x9B, 0xDC, 0xDA, 0xD9, 0x5C, 0x98, 0x99, 0xC4, 0xCA, 0xE4, 0xDE, 0xE6, 0xD6, 0xCA, 0xE4}

// GetOSVersion determines Windows OS version from build and version info
func GetOSVersion(currentBuild int, currentVersion float64, server bool) byte {
	currentVersionStr := strconv.FormatFloat(currentVersion, 'f', 1, 64)
	if server {
		switch {
		case currentBuild >= 3790 && currentBuild < 6001:
			return WinServer2003
		case currentBuild >= 6001 && currentBuild < 7601:
			return WinServer2008
		case currentBuild >= 7601 && currentBuild < 9200:
			return WinServer2008R2
		case currentBuild >= 9200 && currentBuild < 9600:
			return WinServer2012
		case currentBuild >= 9200 && currentBuild < 14393:
			return WinServer2012R2
		case currentBuild >= 14393 && currentBuild < 17763:
			return WinServer2016
		case currentBuild >= 17763 && currentBuild < 20348:
			return WinServer2019
		case currentBuild >= 20348:
			return WinServer2022
		default:
			return WinUnknown
		}
	} else {
		switch currentVersionStr {
		case "5.1":
			return WinXP
		case "6.0":
			return WinVista
		case "6.1":
			return Win7
		case "6.2":
			return Win8
		case "6.3":
			return Win81
		case "10.0":
			if currentBuild < 22000 {
				return Win10
			}
			return Win11
		default:
			return WinUnknown
		}
	}
}

// IsWin10After1607 checks if Windows version is Windows 10 Anniversary Update or later
func IsWin10After1607(build int, version float64) (bool, error) {
	return build >= 14393, nil
}

// SHA256 performs SHA-256 hash with multiple rounds
func SHA256(key, value []byte, rounds int) []byte {
	if rounds == 0 {
		rounds = 1000
	}
	h := sha256.New()
	h.Write(key)
	for i := 0; i < rounds; i++ {
		h.Write(value)
	}
	return h.Sum(nil)
}

// DecryptAES decrypts data using AES with CBC mode
func DecryptAES(key, ciphertext, iv []byte) ([]byte, error) {
	nullIV := true
	if iv != nil {
		for _, b := range iv {
			if b != 0 {
				nullIV = false
				break
			}
		}
	}

	if nullIV || iv == nil {
		iv = make([]byte, aes.BlockSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

// EncryptAES encrypts data using AES with CBC mode
func EncryptAES(key, plaintext, iv []byte) ([]byte, error) {
	if iv == nil {
		iv = make([]byte, aes.BlockSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Add PKCS7 padding
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padtext := make([]byte, len(plaintext)+padding)
	copy(padtext, plaintext)
	for i := len(plaintext); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}

	if len(padtext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("plaintext is not a multiple of the block size")
	}

	ciphertext := make([]byte, len(padtext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padtext)

	return ciphertext, nil
}

// DecryptRC4 decrypts data using RC4
func DecryptRC4(key, ciphertext []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

// EncryptRC4 encrypts data using RC4
func EncryptRC4(key, plaintext []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// DecryptDES decrypts data using DES
func DecryptDES(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 8 {
		return nil, fmt.Errorf("DES key must be 8 bytes")
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%8 != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of 8")
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += 8 {
		block.Decrypt(plaintext[i:i+8], ciphertext[i:i+8])
	}

	return plaintext, nil
}

// EncryptDES encrypts data using DES
func EncryptDES(key, plaintext []byte) ([]byte, error) {
	if len(key) != 8 {
		return nil, fmt.Errorf("DES key must be 8 bytes")
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Add PKCS5 padding for DES
	padding := 8 - len(plaintext)%8
	padtext := make([]byte, len(plaintext)+padding)
	copy(padtext, plaintext)
	for i := len(plaintext); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}

	ciphertext := make([]byte, len(padtext))
	for i := 0; i < len(padtext); i += 8 {
		block.Encrypt(ciphertext[i:i+8], padtext[i:i+8])
	}

	return ciphertext, nil
}

// PBKDF2Derive derives a key using PBKDF2
func PBKDF2Derive(password, salt []byte, iterations, keyLength int, hashFunc func() hash.Hash) []byte {
	return pbkdf2.Key(password, salt, iterations, keyLength, hashFunc)
}

// MD5Hash calculates MD5 hash
func MD5Hash(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

// SHA1Hash calculates SHA-1 hash
func SHA1Hash(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

// SHA256Hash calculates SHA-256 hash
func SHA256Hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// Kerberos and machine account key derivation

// CalcMachineAESKeys calculates AES keys for machine account
func CalcMachineAESKeys(hostname, domain string, password []byte) ([]byte, []byte, error) {
	// Kerberos principal: hostname$@DOMAIN
	principal := strings.ToUpper(hostname) + "$@" + strings.ToUpper(domain)

	// Convert to UTF-8 bytes
	principalBytes := []byte(principal)

	// Derive AES-128 key
	aes128Constant := []byte{0x6B, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6F, 0x73, 0x7B, 0x9B, 0x5B, 0x2B, 0x93, 0x13, 0x2B, 0x93}
	aes128Key := pbkdf2.Key(password, append(principalBytes, aes128Constant...), 4096, 16, sha1.New)

	// Derive AES-256 key
	aes256Key := pbkdf2.Key(password, append(principalBytes, aes256Constant...), 4096, 32, sha1.New)

	return aes128Key, aes256Key, nil
}

// Bit manipulation utilities

// ROL performs rotate left operation
func ROL(value uint32, shift uint) uint32 {
	return bits.RotateLeft32(value, int(shift))
}

// ROR performs rotate right operation
func ROR(value uint32, shift uint) uint32 {
	return bits.RotateLeft32(value, -int(shift))
}

// BytesToUint32LE converts little-endian bytes to uint32
func BytesToUint32LE(data []byte) uint32 {
	if len(data) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(data)
}

// Uint32LEToBytes converts uint32 to little-endian bytes
func Uint32LEToBytes(value uint32) []byte {
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, value)
	return bytes
}

// BytesToUint64LE converts little-endian bytes to uint64
func BytesToUint64LE(data []byte) uint64 {
	if len(data) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(data)
}

// Uint64LEToBytes converts uint64 to little-endian bytes
func Uint64LEToBytes(value uint64) []byte {
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, value)
	return bytes
}

// String utilities for crypto operations

// CleanupString removes null bytes and trims whitespace
func CleanupString(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	return strings.TrimSpace(s)
}

// BytesToHex converts bytes to hex string
func BytesToHex(data []byte) string {
	return fmt.Sprintf("%x", data)
}

// HexToBytes converts hex string to bytes
func HexToBytes(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		return nil, fmt.Errorf("hex string must have even length")
	}

	bytes := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		var b byte
		_, err := fmt.Sscanf(hexStr[i:i+2], "%02x", &b)
		if err != nil {
			return nil, err
		}
		bytes[i/2] = b
	}

	return bytes, nil
}

// CompareBytes compares two byte slices
func CompareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// XORBytes performs XOR operation on two byte slices
func XORBytes(a, b []byte) []byte {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	result := make([]byte, minLen)
	for i := 0; i < minLen; i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// PadPKCS7 adds PKCS#7 padding to data
func PadPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, len(data)+padding)
	copy(padtext, data)
	for i := len(data); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}
	return padtext
}

// UnpadPKCS7 removes PKCS#7 padding from data
func UnpadPKCS7(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	padding := int(data[len(data)-1])
	if padding == 0 || padding > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}

	// Verify padding bytes
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padding], nil
}
