// Package smb provides SMB penetration testing functionality including secdump operations
// This file contains utility functions adapted from github.com/jfjallid/go-secdump
//
// Original copyright notice:
// MIT License
// Copyright (c) 2023 Jonas Fjällid
package smb

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	gosmb "github.com/jfjallid/go-smb/smb"
)

// WindowsOSInfo represents Windows OS version information
type WindowsOSInfo struct {
	MajorVersion uint32
	MinorVersion uint32
	BuildNumber  uint32
	ProductName  string
}

// RegistryConnection represents a connection to remote registry service
type RegistryConnection struct {
	Session *gosmb.Connection
	Handle  interface{} // DCE/RPC handle for registry operations
}

// RegistryValue represents a registry value with type and data
type RegistryValue struct {
	Name string
	Type uint32
	Data []byte
}

// RegistryKey represents a registry key with subkeys and values
type RegistryKey struct {
	Name     string
	SubKeys  []string
	Values   []RegistryValue
	Class    string
	Modified int64
}

// Registry data type constants
const (
	RegNone                     = 0
	RegSZ                       = 1
	RegExpandSZ                 = 2
	RegBinary                   = 3
	RegDword                    = 4
	RegDwordLittleEndian        = 4
	RegDwordBigEndian           = 5
	RegLink                     = 6
	RegMultiSZ                  = 7
	RegResourceList             = 8
	RegFullResourceDescriptor   = 9
	RegResourceRequirementsList = 10
	RegQword                    = 11
	RegQwordLittleEndian        = 11
)

// ConnectToRegistry establishes a connection to the remote registry service
func ConnectToRegistry(session *gosmb.Connection) (*RegistryConnection, error) {
	return nil, fmt.Errorf("not implemented")
}

// OpenRegistryKey opens a registry key for reading
func (rc *RegistryConnection) OpenRegistryKey(keyPath string) (*RegistryKey, error) {
	return nil, fmt.Errorf("not implemented")
}

// ReadRegistryValue reads a value from an open registry key
func (rc *RegistryConnection) ReadRegistryValue(key *RegistryKey, valueName string) (*RegistryValue, error) {
	return nil, fmt.Errorf("not implemented")
}

// EnumerateSubKeys lists all subkeys under the given registry key
func (rc *RegistryConnection) EnumerateSubKeys(key *RegistryKey) ([]string, error) {
	return nil, fmt.Errorf("not implemented")
}

// EnumerateValues lists all values under the given registry key
func (rc *RegistryConnection) EnumerateValues(key *RegistryKey) ([]RegistryValue, error) {
	return nil, fmt.Errorf("not implemented")
}

// CloseRegistryKey closes an open registry key
func (rc *RegistryConnection) CloseRegistryKey(key *RegistryKey) error {
	return fmt.Errorf("not implemented")
}

// Disconnect closes the registry connection
func (rc *RegistryConnection) Disconnect() error {
	return fmt.Errorf("not implemented")
}

// Registry data parsing utilities

// ParseRegistryValue parses a registry value from raw bytes
func ParseRegistryValue(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for registry value")
	}

	// Simple parsing - real implementation would handle different value types
	return data[4:], nil
}

// UTF16LEBytesToString converts UTF-16LE bytes to string
func UTF16LEBytesToString(data []byte) (string, error) {
	if len(data)%2 != 0 {
		return "", fmt.Errorf("UTF-16LE data must have even length")
	}

	// Convert bytes to UTF-16 code units
	utf16Data := make([]uint16, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		utf16Data[i/2] = binary.LittleEndian.Uint16(data[i : i+2])
	}

	// Decode UTF-16 to string
	runes := utf16.Decode(utf16Data)
	return string(runes), nil
}

// StringToUTF16LEBytes converts string to UTF-16LE bytes
func StringToUTF16LEBytes(s string) []byte {
	// Convert string to runes
	runes := []rune(s)

	// Encode as UTF-16
	utf16Codes := utf16.Encode(runes)

	// Convert to little-endian bytes
	bytes := make([]byte, len(utf16Codes)*2)
	for i, code := range utf16Codes {
		binary.LittleEndian.PutUint16(bytes[i*2:], code)
	}

	return bytes
}

// IsPrintableString checks if a byte array represents a printable string
func IsPrintableString(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Check for UTF-16LE string (common in Windows registry)
	if len(data)%2 == 0 {
		isUTF16 := true
		for i := 0; i < len(data); i += 2 {
			if i+1 >= len(data) {
				break
			}
			char := binary.LittleEndian.Uint16(data[i : i+2])
			// Check if it's a printable ASCII character in UTF-16
			if char == 0 {
				break // Null terminator
			}
			if char > 127 || (char < 32 && char != 9 && char != 10 && char != 13) {
				isUTF16 = false
				break
			}
		}
		if isUTF16 {
			return true
		}
	}

	// Check for ASCII string
	for _, b := range data {
		if b == 0 {
			break // Null terminator
		}
		if b < 32 || b > 126 {
			return false
		}
	}

	return true
}

// ExtractStringFromRegistryData extracts a string from registry data based on type
func ExtractStringFromRegistryData(data []byte, dataType uint32) (string, error) {
	switch dataType {
	case RegSZ, RegExpandSZ:
		// UTF-16LE string
		return UTF16LEBytesToString(data)
	case RegMultiSZ:
		// Multiple UTF-16LE strings separated by null terminators
		return UTF16LEBytesToString(data) // Simplified - real implementation would split
	case RegBinary:
		// Binary data - check if it's printable
		if IsPrintableString(data) {
			if len(data)%2 == 0 {
				// Try UTF-16LE first
				if str, err := UTF16LEBytesToString(data); err == nil {
					return str, nil
				}
			}
			// Fall back to ASCII
			return string(data), nil
		}
		return fmt.Sprintf("0x%x", data), nil
	case RegDword:
		if len(data) >= 4 {
			value := BytesToUint32LE(data)
			return fmt.Sprintf("0x%08x", value), nil
		}
		return "0x0", nil
	case RegQword:
		if len(data) >= 8 {
			value := binary.LittleEndian.Uint64(data)
			return fmt.Sprintf("0x%016x", value), nil
		}
		return "0x0", nil
	default:
		return fmt.Sprintf("0x%x", data), nil
	}
}

// Registry key path utilities

// NormalizeRegistryPath normalizes a registry key path
func NormalizeRegistryPath(path string) string {
	// Convert forward slashes to backslashes
	// Remove duplicate slashes
	// Ensure consistent formatting

	// Simplified implementation
	return path
}

// SplitRegistryPath splits a registry path into hive and key components
func SplitRegistryPath(path string) (hive, key string) {
	// Implement proper path splitting
	// Handle paths like "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows"

	return "HKEY_LOCAL_MACHINE", path
}

// GetRegistryHiveHandle gets a handle to a registry hive
func GetRegistryHiveHandle(hive string) (interface{}, error) {
	return nil, fmt.Errorf("not implemented")
}

// Registry data validation

// IsValidRegistryKeyName checks if a string is a valid registry key name
func IsValidRegistryKeyName(name string) bool {
	if len(name) == 0 || len(name) > 255 {
		return false
	}

	// Check for invalid characters
	invalidChars := []rune{'\\', '/', ':', '*', '?', '"', '<', '>', '|'}
	for _, char := range name {
		for _, invalid := range invalidChars {
			if char == invalid {
				return false
			}
		}
	}

	return true
}

// IsValidRegistryValueName checks if a string is a valid registry value name
func IsValidRegistryValueName(name string) bool {
	// Value names have fewer restrictions than key names
	if len(name) > 16383 { // Maximum value name length
		return false
	}

	return true
}

// Registry security utilities

// GetRegistryKeySecurityDescriptor retrieves security information for a registry key
func GetRegistryKeySecurityDescriptor(rc *RegistryConnection, key *RegistryKey) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// CheckRegistryKeyAccess checks if we have specific access to a registry key
func CheckRegistryKeyAccess(rc *RegistryConnection, key *RegistryKey, accessMask uint32) (bool, error) {
	return false, fmt.Errorf("not implemented")
}

// Registry backup and restore utilities

// BackupRegistryKey creates a backup of a registry key and its subkeys
func BackupRegistryKey(rc *RegistryConnection, key *RegistryKey) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// RestoreRegistryKey restores a registry key from backup data
func RestoreRegistryKey(rc *RegistryConnection, keyPath string, backupData []byte) error {
	return fmt.Errorf("not implemented")
}
