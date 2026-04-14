package smb

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Minimal Windows registry hive (regf) file parser for offline SAM/LSA extraction.
// Supports navigating key hierarchy, reading values, class names, and listing subkeys.

const (
	regfMagic   = 0x66676572 // "regf"
	regfHdrSize = 0x1000     // 4096 byte file header
	nkSig       = 0x6B6E     // "nk"
	vkSig       = 0x6B76     // "vk"
	lfSig       = 0x666C     // "lf"
	lhSig       = 0x686C     // "lh"
	riSig       = 0x6972     // "ri"
	liSig       = 0x696C     // "li"
	nkCompName  = 0x0020     // key name is ASCII-compressed
	vkCompName  = 0x0001     // value name is ASCII-compressed
)

// RegistryHive represents a parsed registry hive file.
type RegistryHive struct {
	data       []byte
	rootOffset uint32
}

// HiveKey represents a key node (NK record) in the hive.
type HiveKey struct {
	hive          *RegistryHive
	offset        uint32
	flags         uint16
	numSubkeys    uint32
	subkeysOffset uint32
	numValues     uint32
	valuesOffset  uint32
	classOffset   uint32
	classLen      uint16
	Name          string
}

// HiveValue represents a value node (VK record) in the hive.
type HiveValue struct {
	Name     string
	DataType uint32
	Data     []byte
}

// ParseRegistryHive parses raw bytes as a Windows registry hive file.
func ParseRegistryHive(data []byte) (*RegistryHive, error) {
	if len(data) < regfHdrSize+32 {
		return nil, fmt.Errorf("data too small for registry hive (%d bytes)", len(data))
	}
	sig := binary.LittleEndian.Uint32(data[0:4])
	if sig != regfMagic {
		return nil, fmt.Errorf("invalid regf signature: 0x%x", sig)
	}
	rootOffset := binary.LittleEndian.Uint32(data[0x24:0x28])
	return &RegistryHive{data: data, rootOffset: rootOffset}, nil
}

// cellData returns the file offset of a cell's content (skipping the 4-byte size field).
// All cell offsets in regf are relative to the start of the hive bins area (file offset 0x1000).
func (h *RegistryHive) cellData(offset uint32) int {
	return int(offset) + regfHdrSize + 4
}

// RootKey returns the root key of the hive.
func (h *RegistryHive) RootKey() (*HiveKey, error) {
	return h.readKey(h.rootOffset)
}

func (h *RegistryHive) readKey(offset uint32) (*HiveKey, error) {
	pos := h.cellData(offset)
	if pos+0x4C > len(h.data) {
		return nil, fmt.Errorf("key node out of bounds at offset 0x%x", offset)
	}
	sig := binary.LittleEndian.Uint16(h.data[pos : pos+2])
	if sig != nkSig {
		return nil, fmt.Errorf("expected nk signature at 0x%x, got 0x%x", pos, sig)
	}
	k := &HiveKey{hive: h, offset: offset}
	k.flags = binary.LittleEndian.Uint16(h.data[pos+2 : pos+4])
	k.numSubkeys = binary.LittleEndian.Uint32(h.data[pos+0x14 : pos+0x18])
	k.subkeysOffset = binary.LittleEndian.Uint32(h.data[pos+0x1C : pos+0x20])
	k.numValues = binary.LittleEndian.Uint32(h.data[pos+0x24 : pos+0x28])
	k.valuesOffset = binary.LittleEndian.Uint32(h.data[pos+0x28 : pos+0x2C])
	k.classOffset = binary.LittleEndian.Uint32(h.data[pos+0x30 : pos+0x34])
	nameLen := int(binary.LittleEndian.Uint16(h.data[pos+0x48 : pos+0x4A]))
	k.classLen = binary.LittleEndian.Uint16(h.data[pos+0x4A : pos+0x4C])
	if pos+0x4C+nameLen > len(h.data) {
		return nil, fmt.Errorf("key name extends past data")
	}
	nameBytes := h.data[pos+0x4C : pos+0x4C+nameLen]
	if k.flags&nkCompName != 0 {
		k.Name = string(nameBytes) // ASCII
	} else {
		k.Name = decodeUTF16LE(nameBytes)
	}
	return k, nil
}

// ClassName returns the class name of this key (used for boot key extraction).
func (k *HiveKey) ClassName() string {
	if k.classLen == 0 || k.classOffset == 0xFFFFFFFF {
		return ""
	}
	pos := k.hive.cellData(k.classOffset)
	end := pos + int(k.classLen)
	if end > len(k.hive.data) {
		return ""
	}
	raw := k.hive.data[pos:end]
	// Class names are typically stored as UTF-16LE
	if len(raw)%2 == 0 && len(raw) >= 2 {
		decoded := decodeUTF16LE(raw)
		if decoded != "" {
			return decoded
		}
	}
	return string(raw)
}

// Subkeys returns all subkeys of this key.
func (k *HiveKey) Subkeys() ([]*HiveKey, error) {
	if k.numSubkeys == 0 {
		return nil, nil
	}
	return k.hive.readSubkeyList(k.subkeysOffset)
}

func (h *RegistryHive) readSubkeyList(offset uint32) ([]*HiveKey, error) {
	pos := h.cellData(offset)
	if pos+4 > len(h.data) {
		return nil, fmt.Errorf("subkey list out of bounds at 0x%x", offset)
	}
	sig := binary.LittleEndian.Uint16(h.data[pos : pos+2])
	count := int(binary.LittleEndian.Uint16(h.data[pos+2 : pos+4]))
	var keys []*HiveKey
	switch sig {
	case lfSig, lhSig:
		// Array of (offset, hash/hint) pairs, 8 bytes each
		for i := 0; i < count; i++ {
			ep := pos + 4 + i*8
			if ep+4 > len(h.data) {
				break
			}
			keyOff := binary.LittleEndian.Uint32(h.data[ep : ep+4])
			key, err := h.readKey(keyOff)
			if err != nil {
				continue
			}
			keys = append(keys, key)
		}
	case riSig:
		// Array of offsets to other subkey lists
		for i := 0; i < count; i++ {
			ep := pos + 4 + i*4
			if ep+4 > len(h.data) {
				break
			}
			listOff := binary.LittleEndian.Uint32(h.data[ep : ep+4])
			sub, err := h.readSubkeyList(listOff)
			if err != nil {
				continue
			}
			keys = append(keys, sub...)
		}
	case liSig:
		// Array of offsets directly to key nodes
		for i := 0; i < count; i++ {
			ep := pos + 4 + i*4
			if ep+4 > len(h.data) {
				break
			}
			keyOff := binary.LittleEndian.Uint32(h.data[ep : ep+4])
			key, err := h.readKey(keyOff)
			if err != nil {
				continue
			}
			keys = append(keys, key)
		}
	default:
		return nil, fmt.Errorf("unknown subkey list type: 0x%x", sig)
	}
	return keys, nil
}

// OpenSubKey navigates a backslash-separated path from this key.
func (k *HiveKey) OpenSubKey(path string) (*HiveKey, error) {
	parts := strings.Split(path, `\`)
	current := k
	for _, part := range parts {
		if part == "" {
			continue
		}
		subkeys, err := current.Subkeys()
		if err != nil {
			return nil, fmt.Errorf("failed to list subkeys of %q: %v", current.Name, err)
		}
		found := false
		for _, sk := range subkeys {
			if strings.EqualFold(sk.Name, part) {
				current = sk
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("subkey %q not found under %q", part, current.Name)
		}
	}
	return current, nil
}

// Values returns all values of this key.
func (k *HiveKey) Values() ([]*HiveValue, error) {
	if k.numValues == 0 {
		return nil, nil
	}
	pos := k.hive.cellData(k.valuesOffset)
	var values []*HiveValue
	for i := uint32(0); i < k.numValues; i++ {
		ep := pos + int(i)*4
		if ep+4 > len(k.hive.data) {
			break
		}
		valOff := binary.LittleEndian.Uint32(k.hive.data[ep : ep+4])
		val, err := k.hive.readValue(valOff)
		if err != nil {
			continue
		}
		values = append(values, val)
	}
	return values, nil
}

// GetValue returns a named value, or error if not found.
func (k *HiveKey) GetValue(name string) (*HiveValue, error) {
	values, err := k.Values()
	if err != nil {
		return nil, err
	}
	for _, v := range values {
		if strings.EqualFold(v.Name, name) {
			return v, nil
		}
	}
	return nil, fmt.Errorf("value %q not found in key %q", name, k.Name)
}

// GetDefaultValue returns the unnamed default value of this key.
func (k *HiveKey) GetDefaultValue() (*HiveValue, error) {
	values, err := k.Values()
	if err != nil {
		return nil, err
	}
	for _, v := range values {
		if v.Name == "" {
			return v, nil
		}
	}
	return nil, fmt.Errorf("default value not found in key %q", k.Name)
}

// GetValueDWORD reads a DWORD value and returns it as uint32.
func (k *HiveKey) GetValueDWORD(name string) (uint32, error) {
	v, err := k.GetValue(name)
	if err != nil {
		return 0, err
	}
	if len(v.Data) < 4 {
		return 0, fmt.Errorf("DWORD value %q too short: %d bytes", name, len(v.Data))
	}
	return binary.LittleEndian.Uint32(v.Data[:4]), nil
}

// GetValueString reads a REG_SZ or REG_EXPAND_SZ value as a Go string.
func (k *HiveKey) GetValueString(name string) (string, error) {
	v, err := k.GetValue(name)
	if err != nil {
		return "", err
	}
	if len(v.Data) < 2 {
		return "", nil
	}
	return decodeUTF16LE(v.Data), nil
}

func (h *RegistryHive) readValue(offset uint32) (*HiveValue, error) {
	pos := h.cellData(offset)
	if pos+0x14 > len(h.data) {
		return nil, fmt.Errorf("value node out of bounds at 0x%x", offset)
	}
	sig := binary.LittleEndian.Uint16(h.data[pos : pos+2])
	if sig != vkSig {
		return nil, fmt.Errorf("expected vk signature at 0x%x, got 0x%x", pos, sig)
	}
	nameLen := int(binary.LittleEndian.Uint16(h.data[pos+2 : pos+4]))
	dataLen := binary.LittleEndian.Uint32(h.data[pos+4 : pos+8])
	dataOffOrInline := binary.LittleEndian.Uint32(h.data[pos+8 : pos+0xC])
	dataType := binary.LittleEndian.Uint32(h.data[pos+0xC : pos+0x10])
	flags := binary.LittleEndian.Uint16(h.data[pos+0x10 : pos+0x12])

	v := &HiveValue{DataType: dataType}

	// Parse name
	if nameLen > 0 {
		nameEnd := pos + 0x14 + nameLen
		if nameEnd > len(h.data) {
			return nil, fmt.Errorf("value name extends past data")
		}
		nameBytes := h.data[pos+0x14 : nameEnd]
		if flags&vkCompName != 0 {
			v.Name = string(nameBytes) // ASCII
		} else {
			v.Name = decodeUTF16LE(nameBytes)
		}
	}

	// Parse data
	if dataLen&0x80000000 != 0 {
		// Resident data: stored inline in the data offset field (≤4 bytes)
		actualLen := dataLen & 0x7FFFFFFF
		if actualLen > 4 {
			actualLen = 4
		}
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, dataOffOrInline)
		v.Data = make([]byte, actualLen)
		copy(v.Data, buf[:actualLen])
	} else if dataLen > 0 {
		dataPos := h.cellData(dataOffOrInline)
		end := dataPos + int(dataLen)
		if end > len(h.data) {
			return nil, fmt.Errorf("value data extends past hive (offset 0x%x, len %d)", dataOffOrInline, dataLen)
		}
		v.Data = make([]byte, dataLen)
		copy(v.Data, h.data[dataPos:end])
	}

	return v, nil
}
