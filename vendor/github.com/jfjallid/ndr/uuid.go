package ndr

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var re regexp.Regexp = *regexp.MustCompile(`([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})`)

func uuid_to_bin(uuid string) ([]byte, error) {
	//log.Debugln("In uuid_to_bin")

	if !strings.ContainsRune(uuid, '-') {
		return hex.DecodeString(uuid)
	}

	// Assume Variant 2 UUID
	matches := re.FindAllStringSubmatch(uuid, -1)
	if (len(matches) == 0) || (len(matches[0]) != 7) {
		return nil, fmt.Errorf("Failed to parse UUID v2 string")
	}
	uuid1, uuid2, uuid3, uuid4, uuid5, uuid6 := matches[0][1], matches[0][2], matches[0][3], matches[0][4], matches[0][5], matches[0][6]
	buf := make([]byte, 0)
	n, err := strconv.ParseUint(uuid1, 16, 32)
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint32(buf, uint32(n))
	n, err = strconv.ParseUint(uuid2, 16, 16)
	if err != nil {
		return nil, err
	}

	buf = binary.LittleEndian.AppendUint16(buf, uint16(n))
	n, err = strconv.ParseUint(uuid3, 16, 16)
	if err != nil {
		return nil, err
	}

	buf = binary.LittleEndian.AppendUint16(buf, uint16(n))
	n, err = strconv.ParseUint(uuid4, 16, 16)
	if err != nil {
		return nil, err
	}

	buf = binary.BigEndian.AppendUint16(buf, uint16(n))
	n, err = strconv.ParseUint(uuid5, 16, 16)
	if err != nil {
		return nil, err
	}

	buf = binary.BigEndian.AppendUint16(buf, uint16(n))
	n, err = strconv.ParseUint(uuid6, 16, 32)
	if err != nil {
		return nil, err
	}

	buf = binary.BigEndian.AppendUint32(buf, uint32(n))

	return buf, nil
}
