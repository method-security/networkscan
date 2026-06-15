package ubiquitidiscovery

import (
	"encoding/binary"
	"fmt"
	"net"
)

// discoveryRecord is a single TLV-encoded record extracted from a Discovery
// response.  Type is the 1-byte record type; Value is the raw record bytes
// (length-prefix stripped).
type discoveryRecord struct {
	Type  byte
	Value []byte
}

// parseDiscoveryResponse decodes a Discovery response packet (4-byte header
// followed by length-prefixed TLV records) into a slice of records.  Returns
// the protocol version reported in the header and the records.
//
// Wire format (per Ubiquiti's KB + community reverse-engineering):
//
//	0      version
//	1      command (echoed)
//	2-3    payloadLen (big-endian uint16, length of the TLV blob)
//	4-...  TLV records:  type(1) + len(big-endian uint16, 2) + value(len)
func parseDiscoveryResponse(data []byte) (version byte, records []discoveryRecord, err error) {
	if len(data) < 4 {
		return 0, nil, fmt.Errorf("response truncated: %d < 4 header bytes", len(data))
	}
	version = data[0]
	payloadLen := int(binary.BigEndian.Uint16(data[2:4]))
	if payloadLen == 0 || 4+payloadLen > len(data) {
		// Some firmware reports payloadLen=0 even with TLVs present — fall
		// back to parsing the rest of the buffer.
		payloadLen = len(data) - 4
	}
	body := data[4 : 4+payloadLen]

	for offset := 0; offset < len(body); {
		// Need at least 3 bytes for type + length.
		if offset+3 > len(body) {
			return version, records, fmt.Errorf("TLV truncated at offset %d", offset)
		}
		recType := body[offset]
		recLen := int(binary.BigEndian.Uint16(body[offset+1 : offset+3]))
		offset += 3
		if recLen < 0 || offset+recLen > len(body) {
			return version, records, fmt.Errorf("TLV value truncated: type %#02x, declared %d, available %d", recType, recLen, len(body)-offset)
		}
		val := make([]byte, recLen)
		copy(val, body[offset:offset+recLen])
		records = append(records, discoveryRecord{Type: recType, Value: val})
		offset += recLen
	}
	return version, records, nil
}

// extractFingerprint walks the parsed records and pulls fingerprint fields out
// into a typed map for the caller.  Records of unknown type are skipped
// silently — firmware-variant fields are common and we don't want to abort
// parsing on an unfamiliar type.
type discoveryFingerprint struct {
	MAC          string
	IPAddress    string
	Firmware     string
	Hostname     string
	Platform     string
	Essid        string
	Model        string
	UptimeSecs   *uint32
	RecordCount  int
}

func extractFingerprint(records []discoveryRecord) discoveryFingerprint {
	fp := discoveryFingerprint{RecordCount: len(records)}
	for _, r := range records {
		switch r.Type {
		case tlvTypeMacIPv1, tlvTypeMacIPv2:
			// 10 bytes: 6 MAC + 4 IPv4.  Some firmware emits less; tolerate
			// truncation silently.
			if len(r.Value) >= 6 && fp.MAC == "" {
				mac := net.HardwareAddr(r.Value[:6])
				fp.MAC = mac.String()
			}
			if len(r.Value) >= 10 && fp.IPAddress == "" {
				ip := net.IP(r.Value[6:10])
				fp.IPAddress = ip.String()
			}
		case tlvTypeFirmwareLen, tlvTypeVersion:
			if fp.Firmware == "" {
				fp.Firmware = trimNonPrintable(string(r.Value))
			}
		case tlvTypeUptime:
			if len(r.Value) >= 4 {
				v := binary.BigEndian.Uint32(r.Value[:4])
				fp.UptimeSecs = &v
			}
		case tlvTypeHostname:
			if fp.Hostname == "" {
				fp.Hostname = trimNonPrintable(string(r.Value))
			}
		case tlvTypePlatform:
			if fp.Platform == "" {
				fp.Platform = trimNonPrintable(string(r.Value))
			}
		case tlvTypeEssid:
			if fp.Essid == "" {
				fp.Essid = trimNonPrintable(string(r.Value))
			}
		case tlvTypeModel:
			if fp.Model == "" {
				fp.Model = trimNonPrintable(string(r.Value))
			}
		}
	}
	return fp
}

// trimNonPrintable strips leading/trailing C-style null padding and rejects
// strings that aren't ASCII-safe (devices occasionally emit garbage on
// firmware-corruption edge cases).  Returns "" when the string would contain
// any non-printable byte after trimming.
func trimNonPrintable(s string) string {
	// Strip trailing nulls + whitespace.
	end := len(s)
	for end > 0 && (s[end-1] == 0x00 || s[end-1] == ' ' || s[end-1] == '\r' || s[end-1] == '\n' || s[end-1] == '\t') {
		end--
	}
	s = s[:end]
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return s
}
