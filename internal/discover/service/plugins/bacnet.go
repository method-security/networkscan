// Package plugins provides BACnet/IP service fingerprinting.
//
// The probe sends a unicast Who-Is and parses the I-Am response to extract
// device-instance, max-APDU, segmentation-supported, and vendor-id. When the
// I-Am is intelligible, follow-up ReadProperty requests are issued against the
// Device object for vendor-name, model-name, firmware-revision,
// application-software-version, object-name, description, protocol-version,
// and protocol-revision. Best-effort: properties that don't decode or aren't
// supported by the device are simply omitted.
//
// All exchanges are strictly read-only (Who-Is + ReadProperty). No
// WriteProperty, SubscribeCOV, CreateObject, or ReinitializeDevice services
// are ever issued.
//
// Reference: ASHRAE 135 BACnet protocol specification.
package plugins

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type BACnetFingerprinter struct{}

func (BACnetFingerprinter) Name() string { return "bacnet" }

func (BACnetFingerprinter) DefaultPorts() []int { return []int{47808} }

// whoIsRequest is the canonical BACnet/IP global Who-Is packet (no instance
// range filter — any device on the segment may reply).
//
//	BVLC: 81 0b 00 0c                            (Original-Broadcast-NPDU, len 12)
//	NPDU: 01 20 ff ff 00 ff                      (control=destination spec, DNET=0xFFFF global, DLEN=0, hop=0xFF)
//	APDU: 10 08                                  (Unconfirmed-Request, service-choice 8 = Who-Is)
var whoIsRequest = []byte{0x81, 0x0b, 0x00, 0x0c, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08}

const (
	bvlcTypeBacnetIP            byte = 0x81
	bvlcFuncOriginalUnicast     byte = 0x0a
	bvlcFuncOriginalBroadcast   byte = 0x0b
	apduTypeUnconfirmedRequest  byte = 0x10
	apduTypeComplexAck          byte = 0x30
	serviceChoiceIAm            byte = 0x00
	serviceChoiceReadProperty   byte = 0x0c
	objectTypeDevice            uint32 = 8
	maxBacnetReadBytes          int  = 1476
)

// BACnet Device-object property identifiers used by the probe (all read-only
// in BACnet, and listed in the standard property set per ASHRAE 135).
const (
	bacnetPropObjectName                 = 77
	bacnetPropModelName                  = 70
	bacnetPropFirmwareRevision           = 44
	bacnetPropApplicationSoftwareVersion = 12
	bacnetPropDescription                = 28
	bacnetPropVendorName                 = 121
	bacnetPropProtocolVersion            = 98
	bacnetPropProtocolRevision           = 139
)

func (BACnetFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	resp, err := helpers.UDPExchange(ctx, ip, port, timeout, whoIsRequest, maxBacnetReadBytes)
	if err != nil {
		return nil, err
	}
	iam, err := parseIAm(resp)
	if err != nil {
		return nil, err
	}

	info := &protocol.BacnetServerInfo{
		DeviceInstance:    intPtr(int(iam.deviceInstance)),
		VendorId:          intPtr(int(iam.vendorID)),
		MaxApdu:           intPtr(int(iam.maxAPDU)),
		RespondingAddress: bacnetStringPtr(ip.String()),
	}
	if seg := segmentationName(iam.segmentation); seg != "" {
		info.SegmentationSupported = &seg
	}

	// Best-effort ReadProperty enrichment. Each request is its own UDP
	// exchange with a fresh invoke ID; failures are silently ignored so a
	// non-responsive or restrictive device still gets the I-Am-derived
	// fingerprint above.
	readProps := []struct {
		propID int
		assign func(string)
	}{
		{bacnetPropVendorName, func(s string) { info.VendorName = &s }},
		{bacnetPropModelName, func(s string) { info.ModelName = &s }},
		{bacnetPropFirmwareRevision, func(s string) { info.FirmwareRevision = &s }},
		{bacnetPropApplicationSoftwareVersion, func(s string) { info.ApplicationSoftwareVersion = &s }},
		{bacnetPropObjectName, func(s string) { info.ObjectName = &s }},
		{bacnetPropDescription, func(s string) { info.Description = &s }},
	}
	invokeID := byte(1)
	for _, rp := range readProps {
		if v, ok := readPropertyString(ctx, ip, port, timeout, iam.deviceInstance, rp.propID, invokeID); ok {
			rp.assign(v)
		}
		invokeID++
	}
	if v, ok := readPropertyUnsigned(ctx, ip, port, timeout, iam.deviceInstance, bacnetPropProtocolVersion, invokeID); ok {
		n := int(v)
		info.ProtocolVersion = &n
	}
	invokeID++
	if v, ok := readPropertyUnsigned(ctx, ip, port, timeout, iam.deviceInstance, bacnetPropProtocolRevision, invokeID); ok {
		n := int(v)
		info.ProtocolRevision = &n
	}

	version := "BACnet/IP"
	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeBacnet,
		Version:   &version,
		Metadata:  &discoverfern.ServiceMetadata{Bacnet: info},
	}, nil
}

// iAmResult holds the four values an I-Am announcement carries.
type iAmResult struct {
	deviceInstance uint32
	maxAPDU        uint32
	segmentation   uint32
	vendorID       uint32
}

// parseIAm validates the BVLC/NPDU/APDU layers and decodes the four
// application-tagged values in an I-Am unconfirmed-request.
func parseIAm(resp []byte) (*iAmResult, error) {
	if len(resp) < 8 || resp[0] != bvlcTypeBacnetIP {
		return nil, fmt.Errorf("not BACnet/IP")
	}
	if resp[1] != bvlcFuncOriginalUnicast && resp[1] != bvlcFuncOriginalBroadcast {
		return nil, fmt.Errorf("not BACnet/IP")
	}
	bvlcLen := int(binary.BigEndian.Uint16(resp[2:4]))
	if bvlcLen != len(resp) || bvlcLen < 8 {
		// Tolerate length mismatches but still bound reads.
		bvlcLen = len(resp)
	}
	// Quick gate for the I-Am marker (Unconfirmed-Request + service 0 = I-Am)
	// before paying the cost of full NPDU parsing.
	if !bytes.Contains(resp[4:bvlcLen], []byte{apduTypeUnconfirmedRequest, serviceChoiceIAm}) {
		return nil, fmt.Errorf("not BACnet/IP")
	}

	apdu, err := skipNPDU(resp[4:bvlcLen])
	if err != nil {
		return nil, err
	}
	if len(apdu) < 2 || apdu[0] != apduTypeUnconfirmedRequest || apdu[1] != serviceChoiceIAm {
		return nil, fmt.Errorf("not BACnet I-Am")
	}
	body := apdu[2:]

	// Tag 1: BACnetObjectIdentifier (application tag 12, length 4) = 0xC4 + 4 bytes
	if len(body) < 5 || body[0] != 0xC4 {
		return nil, fmt.Errorf("malformed I-Am: missing object identifier")
	}
	objID := binary.BigEndian.Uint32(body[1:5])
	deviceInstance := objID & 0x3FFFFF
	if (objID >> 22) != objectTypeDevice {
		return nil, fmt.Errorf("malformed I-Am: object is not a Device")
	}
	body = body[5:]

	// Tag 2: max-APDU-length-accepted, unsigned (application tag 2)
	maxAPDU, body, err := readAppUnsigned(body, 2)
	if err != nil {
		return nil, fmt.Errorf("malformed I-Am max-APDU: %w", err)
	}

	// Tag 3: segmentation-supported, enumerated (application tag 9), 1 byte
	if len(body) < 2 || body[0] != 0x91 {
		return nil, fmt.Errorf("malformed I-Am: missing segmentation")
	}
	segmentation := uint32(body[1])
	body = body[2:]

	// Tag 4: vendor-id, unsigned (application tag 2)
	vendorID, _, err := readAppUnsigned(body, 2)
	if err != nil {
		return nil, fmt.Errorf("malformed I-Am vendor-id: %w", err)
	}

	return &iAmResult{
		deviceInstance: deviceInstance,
		maxAPDU:        maxAPDU,
		segmentation:   segmentation,
		vendorID:       vendorID,
	}, nil
}

// skipNPDU walks the optional NPDU header fields (per ASHRAE 135 §6) and
// returns the slice positioned at the start of the APDU.
func skipNPDU(npdu []byte) ([]byte, error) {
	if len(npdu) < 2 {
		return nil, fmt.Errorf("truncated NPDU")
	}
	// npdu[0] = protocol version (must be 1), npdu[1] = control octet
	control := npdu[1]
	if control&0x80 != 0 {
		// Network layer message — not an APDU.
		return nil, fmt.Errorf("network layer message, not APDU")
	}
	off := 2
	hasDestination := control&0x20 != 0
	hasSource := control&0x08 != 0
	if hasDestination {
		// DNET (2) + DLEN (1) + DADR (DLEN)
		if len(npdu) < off+3 {
			return nil, fmt.Errorf("truncated NPDU destination")
		}
		dlen := int(npdu[off+2])
		off += 3 + dlen
	}
	if hasSource {
		if len(npdu) < off+3 {
			return nil, fmt.Errorf("truncated NPDU source")
		}
		slen := int(npdu[off+2])
		off += 3 + slen
	}
	if hasDestination {
		if len(npdu) <= off {
			return nil, fmt.Errorf("truncated NPDU hop count")
		}
		off++ // hop count
	}
	if off > len(npdu) {
		return nil, fmt.Errorf("truncated NPDU")
	}
	return npdu[off:], nil
}

// readAppUnsigned decodes a BACnet application-tagged unsigned int. The tag
// nibble must match expectedAppTag (typically 2 for "Unsigned"). Returns the
// value and the remainder of the buffer.
func readAppUnsigned(b []byte, expectedAppTag byte) (uint32, []byte, error) {
	if len(b) < 1 {
		return 0, b, fmt.Errorf("truncated tag")
	}
	tag := b[0]
	// Context-class tags have bit 3 (0x08) set; for application-class the
	// high nibble is the application tag number and the low nibble is the
	// length (or 5 = extended).
	if tag&0x08 != 0 {
		return 0, b, fmt.Errorf("expected application tag, got context tag 0x%02x", tag)
	}
	if (tag >> 4) != expectedAppTag {
		return 0, b, fmt.Errorf("expected app tag %d, got %d", expectedAppTag, tag>>4)
	}
	length := int(tag & 0x07)
	off := 1
	if length == 5 {
		if len(b) < off+1 {
			return 0, b, fmt.Errorf("truncated extended length")
		}
		length = int(b[off])
		off++
	}
	if length < 1 || length > 4 {
		return 0, b, fmt.Errorf("unsigned length %d out of range", length)
	}
	if len(b) < off+length {
		return 0, b, fmt.Errorf("truncated unsigned value")
	}
	var v uint32
	for i := 0; i < length; i++ {
		v = (v << 8) | uint32(b[off+i])
	}
	return v, b[off+length:], nil
}

// buildReadPropertyRequest constructs a confirmed-request ReadProperty against
// the Device object. invokeID rotates per request to disambiguate replies.
func buildReadPropertyRequest(deviceInstance uint32, propertyID int, invokeID byte) []byte {
	apdu := make([]byte, 0, 16)
	// Confirmed-Request APDU: type 0, no segmentation, max-segs=0, max-resp=5 (1476).
	apdu = append(apdu, 0x00, 0x05, invokeID, serviceChoiceReadProperty)
	// Object identifier: context tag 0, length 4.
	objID := (objectTypeDevice << 22) | (deviceInstance & 0x3FFFFF)
	apdu = append(apdu, 0x0c)
	apdu = append(apdu, byte(objID>>24), byte(objID>>16), byte(objID>>8), byte(objID))
	// Property identifier: context tag 1, unsigned length 1 or 2.
	if propertyID < 0 || propertyID > 0xFFFF {
		return nil
	}
	if propertyID <= 0xFF {
		apdu = append(apdu, 0x19, byte(propertyID))
	} else {
		apdu = append(apdu, 0x1a, byte(propertyID>>8), byte(propertyID))
	}
	// NPDU: version 1, control 0x04 (expecting-reply).
	npdu := []byte{0x01, 0x04}
	body := append(npdu, apdu...)
	total := 4 + len(body)
	pkt := make([]byte, 0, total)
	// BVLC: type 0x81, function 0x0a (Original-Unicast-NPDU), length.
	pkt = append(pkt, bvlcTypeBacnetIP, bvlcFuncOriginalUnicast,
		byte(total>>8), byte(total))
	pkt = append(pkt, body...)
	return pkt
}

// readPropertyString issues a ReadProperty and returns the property value when
// it decodes as a BACnet character-string. Errors and non-string replies map
// to (`"", false`).
func readPropertyString(ctx context.Context, ip net.IP, port int, timeout int, deviceInstance uint32, propertyID int, invokeID byte) (string, bool) {
	value, ok := readPropertyRaw(ctx, ip, port, timeout, deviceInstance, propertyID, invokeID)
	if !ok {
		return "", false
	}
	return decodeCharString(value)
}

// readPropertyUnsigned issues a ReadProperty and returns the property value
// when it decodes as a BACnet unsigned int. Errors map to (0, false).
func readPropertyUnsigned(ctx context.Context, ip net.IP, port int, timeout int, deviceInstance uint32, propertyID int, invokeID byte) (uint32, bool) {
	value, ok := readPropertyRaw(ctx, ip, port, timeout, deviceInstance, propertyID, invokeID)
	if !ok {
		return 0, false
	}
	v, _, err := readAppUnsigned(value, 2)
	if err != nil {
		return 0, false
	}
	return v, true
}

// readPropertyRaw sends a ReadProperty request and returns the bytes between
// the property-value open and close tags (3e ... 3f).
func readPropertyRaw(ctx context.Context, ip net.IP, port int, timeout int, deviceInstance uint32, propertyID int, invokeID byte) ([]byte, bool) {
	req := buildReadPropertyRequest(deviceInstance, propertyID, invokeID)
	if req == nil {
		return nil, false
	}
	resp, err := helpers.UDPExchange(ctx, ip, port, timeout, req, maxBacnetReadBytes)
	if err != nil {
		return nil, false
	}
	value, err := parseReadPropertyAck(resp, invokeID)
	if err != nil {
		return nil, false
	}
	return value, true
}

// parseReadPropertyAck unwraps a ComplexACK ReadProperty response and returns
// the bytes inside the property-value open/close brackets.
func parseReadPropertyAck(resp []byte, invokeID byte) ([]byte, error) {
	if len(resp) < 8 || resp[0] != bvlcTypeBacnetIP {
		return nil, fmt.Errorf("not BACnet/IP reply")
	}
	if resp[1] != bvlcFuncOriginalUnicast && resp[1] != bvlcFuncOriginalBroadcast {
		return nil, fmt.Errorf("not BACnet/IP reply")
	}
	bvlcLen := int(binary.BigEndian.Uint16(resp[2:4]))
	if bvlcLen != len(resp) || bvlcLen < 8 {
		bvlcLen = len(resp)
	}
	apdu, err := skipNPDU(resp[4:bvlcLen])
	if err != nil {
		return nil, err
	}
	// ComplexACK: 0x30 | flags, then invokeID, then service choice.
	if len(apdu) < 3 || apdu[0]&0xF0 != apduTypeComplexAck {
		return nil, fmt.Errorf("not ComplexACK (apdu[0]=0x%02x)", apdu[0])
	}
	if apdu[1] != invokeID || apdu[2] != serviceChoiceReadProperty {
		return nil, fmt.Errorf("ComplexACK mismatch (invokeID=0x%02x, service=0x%02x)", apdu[1], apdu[2])
	}
	body := apdu[3:]

	// Skip context tag 0 (object identifier, 4 bytes) and context tag 1
	// (property identifier, 1 or 2 bytes). Optional context tag 2 is array
	// index — we never request one, but tolerate it.
	body, err = skipContextTag(body, 0)
	if err != nil {
		return nil, fmt.Errorf("missing object identifier: %w", err)
	}
	body, err = skipContextTag(body, 1)
	if err != nil {
		return nil, fmt.Errorf("missing property identifier: %w", err)
	}
	if len(body) > 0 && body[0] == 0x29 { // context tag 2, length 1 — array index
		if len(body) < 2 {
			return nil, fmt.Errorf("truncated array index")
		}
		body = body[2:]
	}

	// Property-value brackets: context tag 3 open (0x3e) ... close (0x3f).
	if len(body) < 2 || body[0] != 0x3e {
		return nil, fmt.Errorf("missing property-value open tag (got 0x%02x)", body[0])
	}
	body = body[1:]
	end := bytes.IndexByte(body, 0x3f)
	if end < 0 {
		return nil, fmt.Errorf("missing property-value close tag")
	}
	return body[:end], nil
}

// skipContextTag consumes a context-tagged primitive value with the expected
// tag number, returning the remainder of the buffer.
func skipContextTag(b []byte, expected byte) ([]byte, error) {
	if len(b) < 1 {
		return b, fmt.Errorf("truncated tag")
	}
	tag := b[0]
	if tag&0x08 == 0 {
		return b, fmt.Errorf("expected context tag, got application tag 0x%02x", tag)
	}
	if tag>>4 != expected {
		return b, fmt.Errorf("expected context tag %d, got %d", expected, tag>>4)
	}
	length := int(tag & 0x07)
	off := 1
	if length == 5 {
		if len(b) < off+1 {
			return b, fmt.Errorf("truncated extended length")
		}
		length = int(b[off])
		off++
	}
	if len(b) < off+length {
		return b, fmt.Errorf("truncated context value")
	}
	return b[off+length:], nil
}

// decodeCharString reads a BACnet character-string (application tag 7) from
// the front of b. Only the common UTF-8 / ANSI_X3.4 encoding is decoded; any
// other encoding is returned as an opaque hex-stripped string after best
// effort.
func decodeCharString(b []byte) (string, bool) {
	if len(b) < 1 {
		return "", false
	}
	tag := b[0]
	if tag&0x08 != 0 || (tag>>4) != 7 {
		return "", false
	}
	length := int(tag & 0x07)
	off := 1
	if length == 5 {
		if len(b) < off+1 {
			return "", false
		}
		length = int(b[off])
		off++
		// 2-byte extended length is rarely used here, but handle it.
		if length == 254 {
			if len(b) < off+2 {
				return "", false
			}
			length = int(binary.BigEndian.Uint16(b[off : off+2]))
			off += 2
		} else if length == 255 {
			if len(b) < off+4 {
				return "", false
			}
			length = int(binary.BigEndian.Uint32(b[off : off+4]))
			off += 4
		}
	}
	if length < 1 || len(b) < off+length {
		return "", false
	}
	// First byte of the value is the encoding indicator.
	// 0 = ANSI_X3.4 / UTF-8 (most common), 1 = IBM/Microsoft DBCS, 2 = JIS,
	// 3 = UCS-4, 4 = UCS-2, 5 = ISO-8859-1.
	enc := b[off]
	data := b[off+1 : off+length]
	// Trim trailing NULs that some implementations include for fixed widths.
	data = bytes.TrimRight(data, "\x00")
	if enc != 0 && enc != 5 {
		// Unknown encoding — return only printable ASCII bytes as a best
		// effort. Callers can decide whether to keep it.
		filtered := make([]byte, 0, len(data))
		for _, c := range data {
			if c >= 0x20 && c < 0x7f {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) == 0 {
			return "", false
		}
		return string(filtered), true
	}
	return string(data), true
}

// segmentationName maps the BACnet Segmentation enum (0-3) to the canonical
// ASHRAE 135 string. Unknown values are left empty so the caller leaves the
// field unset (no UNKNOWN sentinel; per ontology-definition convention).
func segmentationName(v uint32) string {
	switch v {
	case 0:
		return "SEGMENTED_BOTH"
	case 1:
		return "SEGMENTED_TRANSMIT"
	case 2:
		return "SEGMENTED_RECEIVE"
	case 3:
		return "NO_SEGMENTATION"
	default:
		return ""
	}
}

func intPtr(i int) *int          { return &i }
func bacnetStringPtr(s string) *string { return &s }
