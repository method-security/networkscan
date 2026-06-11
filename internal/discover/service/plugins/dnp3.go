// Package plugins provides DNP3 (Distributed Network Protocol 3) service fingerprinting
package plugins

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
)

type DNP3Fingerprinter struct{}

func (DNP3Fingerprinter) Name() string { return "dnp3" }

func (DNP3Fingerprinter) DefaultPorts() []int { return []int{20000} }

func (DNP3Fingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))

	conn, err := helpers.Dial(ctx, "tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	// Set overall deadline for the connection
	if err := helpers.SetDeadline(conn, timeout); err != nil {
		return nil, err
	}

	// Step 1: Send link-layer Link Status Request (spray multiple destination addresses)
	linkProbe := buildDNP3LinkStatusRequest()
	if _, err := conn.Write(linkProbe); err != nil {
		return nil, err
	}

	// Read link-layer response (up to 292 bytes). Accept partial responses paired
	// with io.EOF / read errors as long as we got a full DNP3 frame header — Go's
	// conn.Read can legitimately return (n>0, io.EOF) when the peer half-closes
	// after the response, and rejecting those would drop valid DNP3 targets.
	linkBuf := make([]byte, 292)
	n, err := conn.Read(linkBuf)
	if n < 10 {
		if err != nil {
			return nil, fmt.Errorf("no DNP3 link-layer response: %w", err)
		}
		return nil, fmt.Errorf("DNP3 link-layer response too short: %d bytes", n)
	}

	// Validate DNP3 frame
	if !validDNP3Frame(linkBuf[:n]) {
		return nil, fmt.Errorf("not DNP3")
	}

	// Step 2: Extract outstation source address from link-layer response.
	// DNP3 frame layout: [0x05][0x64][LEN][CTRL][DEST_LSB][DEST_MSB][SRC_LSB][SRC_MSB][CRC_LSB][CRC_MSB]
	// The outstation's address is in the SRC bytes (indices 6-7).
	outstationAddr := binary.LittleEndian.Uint16(linkBuf[6:8])
	sourceAddrStr := strconv.Itoa(int(outstationAddr))

	// Build partial result — link-layer success guarantees we return ServiceDetails
	dnp3Version := "DNP3 L3"
	info := &protocol.Dnp3ServerInfo{
		Version:       &dnp3Version,
		SourceAddress: &sourceAddrStr,
	}

	// Step 3: Issue DNP3 application-layer Read Device Attributes (object group 0, var 254).
	// Master source MUST equal dnp3MasterSourceAddress used in the link-layer probe; see
	// the constant's docstring for why this matters.
	readAttrReq := buildDNP3ReadAttributesRequest(outstationAddr, dnp3MasterSourceAddress)
	if _, err := conn.Write(readAttrReq); err == nil {
		// Read response (up to 1024 bytes). Accept partial payloads paired with
		// io.EOF / read errors as long as we got a full DNP3 frame header — same
		// reasoning as the link-layer Read above. Outstations frequently half-close
		// after sending the attribute response, which would otherwise discard
		// parseable metadata.
		attrBuf := make([]byte, 1024)
		attrN, _ := conn.Read(attrBuf)
		if attrN >= 10 {
			parseDeviceAttributes(attrBuf[:attrN], info)
		}
		// If parsing fails we still have link-layer data — fall through gracefully
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeTcp,
		Protocol:  common.ProtocolTypeDnp3,
		Version:   &dnp3Version,
		Metadata:  &discoverfern.ServiceMetadata{Dnp3: info},
	}

	return result, nil
}

// buildDNP3ReadAttributesRequest constructs a DNP3 application-layer Read request
// for device attributes (object group 0, variation 254 = all attributes).
// The request is wrapped in transport and data-link layers per IEEE 1815.
func buildDNP3ReadAttributesRequest(destAddr, srcAddr uint16) []byte {
	// Application layer: AC=0xC0 (FIR+FIN), FC=0x01 (READ), OBJ=0x00 0xFE (G0V254), QUAL=0x06 (all points)
	appLayer := []byte{0xC0, 0x01, 0x00, 0xFE, 0x06}

	// Transport header: 0xC0 = FIN=1 FIR=1 SEQ=0
	transportByte := byte(0xC0)

	// User data = transport byte + app layer
	userDataPayload := append([]byte{transportByte}, appLayer...)

	// Chunk user data into 16-byte blocks, each followed by a 2-byte CRC.
	var userDataBlocks []byte
	for len(userDataPayload) > 0 {
		chunkSize := 16
		if len(userDataPayload) < chunkSize {
			chunkSize = len(userDataPayload)
		}
		chunk := userDataPayload[:chunkSize]
		userDataPayload = userDataPayload[chunkSize:]
		userDataBlocks = append(userDataBlocks, chunk...)
		userDataBlocks = append(userDataBlocks, dnp3CRC(chunk)...)
	}

	// DNP3 link-layer LEN field = number of bytes from CTRL (byte 3) through end of user data payload
	// (i.e., not counting start bytes 0x05 0x64, not counting the header CRC).
	// Per IEEE 1815 § 9.2.2.1: LEN = 5 (CTRL + DEST + SRC) + len(userDataBlocks)
	// Actually LEN covers: CTRL(1) + DEST(2) + SRC(2) + userDataPayload (without CRCs counted separately)
	// Standard formula: LEN = 5 + len(userDataPayload_before_chunking)
	// But userDataPayload at this point is consumed; reconstruct original length:
	origUserDataLen := 1 + len(appLayer) // transport byte + app bytes
	linkLen := byte(5 + origUserDataLen)

	// Link header (before CRC): [0x05][0x64][LEN][0xC4][DEST_LSB][DEST_MSB][SRC_LSB][SRC_MSB]
	// 0xC4 = DIR=1(from master) PRM=1 FCB=0 FCV=0 FC=4 (UNCONFIRMED_USER_DATA)
	header := []byte{
		0x05, 0x64,
		linkLen,
		0xC4,
		byte(destAddr & 0xFF), byte(destAddr >> 8),
		byte(srcAddr & 0xFF), byte(srcAddr >> 8),
	}
	headerCRC := dnp3CRC(header)

	// Assemble full frame
	frame := make([]byte, 0, 10+len(userDataBlocks))
	frame = append(frame, header...)
	frame = append(frame, headerCRC...)
	frame = append(frame, userDataBlocks...)

	return frame
}

// parseDeviceAttributes parses a DNP3 device attributes response and populates info.
// It tolerates malformed frames gracefully.
func parseDeviceAttributes(resp []byte, info *protocol.Dnp3ServerInfo) {
	// Validate link-layer header: [0x05][0x64][LEN][CTRL][DEST][SRC][CRC]
	if len(resp) < 10 || resp[0] != 0x05 || resp[1] != 0x64 {
		return
	}
	if !dnp3CRCOK(resp[:8], resp[8:10]) {
		return
	}

	// Reassemble user data by stripping CRCs from 16-byte blocks
	userDataBlocks := resp[10:] // skip the 10-byte link header
	payload := reassembleDNP3UserData(userDataBlocks)
	if len(payload) < 2 {
		return
	}

	// Skip transport byte (first byte)
	if len(payload) < 2 {
		return
	}
	appData := payload[1:]

	// Application layer: AC(1) + FC(1) + IIN(2) + objects
	if len(appData) < 4 {
		return
	}
	// fc := appData[1]  // should be 0x81 = Response
	// IIN bytes at [2] and [3]
	objects := appData[4:]

	// Parse object group 0 attributes
	// Each attribute object encoding: group(1) variation(1) qualifier(1) ...
	// For group 0, qualifier 0x00 means single index follows, qualifier 0x06 = all
	parseDNP3AttributeObjects(objects, info)
}

// reassembleDNP3UserData strips the CRC bytes (2 bytes after every 16 data bytes)
// and returns the raw user-data payload.
func reassembleDNP3UserData(blocks []byte) []byte {
	var out []byte
	for len(blocks) > 0 {
		chunkSize := 16
		if len(blocks) < chunkSize {
			chunkSize = len(blocks)
		}
		dataChunk := blocks[:chunkSize]
		blocks = blocks[chunkSize:]
		// Each chunk is followed by 2 CRC bytes (if we have them)
		if len(blocks) >= 2 {
			blocks = blocks[2:] // skip CRC
		}
		out = append(out, dataChunk...)
	}
	return out
}

// parseDNP3AttributeObjects walks the object stream for group 0 attribute variations.
func parseDNP3AttributeObjects(data []byte, info *protocol.Dnp3ServerInfo) {
	i := 0
	for i+2 < len(data) {
		grp := data[i]
		variation := data[i+1]
		qualifier := data[i+2]
		i += 3

		if grp != 0x00 {
			// Not a device attribute object; we can't reliably skip without more info
			return
		}

		// Determine how many objects and how to read the index.
		// Qualifier code: high nibble = index prefix code, low nibble = range/count code (IEEE 1815 § 4.4).
		switch qualifier {
		case 0x00: // 8-bit start index, 8-bit stop index (NOT count) — IEEE 1815 § 4.4.4.2
			if i+2 > len(data) {
				return
			}
			startIdx := int(data[i])
			stopIdx := int(data[i+1])
			i += 2
			if stopIdx < startIdx {
				return
			}
			count := stopIdx - startIdx + 1
			for c := 0; c < count && i < len(data); c++ {
				attrLen, ok := readDNP3VisibleString(data, i, variation, info)
				if !ok {
					return
				}
				i += attrLen
			}
		case 0x06: // no range — all points (variation 254 response may use this)
			// The response to "all attributes" typically echoes each attribute as
			// a separate object with qualifier 0x00 or 0x17 (per OpenDNP3).
			// If we see 0x06 in the response, skip — not a valid attribute response encoding.
			return
		case 0x07: // PrefixCode 0 + RangeCode 7: 8-bit object count, no per-item prefix
			if i+1 > len(data) {
				return
			}
			count := int(data[i])
			i++
			for c := 0; c < count && i < len(data); c++ {
				attrLen, ok := readDNP3VisibleString(data, i, variation, info)
				if !ok {
					return
				}
				i += attrLen
			}
		case 0x17: // PrefixCode 1 + RangeCode 7: 8-bit object count, each item with 8-bit index prefix.
			// For group 0 responses where the request used variation 254 ("all attributes"),
			// each item's 8-bit index prefix carries the SPECIFIC attribute variation. The header
			// variation tells you which set was requested (254 = all); the per-item prefix tells
			// you which attribute this particular item is. Use the prefix as the effective
			// variation when mapping to Dnp3ServerInfo fields, falling back to the header
			// variation when the prefix is 0 (i.e. the prefix is being used purely as an index,
			// not as the variation selector — rare but spec-permitted).
			if i+1 > len(data) {
				return
			}
			count := int(data[i])
			i++
			for c := 0; c < count && i < len(data); c++ {
				if i >= len(data) {
					return
				}
				itemVariation := data[i]
				i++
				effectiveVariation := itemVariation
				if effectiveVariation == 0 {
					effectiveVariation = variation
				}
				attrLen, ok := readDNP3VisibleString(data, i, effectiveVariation, info)
				if !ok {
					return
				}
				i += attrLen
			}
		case 0x01: // 8-bit index, no count (single item with explicit index)
			if i+1 > len(data) {
				return
			}
			_ = data[i] // index byte
			i++
			attrLen, ok := readDNP3VisibleString(data, i, variation, info)
			if !ok {
				return
			}
			i += attrLen
		default:
			// Unknown qualifier; stop parsing to avoid corruption
			return
		}
	}
}

// readDNP3VisibleString reads one IEEE 1815 attribute at data[offset]. All DNP3
// attribute encodings use the same [type(1) | length(1) | payload(length)] shape
// (§ 4.3.13 / OpenDNP3), so we always advance past the full encoded attribute
// even when the type isn't visible-string (0x01) — only visible-strings populate
// the Dnp3ServerInfo fields; other types (unsigned int, bit string, octet string,
// etc.) are skipped but their length is still consumed so the parser cursor
// stays aligned with subsequent objects.
// Returns the number of bytes consumed and whether parsing succeeded.
func readDNP3VisibleString(data []byte, offset int, variation byte, info *protocol.Dnp3ServerInfo) (int, bool) {
	if offset+2 > len(data) {
		return 0, false
	}
	attrType := data[offset]
	attrLen := int(data[offset+1])
	if offset+2+attrLen > len(data) {
		return 0, false
	}
	if attrType != 0x01 {
		// Non-visible-string attribute: consume type + length + payload to keep
		// the object walk aligned, but don't populate any Dnp3ServerInfo field.
		return 2 + attrLen, true
	}
	attrValue := string(data[offset+2 : offset+2+attrLen])
	setDNP3AttributeField(variation, attrValue, info)
	return 2 + attrLen, true
}

// setDNP3AttributeField maps a DNP3 attribute variation to the corresponding Dnp3ServerInfo field.
func setDNP3AttributeField(variation byte, value string, info *protocol.Dnp3ServerInfo) {
	v := value
	switch variation {
	case 240:
		info.UserAssignedProductName = &v
	case 242:
		info.UserAssignedName = &v
	case 243:
		info.UserAssignedId = &v
	case 244:
		info.Dnp3SubsetAndConformance = &v
	case 245:
		info.UserAssignedLocation = &v
	case 246:
		info.DeviceManufacturerHardwareVersion = &v
	case 247:
		info.DeviceManufacturerSoftwareVersion = &v
	case 248:
		info.DeviceSerialNumber = &v
	case 250:
		// Combine with 243 if not already set
		if info.UserAssignedId == nil {
			info.UserAssignedId = &v
		}
	case 252:
		info.DeviceManufacturerName = &v
	}
}

// dnp3MasterSourceAddress is the source (master) address used in both the
// link-layer probe and the application-layer Read Device Attributes request.
// Some outstations bind application traffic to the link-layer master address
// they last saw, so the two MUST match — otherwise the outstation may ignore
// or reject the attribute read after accepting the link-layer probe.
const dnp3MasterSourceAddress uint16 = 1

func buildDNP3LinkStatusRequest() []byte {
	probe := make([]byte, 0, 101*10)
	for destination := uint16(0); destination <= 100; destination++ {
		frame := []byte{0x05, 0x64, 0x05, 0xc9, 0x00, 0x00, 0x00, 0x00}
		binary.LittleEndian.PutUint16(frame[4:6], destination)
		binary.LittleEndian.PutUint16(frame[6:8], dnp3MasterSourceAddress)
		probe = append(probe, frame...)
		probe = append(probe, dnp3CRC(frame)...)
	}
	return probe
}

func validDNP3Frame(frame []byte) bool {
	if len(frame) < 10 || frame[0] != 0x05 || frame[1] != 0x64 {
		return false
	}
	linkLen := int(frame[2])
	if linkLen < 5 || linkLen > 250 {
		return false
	}
	if len(frame) < 10 || !dnp3CRCOK(frame[:8], frame[8:10]) {
		return false
	}
	controlFunc := frame[3] & 0x0f
	switch controlFunc {
	case 0x00, 0x01, 0x09, 0x0b, 0x0f:
	default:
		return false
	}
	if len(frame) >= 12 {
		dest := binary.LittleEndian.Uint16(frame[4:6])
		src := binary.LittleEndian.Uint16(frame[6:8])
		if dest == 0xffff && src == 0xffff {
			return false
		}
	}
	return true
}

func dnp3CRCOK(data []byte, got []byte) bool {
	if len(got) < 2 {
		return false
	}
	want := dnp3CRC(data)
	return got[0] == want[0] && got[1] == want[1]
}

func dnp3CRC(data []byte) []byte {
	crc := uint16(0)
	for _, b := range data {
		crc ^= uint16(b)
		for i := 0; i < 8; i++ {
			if crc&0x0001 != 0 {
				crc = (crc >> 1) ^ 0xa6bc
			} else {
				crc >>= 1
			}
		}
	}
	crc = ^crc
	return []byte{byte(crc & 0xff), byte(crc >> 8)}
}
