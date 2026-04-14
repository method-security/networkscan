// Package slp provides shared SLP (Service Location Protocol) helpers for building
// and parsing SLP v2 messages over UDP.
package slp

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common/protocol"
)

const (
	// SLP v2 function IDs
	funcSrvRqst     = 1
	funcSrvRply     = 2
	funcSrvTypeRqst = 9
	funcSrvTypeRply = 10
	funcAttrRqst    = 6
	funcAttrRply    = 7
	funcDAAdvert    = 8

	// SLP multicast address and port
	MulticastAddr = "239.255.255.253"
	DefaultPort   = 427

	// Header size for SLP v2
	headerSize = 14
)

// DAInfo holds information about a discovered Directory Agent.
type DAInfo struct {
	Address string
	Scopes  []string
	Version string
}

// ServiceEntry holds a parsed service URL with its metadata.
type ServiceEntry struct {
	ServiceURL  string
	ServiceType string
	Host        string
	Port        int
	Scopes      []string
	Attributes  map[string]string
	Lifetime    int
}

// DiscoverDAs sends a SrvRqst for "service:directory-agent" to the target and collects DA responses.
func DiscoverDAs(target string, timeout time.Duration) ([]DAInfo, error) {
	conn, err := net.DialTimeout("udp", target, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", target, err)
	}
	defer func() { _ = conn.Close() }()

	packet := buildSrvRqst("service:directory-agent", "")
	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("failed to send DA discovery: %w", err)
	}

	var das []DAInfo
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			// Timeout means we're done collecting responses
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			break
		}

		if n < headerSize {
			continue
		}

		funcID := buf[1]
		switch funcID {
		case funcDAAdvert:
			da, parseErr := parseDAAdvert(buf[:n])
			if parseErr == nil {
				das = append(das, da)
			}
		case funcSrvRply:
			// DA might respond with a SrvRply containing its URL
			entries, parseErr := parseSrvRply(buf[:n])
			if parseErr == nil {
				for _, entry := range entries {
					das = append(das, DAInfo{
						Address: entry.ServiceURL,
						Version: "2",
					})
				}
			}
		}
	}

	return das, nil
}

// QueryServiceTypes sends a SrvTypeRqst and returns all service types registered.
func QueryServiceTypes(target string, timeout time.Duration) ([]string, error) {
	conn, err := net.DialTimeout("udp", target, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", target, err)
	}
	defer func() { _ = conn.Close() }()

	packet := buildSrvTypeRqst("")
	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("failed to send SrvTypeRqst: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read SrvTypeRply: %w", err)
	}

	return parseSrvTypeRply(buf[:n])
}

// QueryServices sends a SrvRqst for a specific service type and returns matching entries.
func QueryServices(target string, serviceType string, timeout time.Duration) ([]ServiceEntry, error) {
	conn, err := net.DialTimeout("udp", target, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", target, err)
	}
	defer func() { _ = conn.Close() }()

	packet := buildSrvRqst(serviceType, "")
	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("failed to send SrvRqst: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read SrvRply: %w", err)
	}

	entries, err := parseSrvRply(buf[:n])
	if err != nil {
		return nil, err
	}

	// Set the service type on each entry and parse the URL
	for i := range entries {
		entries[i].ServiceType = serviceType
		parseServiceURL(&entries[i])
	}

	return entries, nil
}

// QueryAttributes sends an AttrRqst for a specific service URL and returns attributes.
func QueryAttributes(target string, serviceURL string, timeout time.Duration) (map[string]string, error) {
	conn, err := net.DialTimeout("udp", target, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", target, err)
	}
	defer func() { _ = conn.Close() }()

	packet := buildAttrRqst(serviceURL)
	if _, err := conn.Write(packet); err != nil {
		return nil, fmt.Errorf("failed to send AttrRqst: %w", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read AttrRply: %w", err)
	}

	return parseAttrRply(buf[:n])
}

// ToSlpServiceEntry converts an internal ServiceEntry to a Fern-generated SlpServiceEntry.
func ToSlpServiceEntry(entry ServiceEntry) *protocol.SlpServiceEntry {
	result := &protocol.SlpServiceEntry{
		ServiceUrl:  entry.ServiceURL,
		ServiceType: entry.ServiceType,
		Scopes:      entry.Scopes,
		Attributes:  entry.Attributes,
	}
	if entry.Host != "" {
		result.Host = &entry.Host
	}
	if entry.Port > 0 {
		result.Port = &entry.Port
	}
	if entry.Lifetime > 0 {
		result.Lifetime = &entry.Lifetime
	}
	return result
}

// ToSlpDirectoryEntry converts an internal DAInfo to a Fern-generated SlpDirectoryEntry.
func ToSlpDirectoryEntry(da DAInfo) *protocol.SlpDirectoryEntry {
	result := &protocol.SlpDirectoryEntry{
		Address: da.Address,
		Scopes:  da.Scopes,
	}
	if da.Version != "" {
		result.Version = &da.Version
	}
	return result
}

// --- Packet builders ---

func buildHeader(funcID byte, payloadLen int) []byte {
	totalLen := headerSize + payloadLen
	header := make([]byte, headerSize)
	header[0] = 0x02 // Version 2
	header[1] = funcID
	// Length (24-bit big-endian)
	header[2] = byte(totalLen >> 16)
	header[3] = byte(totalLen >> 8)
	header[4] = byte(totalLen)
	// Flags: 0x0000
	header[5] = 0x00
	header[6] = 0x00
	// Next Extension Offset: 0x000000
	header[7] = 0x00
	header[8] = 0x00
	header[9] = 0x00
	// XID
	header[10] = 0x00
	header[11] = 0x01
	// Language tag length + "en"
	header[12] = 0x00
	header[13] = 0x02
	return header
}

func buildSrvRqst(serviceType string, scope string) []byte {
	if scope == "" {
		scope = "DEFAULT"
	}

	var payload []byte

	// Language tag "en"
	payload = append(payload, 'e', 'n')

	// PR list length: 0
	payload = append(payload, 0x00, 0x00)

	// Service type
	stBytes := []byte(serviceType)
	payload = append(payload, byte(len(stBytes)>>8), byte(len(stBytes)))
	payload = append(payload, stBytes...)

	// Scope list
	scopeBytes := []byte(scope)
	payload = append(payload, byte(len(scopeBytes)>>8), byte(len(scopeBytes)))
	payload = append(payload, scopeBytes...)

	// Predicate length: 0
	payload = append(payload, 0x00, 0x00)

	// SLP SPI length: 0
	payload = append(payload, 0x00, 0x00)

	header := buildHeader(funcSrvRqst, len(payload))
	return append(header, payload...)
}

func buildSrvTypeRqst(scope string) []byte {
	if scope == "" {
		scope = "DEFAULT"
	}

	var payload []byte

	// Language tag "en"
	payload = append(payload, 'e', 'n')

	// PR list length: 0
	payload = append(payload, 0x00, 0x00)

	// Naming authority length: 0xFFFF means all naming authorities
	payload = append(payload, 0xFF, 0xFF)

	// Scope list
	scopeBytes := []byte(scope)
	payload = append(payload, byte(len(scopeBytes)>>8), byte(len(scopeBytes)))
	payload = append(payload, scopeBytes...)

	header := buildHeader(funcSrvTypeRqst, len(payload))
	return append(header, payload...)
}

func buildAttrRqst(serviceURL string) []byte {
	var payload []byte

	// Language tag "en"
	payload = append(payload, 'e', 'n')

	// URL
	urlBytes := []byte(serviceURL)
	payload = append(payload, byte(len(urlBytes)>>8), byte(len(urlBytes)))
	payload = append(payload, urlBytes...)

	// Scope list: DEFAULT
	scopeBytes := []byte("DEFAULT")
	payload = append(payload, byte(len(scopeBytes)>>8), byte(len(scopeBytes)))
	payload = append(payload, scopeBytes...)

	// Tag list length: 0 (request all attributes)
	payload = append(payload, 0x00, 0x00)

	// SLP SPI length: 0
	payload = append(payload, 0x00, 0x00)

	header := buildHeader(funcAttrRqst, len(payload))
	return append(header, payload...)
}

// --- Response parsers ---

func parseSrvRply(data []byte) ([]ServiceEntry, error) {
	if len(data) < headerSize {
		return nil, fmt.Errorf("response too short: %d bytes", len(data))
	}
	if data[0] != 2 {
		return nil, fmt.Errorf("unsupported SLP version: %d", data[0])
	}
	if data[1] != funcSrvRply {
		return nil, fmt.Errorf("unexpected function ID: %d, expected SrvRply(%d)", data[1], funcSrvRply)
	}

	// Skip header, then language tag
	langTagLen := binary.BigEndian.Uint16(data[12:14])
	offset := headerSize + int(langTagLen)

	if offset+2 > len(data) {
		return nil, fmt.Errorf("truncated response")
	}

	// Error code
	errorCode := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if errorCode != 0 {
		return nil, fmt.Errorf("SLP error code: %d", errorCode)
	}

	if offset+2 > len(data) {
		return nil, fmt.Errorf("truncated response")
	}

	// URL entry count
	urlCount := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	var entries []ServiceEntry
	for i := 0; i < int(urlCount) && offset+6 <= len(data); i++ {
		// Reserved byte
		offset++
		// Lifetime (2 bytes)
		lifetime := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		// URL length (2 bytes) — skip 3 bytes total from reserved (1 + lifetime 2 already skipped, but we also need to account for the reserved+lifetime = 3 not 6)
		// Actually the URL entry format is: reserved(1) + lifetime(2) + urlLen(2) + url(urlLen) + authBlocks(1)
		// We've consumed reserved(1) + lifetime(2) so far

		if offset+2 > len(data) {
			break
		}
		urlLen := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		if offset+int(urlLen) > len(data) {
			break
		}
		serviceURL := string(data[offset : offset+int(urlLen)])
		offset += int(urlLen)

		entries = append(entries, ServiceEntry{
			ServiceURL: serviceURL,
			Lifetime:   lifetime,
		})

		// Skip auth block count
		if offset < len(data) {
			authBlockCount := int(data[offset])
			offset++
			// Skip auth blocks — each block layout per RFC 2608 §9.2:
			//   BSD(2) + Block Length(2) + Timestamp(4) + SPI Len(2) + SPI + Auth Data
			// Block Length covers the entire block including the BSD.
			for j := 0; j < authBlockCount && offset+4 <= len(data); j++ {
				// Block length is at offset+2 (after the 2-byte BSD) and includes the BSD itself
				blockLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
				if blockLen < 4 || offset+blockLen > len(data) {
					break
				}
				offset += blockLen
			}
		}
	}

	return entries, nil
}

func parseSrvTypeRply(data []byte) ([]string, error) {
	if len(data) < headerSize {
		return nil, fmt.Errorf("response too short: %d bytes", len(data))
	}
	if data[0] != 2 {
		return nil, fmt.Errorf("unsupported SLP version: %d", data[0])
	}
	if data[1] != funcSrvTypeRply {
		return nil, fmt.Errorf("unexpected function ID: %d, expected SrvTypeRply(%d)", data[1], funcSrvTypeRply)
	}

	langTagLen := binary.BigEndian.Uint16(data[12:14])
	offset := headerSize + int(langTagLen)

	if offset+2 > len(data) {
		return nil, fmt.Errorf("truncated response")
	}

	// Error code
	errorCode := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if errorCode != 0 {
		return nil, fmt.Errorf("SLP error code: %d", errorCode)
	}

	if offset+2 > len(data) {
		return nil, fmt.Errorf("truncated response")
	}

	// Service type list length
	listLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset+int(listLen) > len(data) {
		return nil, fmt.Errorf("truncated service type list")
	}

	typeList := string(data[offset : offset+int(listLen)])
	if typeList == "" {
		return nil, nil
	}

	types := strings.Split(typeList, ",")
	for i := range types {
		types[i] = strings.TrimSpace(types[i])
	}

	return types, nil
}

func parseDAAdvert(data []byte) (DAInfo, error) {
	if len(data) < headerSize {
		return DAInfo{}, fmt.Errorf("response too short")
	}
	if data[0] != 2 || data[1] != funcDAAdvert {
		return DAInfo{}, fmt.Errorf("not a DAAdvert")
	}

	langTagLen := binary.BigEndian.Uint16(data[12:14])
	offset := headerSize + int(langTagLen)

	if offset+4 > len(data) {
		return DAInfo{}, fmt.Errorf("truncated DAAdvert")
	}

	// Error code
	errorCode := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if errorCode != 0 {
		return DAInfo{}, fmt.Errorf("DAAdvert error code: %d", errorCode)
	}

	// DA stateless boot timestamp (4 bytes)
	offset += 4

	if offset+2 > len(data) {
		return DAInfo{}, fmt.Errorf("truncated DAAdvert")
	}

	// DA URL length
	urlLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset+int(urlLen) > len(data) {
		return DAInfo{}, fmt.Errorf("truncated DA URL")
	}

	daURL := string(data[offset : offset+int(urlLen)])
	offset += int(urlLen)

	// Scope list
	var scopes []string
	if offset+2 <= len(data) {
		scopeLen := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		if offset+int(scopeLen) <= len(data) {
			scopeList := string(data[offset : offset+int(scopeLen)])
			if scopeList != "" {
				scopes = strings.Split(scopeList, ",")
				for i := range scopes {
					scopes[i] = strings.TrimSpace(scopes[i])
				}
			}
		}
	}

	return DAInfo{
		Address: daURL,
		Scopes:  scopes,
		Version: "2",
	}, nil
}

func parseAttrRply(data []byte) (map[string]string, error) {
	if len(data) < headerSize {
		return nil, fmt.Errorf("response too short: %d bytes", len(data))
	}
	if data[0] != 2 {
		return nil, fmt.Errorf("unsupported SLP version: %d", data[0])
	}
	if data[1] != funcAttrRply {
		return nil, fmt.Errorf("unexpected function ID: %d, expected AttrRply(%d)", data[1], funcAttrRply)
	}

	langTagLen := binary.BigEndian.Uint16(data[12:14])
	offset := headerSize + int(langTagLen)

	if offset+2 > len(data) {
		return nil, fmt.Errorf("truncated response")
	}

	// Error code
	errorCode := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	if errorCode != 0 {
		return nil, fmt.Errorf("SLP error code: %d", errorCode)
	}

	if offset+2 > len(data) {
		return nil, fmt.Errorf("truncated response")
	}

	// Attribute list length
	attrLen := binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	if offset+int(attrLen) > len(data) {
		return nil, fmt.Errorf("truncated attribute list")
	}

	attrList := string(data[offset : offset+int(attrLen)])
	return parseAttributeList(attrList), nil
}

// parseAttributeList parses SLP attribute list format: "(key=value),(key=value)"
func parseAttributeList(attrList string) map[string]string {
	attrs := make(map[string]string)
	if attrList == "" {
		return attrs
	}

	// Split on "),(" to separate attribute entries
	entries := strings.Split(attrList, "),(")
	for _, entry := range entries {
		entry = strings.TrimPrefix(entry, "(")
		entry = strings.TrimSuffix(entry, ")")
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			attrs[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		} else if len(parts) == 1 && parts[0] != "" {
			// Keyword attribute (no value)
			attrs[strings.TrimSpace(parts[0])] = ""
		}
	}

	return attrs
}

// parseServiceURL extracts host and port from an SLP service URL.
func parseServiceURL(entry *ServiceEntry) {
	// SLP URLs look like: service:printer://192.168.1.50:631
	// or: service:printer:lpr://myprinter/queue1
	svcURL := entry.ServiceURL

	// Find the "://" that starts the authority section
	idx := strings.Index(svcURL, "://")
	if idx < 0 {
		return
	}

	// Extract the service type (everything before ://)
	if entry.ServiceType == "" {
		entry.ServiceType = svcURL[:idx]
	}

	// Parse the authority part
	remainder := svcURL[idx+3:]
	parsed, err := url.Parse("dummy://" + remainder)
	if err != nil {
		return
	}

	entry.Host = parsed.Hostname()
	if portStr := parsed.Port(); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			entry.Port = p
		}
	}
}
