// Package plugins provides SNMP service fingerprinting using GoSNMP library
package plugins

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/gosnmp/gosnmp"
)

type SNMPFingerprinter struct{}

func (SNMPFingerprinter) Name() string { return "snmp" }

func (SNMPFingerprinter) DefaultPorts() []int { return []int{161, 162} }

func (SNMPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// Test all SNMP versions to get comprehensive version support information
	// A server can support multiple versions simultaneously (e.g., v1, v2c, AND v3)
	fingerprintTimeout := 1
	if timeout < fingerprintTimeout {
		fingerprintTimeout = timeout
	}

	// Track all findings across all versions
	var allVersions []string
	var allCommunities []string
	var v3Info *SNMPv3EngineInfo
	var sysInfo *SNMPSystemInfo

	// Try SNMPv3 discovery FIRST (use at least 2 seconds for discovery round-trip)
	v3Timeout := fingerprintTimeout
	if v3Timeout < 2 {
		v3Timeout = 2
	}
	if v3InfoResult, sysDescr, err := trySNMPv3Check(ip, port, v3Timeout); err == nil && v3InfoResult != nil {
		allVersions = append(allVersions, "SNMPv3")
		v3Info = v3InfoResult
		// Store basic system description from v3
		if sysDescr != "" && sysInfo == nil {
			sysInfo = &SNMPSystemInfo{SysDescr: sysDescr}
		}
	}

	// Try v1/v2c with community strings
	// Use very short timeout (500ms) since UDP responses are fast
	// If a server doesn't respond quickly, it's likely not going to respond at all
	communityTimeout := fingerprintTimeout / 2
	if communityTimeout < 1 {
		communityTimeout = 1
	}
	// But for the SNMP library, we need to use a fractional timeout
	// Let's use 0.5 seconds (500ms) which should be plenty for UDP
	// However, gosnmp timeout is in seconds (int), so minimum is 1
	// We'll rely on the Retries=0 to make it fast

	type versionTest struct {
		version     gosnmp.SnmpVersion
		versionName string
	}
	versionTests := []versionTest{
		{gosnmp.Version2c, "SNMPv2c"},
		{gosnmp.Version1, "SNMPv1"},
	}
	communities := []string{"public", "private"}

	// Track which communities work to avoid duplicates
	workingCommunities := make(map[string]bool)

	for _, vt := range versionTests {
		versionWorks := false
		for _, community := range communities {
			success, sysInfoResult, err := trySNMPCommunityCheck(ip, port, communityTimeout, community, vt.version)
			if err == nil && success {
				versionWorks = true
				// Only add community if we haven't seen it yet
				if !workingCommunities[community] {
					allCommunities = append(allCommunities, community)
					workingCommunities[community] = true
				}
				// Use full system info from the first successful community check
				if sysInfo == nil || sysInfo.SysName == "" {
					sysInfo = sysInfoResult
				}
			}
		}
		// If this version works with any community, add it to the list
		if versionWorks {
			allVersions = append(allVersions, vt.versionName)
		}
	}

	// If we found any working SNMP version, create a comprehensive result
	if len(allVersions) > 0 {
		return createCombinedSNMPResult(ip, port, host, allVersions, allCommunities, v3Info, sysInfo), nil
	}

	// If nothing worked, service not detected
	return nil, fmt.Errorf("no SNMP response")
}

// trySNMPv3Check attempts to discover SNMPv3 engine information
// Returns engine info, system description, and error
func trySNMPv3Check(ip net.IP, port int, timeout int) (*SNMPv3EngineInfo, string, error) {
	// Create GoSNMP instance for SNMPv3 discovery
	// For SNMPv3 discovery, we need to first discover the engine ID without authentication
	// This is done by sending a packet with empty engine ID and credentials
	g := &gosnmp.GoSNMP{
		Target:    ip.String(),
		Port:      uint16(port),
		Version:   gosnmp.Version3,
		Timeout:   time.Duration(timeout) * time.Second,
		Retries:   2, // Increased retries for SNMPv3 discovery
		Transport: "udp",
		// For discovery, we use no authentication
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.NoAuthNoPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 "public", // Username required by library even for discovery
			AuthoritativeEngineID:    "",       // Empty engine ID triggers discovery
			AuthoritativeEngineBoots: 0,
			AuthoritativeEngineTime:  0,
		},
	}

	err := g.Connect()
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = g.Close() }()

	// Try to get system description - this will trigger SNMPv3 engine discovery internally
	// The gosnmp library automatically sends a discovery packet first if needed
	oids := []string{"1.3.6.1.2.1.1.1.0"} // sysDescr
	result, err := g.Get(oids)

	// Even if Get fails (e.g., "unknown username"), check if we got engine information from the discovery
	// SNMPv3 discovery happens automatically when the engine ID is empty, and we get the engine info
	// back even if authentication fails
	usmParams := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if len(usmParams.AuthoritativeEngineID) > 0 {
		// We successfully discovered an SNMPv3 engine
		// AuthoritativeEngineID is stored as raw bytes in a string
		engineIDBytes := []byte(usmParams.AuthoritativeEngineID)
		engineIDHex := hex.EncodeToString(engineIDBytes)

		engineInfo := &SNMPv3EngineInfo{
			EngineID:    engineIDHex,
			EngineBoots: int(usmParams.AuthoritativeEngineBoots),
			EngineTime:  int(usmParams.AuthoritativeEngineTime),
		}

		// Parse engine ID format from raw bytes
		engineInfo.EngineIDFormat, engineInfo.EngineIDData, engineInfo.Enterprise =
			parseEngineID(engineIDBytes)

		// Add system description if we got it successfully
		var sysDescr string
		if err == nil && len(result.Variables) > 0 && result.Variables[0].Value != nil {
			switch v := result.Variables[0].Value.(type) {
			case []byte:
				sysDescr = string(v)
			case string:
				sysDescr = v
			default:
				sysDescr = fmt.Sprintf("%v", v)
			}
		}

		return engineInfo, sysDescr, nil
	}

	// No engine information received
	if err != nil {
		return nil, "", err
	}
	return nil, "", fmt.Errorf("no SNMPv3 engine information received")
}

// SNMPSystemInfo holds additional SNMP system information
type SNMPSystemInfo struct {
	SysDescr    string
	SysObjectID string
	SysUpTime   uint32
	SysContact  string
	SysName     string
	SysLocation string
	SysServices int
}

// trySNMPCommunityCheck tests if an SNMP community string works
// Returns success status, system info, and error
func trySNMPCommunityCheck(ip net.IP, port int, timeout int, community string, version gosnmp.SnmpVersion) (bool, *SNMPSystemInfo, error) {
	g := &gosnmp.GoSNMP{
		Target:    ip.String(),
		Port:      uint16(port),
		Community: community,
		Version:   version,
		Timeout:   time.Duration(timeout) * time.Second,
		Retries:   0, // No retries for faster detection when testing multiple versions
		Transport: "udp",
	}

	err := g.Connect()
	if err != nil {
		return false, nil, err
	}
	defer func() { _ = g.Close() }()

	// Query multiple system OIDs in one request for efficiency
	oids := []string{
		"1.3.6.1.2.1.1.1.0", // sysDescr
		"1.3.6.1.2.1.1.2.0", // sysObjectID
		"1.3.6.1.2.1.1.3.0", // sysUpTime
		"1.3.6.1.2.1.1.4.0", // sysContact
		"1.3.6.1.2.1.1.5.0", // sysName
		"1.3.6.1.2.1.1.6.0", // sysLocation
		"1.3.6.1.2.1.1.7.0", // sysServices
	}

	result, err := g.Get(oids)
	if err != nil {
		return false, nil, err
	}

	sysInfo := &SNMPSystemInfo{}

	// Extract values from response
	if len(result.Variables) >= 1 {
		sysInfo.SysDescr = extractStringValue(result.Variables[0].Value)
	}
	if len(result.Variables) >= 2 {
		if oid, ok := result.Variables[1].Value.(string); ok {
			sysInfo.SysObjectID = oid
		}
	}
	if len(result.Variables) >= 3 {
		if uptime, ok := result.Variables[2].Value.(uint32); ok {
			sysInfo.SysUpTime = uptime
		}
	}
	if len(result.Variables) >= 4 {
		sysInfo.SysContact = extractStringValue(result.Variables[3].Value)
	}
	if len(result.Variables) >= 5 {
		sysInfo.SysName = extractStringValue(result.Variables[4].Value)
	}
	if len(result.Variables) >= 6 {
		sysInfo.SysLocation = extractStringValue(result.Variables[5].Value)
	}
	if len(result.Variables) >= 7 {
		if services, ok := result.Variables[6].Value.(int); ok {
			sysInfo.SysServices = services
		}
	}

	return true, sysInfo, nil
}

// extractStringValue converts various SNMP value types to string
func extractStringValue(value interface{}) string {
	switch v := value.(type) {
	case []byte: // Note: []byte and []uint8 are the same type
		return string(v)
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

// createCombinedSNMPResult creates a ServiceDetails result combining all detected SNMP versions
func createCombinedSNMPResult(ip net.IP, port int, host string, versions []string, communities []string, v3Info *SNMPv3EngineInfo, sysInfo *SNMPSystemInfo) *discoverfern.ServiceDetails {
	metadata := &protocol.SnmpServerInfo{
		Versions: versions,
	}

	// Add community strings if any were found
	if len(communities) > 0 {
		metadata.CommunityStrings = communities
	}

	// Add system information from successful SNMP queries
	if sysInfo != nil {
		if sysInfo.SysDescr != "" {
			metadata.SystemDescription = &sysInfo.SysDescr
		}
		if sysInfo.SysObjectID != "" {
			metadata.SysObjectId = &sysInfo.SysObjectID
		}
		if sysInfo.SysUpTime > 0 {
			uptime := formatUptime(int(sysInfo.SysUpTime / 100)) // Convert centiseconds to seconds
			metadata.SysUptime = &uptime
		}
		if sysInfo.SysContact != "" {
			metadata.SysContact = &sysInfo.SysContact
		}
		if sysInfo.SysName != "" {
			metadata.SysName = &sysInfo.SysName
		}
		if sysInfo.SysLocation != "" {
			metadata.SysLocation = &sysInfo.SysLocation
		}
		if sysInfo.SysServices > 0 {
			metadata.SysServices = &sysInfo.SysServices
		}
	}

	// Add v3 engine information if available
	if v3Info != nil {
		if v3Info.EngineID != "" {
			metadata.V3EngineId = &v3Info.EngineID
			metadata.V3EngineIdFormat = &v3Info.EngineIDFormat
			if v3Info.EngineIDData != "" {
				metadata.V3EngineIdData = &v3Info.EngineIDData
			}
		}
		if v3Info.EngineBoots > 0 {
			metadata.V3EngineBoots = &v3Info.EngineBoots
		}
		if v3Info.EngineTime > 0 {
			metadata.V3EngineTime = &v3Info.EngineTime
			uptime := formatUptime(v3Info.EngineTime)
			metadata.V3EngineUptime = &uptime
		}
		if v3Info.Enterprise > 0 {
			metadata.V3Enterprise = &v3Info.Enterprise
			// Add enterprise name lookup
			enterpriseName := lookupEnterpriseName(v3Info.Enterprise)
			if enterpriseName != "" {
				metadata.V3EnterpriseName = &enterpriseName
			}
		}
	}

	// Use the highest version as the primary version string
	versionStr := versions[len(versions)-1]
	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeSnmp,
		Version:   &versionStr,
		Metadata:  discoverfern.NewServiceMetadataFromSnmp(metadata),
	}

	return result
}

// lookupEnterpriseName returns the enterprise name for a given enterprise ID
// This is a simple lookup for common vendors. For a complete solution, you'd want
// to download and parse the IANA enterprise numbers file periodically.
func lookupEnterpriseName(enterpriseID int) string {
	// Common enterprise IDs - add more as needed
	enterpriseNames := map[int]string{
		9:     "Cisco",
		11:    "HP",
		43:    "3Com",
		311:   "Microsoft",
		2011:  "Huawei",
		2636:  "Juniper",
		6876:  "VMware",
		8072:  "Net-SNMP",
		14988: "MikroTik",
		25506: "H3C",
		35098: "Arista",
	}

	if name, ok := enterpriseNames[enterpriseID]; ok {
		return name
	}
	return ""
}

// SNMPv3EngineInfo holds SNMPv3 engine discovery information
type SNMPv3EngineInfo struct {
	EngineID       string
	EngineIDFormat string
	EngineIDData   string
	EngineBoots    int
	EngineTime     int
	Enterprise     int
}

// parseEngineID analyzes the engine ID format and extracts relevant information
func parseEngineID(engineID []byte) (format, data string, enterprise int) {
	if len(engineID) < 5 {
		return "unknown", "", 0
	}

	// First 4 bytes are enterprise ID (bits 0-30, bit 31 is the format indicator)
	// We need to mask off the high bit which indicates RFC3411 format
	enterprise = (int(engineID[0])<<24 | int(engineID[1])<<16 | int(engineID[2])<<8 | int(engineID[3])) & 0x7FFFFFFF

	if len(engineID) < 6 {
		return "enterprise", "", enterprise
	}

	// 5th byte indicates format
	formatByte := engineID[4]
	remainder := engineID[5:]

	switch formatByte {
	case 1:
		if len(remainder) >= 4 {
			return "ipv4", fmt.Sprintf("%d.%d.%d.%d", remainder[0], remainder[1], remainder[2], remainder[3]), enterprise
		}
	case 2:
		if len(remainder) >= 16 {
			return "ipv6", hex.EncodeToString(remainder[:16]), enterprise
		}
	case 3:
		if len(remainder) >= 6 {
			return "mac", fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				remainder[0], remainder[1], remainder[2], remainder[3], remainder[4], remainder[5]), enterprise
		}
	case 4:
		return "text", string(remainder), enterprise
	case 5:
		return "octets", hex.EncodeToString(remainder), enterprise
	default:
		return "reserved", hex.EncodeToString(remainder), enterprise
	}

	return "unknown", hex.EncodeToString(remainder), enterprise
}

// formatUptime converts engine time (seconds) to a human-readable format
func formatUptime(seconds int) string {
	if seconds <= 0 {
		return "0 seconds"
	}

	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	secs := seconds % 60

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d days", days))
	}
	if hours > 0 || days > 0 {
		parts = append(parts, fmt.Sprintf("%02d:%02d:%02d", hours, minutes, secs))
	} else if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%d:%02d", minutes, secs))
	} else {
		parts = append(parts, fmt.Sprintf("%d seconds", secs))
	}

	return strings.Join(parts, ", ")
}
