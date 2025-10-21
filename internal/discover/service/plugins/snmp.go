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
	// Test all SNMP versions with public and private community strings
	// Use a short timeout for each attempt (1 second)
	fingerprintTimeout := 1
	if timeout < fingerprintTimeout {
		fingerprintTimeout = timeout
	}

	// Define versions to test with their names
	type versionTest struct {
		version     gosnmp.SnmpVersion
		versionName string
	}
	versionTests := []versionTest{
		{gosnmp.Version2c, "SNMPv2c"},
		{gosnmp.Version1, "SNMPv1"},
	}
	communities := []string{"public", "private"}

	// Try each version with each community string
	for _, vt := range versionTests {
		for _, community := range communities {
			if success, sysDescr, err := trySNMPCommunityCheck(ip, port, fingerprintTimeout, community, vt.version); err == nil && success {
				return createSNMPFingerprintResult(ip, port, host, sysDescr, vt.versionName, community), nil
			}
		}
	}

	// Try SNMPv3 discovery
	if v3Info, sysDescr, err := trySNMPv3Check(ip, port, fingerprintTimeout); err == nil && v3Info != nil {
		return createSNMPv3FingerprintResult(ip, port, host, sysDescr, v3Info), nil
	}

	// If nothing worked, service not detected
	return nil, fmt.Errorf("no SNMP response")
}

// trySNMPv3Check attempts to discover SNMPv3 engine information
// Returns engine info, system description, and error
func trySNMPv3Check(ip net.IP, port int, timeout int) (*SNMPv3EngineInfo, string, error) {
	// Create GoSNMP instance for SNMPv3 discovery
	g := &gosnmp.GoSNMP{
		Target:    ip.String(),
		Port:      uint16(port),
		Version:   gosnmp.Version3,
		Timeout:   time.Duration(timeout) * time.Second,
		Retries:   1,
		Transport: "udp",
		// For discovery, we use no authentication but need a username
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.NoAuthNoPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName: "public", // Username required even for discovery
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

	// Even if Get fails, check if we got engine information from the discovery
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

// trySNMPCommunityCheck tests if an SNMP community string works
// Returns success status, system description, and error
func trySNMPCommunityCheck(ip net.IP, port int, timeout int, community string, version gosnmp.SnmpVersion) (bool, string, error) {
	g := &gosnmp.GoSNMP{
		Target:    ip.String(),
		Port:      uint16(port),
		Community: community,
		Version:   version,
		Timeout:   time.Duration(timeout) * time.Second,
		Retries:   1,
		Transport: "udp",
	}

	err := g.Connect()
	if err != nil {
		return false, "", err
	}
	defer func() { _ = g.Close() }()

	// Try to get system description
	oids := []string{"1.3.6.1.2.1.1.1.0"} // sysDescr
	result, err := g.Get(oids)
	if err != nil {
		return false, "", err
	}

	// Extract system description if available
	var sysDescr string
	if len(result.Variables) > 0 && result.Variables[0].Value != nil {
		switch v := result.Variables[0].Value.(type) {
		case []byte:
			sysDescr = string(v)
		case string:
			sysDescr = v
		default:
			sysDescr = fmt.Sprintf("%v", v)
		}
	}

	return true, sysDescr, nil
}

// createSNMPFingerprintResult creates a ServiceDetails result for v1/v2c fingerprinting
func createSNMPFingerprintResult(ip net.IP, port int, host string, systemDescription, version, community string) *discoverfern.ServiceDetails {
	metadata := &protocol.SnmpServerInfo{
		Versions:         []string{version},
		CommunityStrings: []string{community},
	}

	if systemDescription != "" {
		metadata.SystemDescription = &systemDescription
	}

	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeSnmp,
		Version:   &version,
		Metadata:  discoverfern.NewServiceMetadataFromSnmp(metadata),
	}

	return result
}

// createSNMPv3FingerprintResult creates a ServiceDetails result for SNMPv3 fingerprinting
func createSNMPv3FingerprintResult(ip net.IP, port int, host string, systemDescription string, v3Info *SNMPv3EngineInfo) *discoverfern.ServiceDetails {
	metadata := &protocol.SnmpServerInfo{
		Versions: []string{"SNMPv3"},
	}

	if systemDescription != "" {
		metadata.SystemDescription = &systemDescription
	}

	// Add v3 engine information
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
		}
	}

	versionStr := "SNMPv3"
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

	// First 4 bytes are enterprise ID
	enterprise = int(engineID[0])<<24 | int(engineID[1])<<16 | int(engineID[2])<<8 | int(engineID[3])

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
