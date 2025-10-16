// Package plugins provides SNMP service fingerprinting using GoSNMP library
package plugins

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/gosnmp/gosnmp"
)

type SNMPFingerprinter struct{}

func (SNMPFingerprinter) Name() string { return "snmp" }

func (SNMPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	// First try SNMPv3 discovery (most secure, modern)
	if result, err := trySNMPv3Discovery(ip, port, host, timeout); err == nil && result != nil {
		return result, nil
	}

	// Fall back to SNMPv2c/v1 with community strings
	communityStrings := []string{"public", "private"}

	for _, community := range communityStrings {
		// Try SNMPv2c first
		if result, err := trySNMPCommunity(ip, port, host, timeout, community, gosnmp.Version2c); err == nil && result != nil {
			return result, nil
		}

		// Fall back to SNMPv1
		if result, err := trySNMPCommunity(ip, port, host, timeout, community, gosnmp.Version1); err == nil && result != nil {
			return result, nil
		}
	}

	return nil, fmt.Errorf("no valid SNMP response with any method")
}

// trySNMPv3Discovery attempts to discover SNMPv3 engine information
func trySNMPv3Discovery(ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
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
		return nil, err
	}
	defer g.Conn.Close()

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

		serviceResult := createSNMPv3Result(ip, port, host, engineInfo)

		// Add system description if we got it successfully
		if err == nil && len(result.Variables) > 0 && result.Variables[0].Value != nil {
			serviceResult.Metadata["system_description"] = fmt.Sprintf("%v", result.Variables[0].Value)
		}

		return serviceResult, nil
	}

	// No engine information received
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no SNMPv3 engine information received")
}

// trySNMPCommunity tries SNMP with community string authentication
func trySNMPCommunity(ip net.IP, port int, host string, timeout int, community string, version gosnmp.SnmpVersion) (*discoverfern.ServiceDetails, error) {
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
		return nil, err
	}
	defer g.Conn.Close()

	// Try to get system description
	oids := []string{"1.3.6.1.2.1.1.1.0"} // sysDescr
	result, err := g.Get(oids)
	if err != nil {
		return nil, err
	}

	// SNMP service detected
	serviceResult := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeSnmp,
		Metadata:  make(map[string]string),
	}

	// Map SNMP version
	var versionStr string
	switch version {
	case gosnmp.Version1:
		versionStr = "SNMPv1"
	case gosnmp.Version2c:
		versionStr = "SNMPv2c"
	default:
		versionStr = fmt.Sprintf("SNMP (version %v)", version)
	}

	serviceResult.Version = &versionStr
	serviceResult.Metadata["snmp_version"] = versionStr
	serviceResult.Metadata["community"] = community
	serviceResult.Metadata["community_used"] = community

	// Add system description if available
	if len(result.Variables) > 0 && result.Variables[0].Value != nil {
		serviceResult.Metadata["system_description"] = fmt.Sprintf("%v", result.Variables[0].Value)
	}

	return serviceResult, nil
}

// createSNMPv3Result creates a ServiceDetails result for SNMPv3
func createSNMPv3Result(ip net.IP, port int, host string, engineInfo *SNMPv3EngineInfo) *discoverfern.ServiceDetails {
	result := &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeSnmp,
		Metadata:  make(map[string]string),
	}

	versionStr := "SNMPv3"
	result.Version = &versionStr
	result.Metadata["snmp_version"] = "3"

	// Add engine information to metadata
	if engineInfo.EngineID != "" {
		result.Metadata["engine_id"] = engineInfo.EngineID
		result.Metadata["engine_id_format"] = engineInfo.EngineIDFormat
		if engineInfo.EngineIDData != "" {
			result.Metadata["engine_id_data"] = engineInfo.EngineIDData
		}
	}
	if engineInfo.EngineBoots > 0 {
		result.Metadata["engine_boots"] = strconv.Itoa(engineInfo.EngineBoots)
	}
	if engineInfo.EngineTime > 0 {
		result.Metadata["engine_time"] = strconv.Itoa(engineInfo.EngineTime)
		result.Metadata["engine_uptime"] = formatUptime(engineInfo.EngineTime)
	}
	if engineInfo.Enterprise > 0 {
		result.Metadata["enterprise"] = strconv.Itoa(engineInfo.Enterprise)
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
