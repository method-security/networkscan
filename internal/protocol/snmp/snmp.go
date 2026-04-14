// Package snmp provides shared SNMP protocol helpers used by both discover and enumerate modules.
package snmp

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	commonprotocolfern "github.com/Method-Security/networkscan/generated/go/common/protocol"
	"github.com/gosnmp/gosnmp"
)

// SNMPv3EngineInfo holds SNMPv3 engine discovery information.
type SNMPv3EngineInfo struct {
	EngineID       string
	EngineIDFormat string
	EngineIDData   string
	EngineBoots    int
	EngineTime     int
	Enterprise     int
}

// SNMPSystemInfo holds SNMP system MIB information.
type SNMPSystemInfo struct {
	SysDescr    string
	SysObjectID string
	SysUpTime   uint32
	SysContact  string
	SysName     string
	SysLocation string
	SysServices int
}

// SystemOIDs are the standard system MIB OIDs queried by SNMP operations.
var SystemOIDs = []string{
	"1.3.6.1.2.1.1.1.0", // sysDescr
	"1.3.6.1.2.1.1.2.0", // sysObjectID
	"1.3.6.1.2.1.1.3.0", // sysUpTime
	"1.3.6.1.2.1.1.4.0", // sysContact
	"1.3.6.1.2.1.1.5.0", // sysName
	"1.3.6.1.2.1.1.6.0", // sysLocation
	"1.3.6.1.2.1.1.7.0", // sysServices
}

// TrySNMPv3Discovery attempts SNMPv3 engine discovery.
// Returns engine info, system description (if available), and error.
func TrySNMPv3Discovery(ip net.IP, port uint16, timeout int) (*SNMPv3EngineInfo, string, error) {
	g := &gosnmp.GoSNMP{
		Target:        ip.String(),
		Port:          port,
		Version:       gosnmp.Version3,
		Timeout:       time.Duration(timeout) * time.Second,
		Retries:       2,
		Transport:     "udp",
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.NoAuthNoPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 "public",
			AuthoritativeEngineID:    "",
			AuthoritativeEngineBoots: 0,
			AuthoritativeEngineTime:  0,
		},
	}

	err := g.Connect()
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = g.Close() }()

	result, getErr := g.Get([]string{"1.3.6.1.2.1.1.1.0"})

	usmParams := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if len(usmParams.AuthoritativeEngineID) == 0 {
		if getErr != nil {
			return nil, "", getErr
		}
		return nil, "", fmt.Errorf("no SNMPv3 engine information received")
	}

	engineIDBytes := []byte(usmParams.AuthoritativeEngineID)
	engineIDHex := hex.EncodeToString(engineIDBytes)

	engineInfo := &SNMPv3EngineInfo{
		EngineID:    engineIDHex,
		EngineBoots: int(usmParams.AuthoritativeEngineBoots),
		EngineTime:  int(usmParams.AuthoritativeEngineTime),
	}

	engineInfo.EngineIDFormat, engineInfo.EngineIDData, engineInfo.Enterprise =
		ParseEngineID(engineIDBytes)

	var sysDescr string
	if getErr == nil && len(result.Variables) > 0 && result.Variables[0].Value != nil {
		sysDescr = ExtractStringValue(result.Variables[0].Value)
	}

	return engineInfo, sysDescr, nil
}

// TrySNMPCommunityCheck tests if an SNMP community string works.
// Returns success status, system info, and error.
func TrySNMPCommunityCheck(ip net.IP, port uint16, timeout int, community string, version gosnmp.SnmpVersion) (bool, *SNMPSystemInfo, error) {
	g := &gosnmp.GoSNMP{
		Target:    ip.String(),
		Port:      port,
		Community: community,
		Version:   version,
		Timeout:   time.Duration(timeout) * time.Second,
		Retries:   0,
		Transport: "udp",
	}

	err := g.Connect()
	if err != nil {
		return false, nil, err
	}
	defer func() { _ = g.Close() }()

	result, err := g.Get(SystemOIDs)
	if err != nil {
		return false, nil, err
	}

	sysInfo := ParseSystemInfo(result)
	return true, sysInfo, nil
}

// TrySNMPv3NoAuthGet attempts a single SNMPv3 GET with NoAuthNoPriv for a specific username.
// Returns true if the GET succeeds (unauthenticated read access is allowed).
// Also returns parsed system info if the query succeeded.
func TrySNMPv3NoAuthGet(ip net.IP, port uint16, username string) (bool, *SNMPSystemInfo) {
	g := &gosnmp.GoSNMP{
		Target:        ip.String(),
		Port:          port,
		Version:       gosnmp.Version3,
		Timeout:       2 * time.Second,
		Retries:       0,
		Transport:     "udp",
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.NoAuthNoPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 username,
			AuthoritativeEngineID:    "",
			AuthoritativeEngineBoots: 0,
			AuthoritativeEngineTime:  0,
		},
	}

	err := g.Connect()
	if err != nil {
		return false, nil
	}
	defer func() { _ = g.Close() }()

	result, err := g.Get(SystemOIDs)
	if err != nil {
		return false, nil
	}

	if len(result.Variables) == 0 || result.Variables[0].Type == gosnmp.NoSuchObject ||
		result.Variables[0].Type == gosnmp.NoSuchInstance {
		return false, nil
	}

	return true, ParseSystemInfo(result)
}

// ParseSystemInfo extracts system MIB values from an SNMP GET result.
func ParseSystemInfo(result *gosnmp.SnmpPacket) *SNMPSystemInfo {
	sysInfo := &SNMPSystemInfo{}

	if len(result.Variables) >= 1 {
		sysInfo.SysDescr = ExtractStringValue(result.Variables[0].Value)
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
		sysInfo.SysContact = ExtractStringValue(result.Variables[3].Value)
	}
	if len(result.Variables) >= 5 {
		sysInfo.SysName = ExtractStringValue(result.Variables[4].Value)
	}
	if len(result.Variables) >= 6 {
		sysInfo.SysLocation = ExtractStringValue(result.Variables[5].Value)
	}
	if len(result.Variables) >= 7 {
		if services, ok := result.Variables[6].Value.(int); ok {
			sysInfo.SysServices = services
		}
	}

	return sysInfo
}

// PopulateServerInfo fills a SnmpServerInfo from SNMPv3EngineInfo and SNMPSystemInfo.
func PopulateServerInfo(serverInfo *commonprotocolfern.SnmpServerInfo, v3Info *SNMPv3EngineInfo, sysInfo *SNMPSystemInfo) {
	if v3Info != nil {
		if serverInfo.V3EngineId == nil {
			serverInfo.V3EngineId = &v3Info.EngineID
		}
		if serverInfo.V3EngineIdFormat == nil {
			serverInfo.V3EngineIdFormat = &v3Info.EngineIDFormat
		}
		if v3Info.EngineIDData != "" && serverInfo.V3EngineIdData == nil {
			serverInfo.V3EngineIdData = &v3Info.EngineIDData
		}
		if v3Info.EngineBoots > 0 && serverInfo.V3EngineBoots == nil {
			serverInfo.V3EngineBoots = &v3Info.EngineBoots
		}
		if v3Info.EngineTime > 0 && serverInfo.V3EngineTime == nil {
			serverInfo.V3EngineTime = &v3Info.EngineTime
			uptime := FormatUptime(v3Info.EngineTime)
			serverInfo.V3EngineUptime = &uptime
		}
		if v3Info.Enterprise > 0 && serverInfo.V3Enterprise == nil {
			serverInfo.V3Enterprise = &v3Info.Enterprise
			if name := LookupEnterpriseName(v3Info.Enterprise); name != "" {
				serverInfo.V3EnterpriseName = &name
			}
		}
	}

	if sysInfo != nil {
		if sysInfo.SysDescr != "" && serverInfo.SystemDescription == nil {
			serverInfo.SystemDescription = &sysInfo.SysDescr
		}
		if sysInfo.SysObjectID != "" && serverInfo.SysObjectId == nil {
			serverInfo.SysObjectId = &sysInfo.SysObjectID
		}
		if sysInfo.SysUpTime > 0 && serverInfo.SysUptime == nil {
			uptime := FormatUptime(int(sysInfo.SysUpTime / 100))
			serverInfo.SysUptime = &uptime
		}
		if sysInfo.SysContact != "" && serverInfo.SysContact == nil {
			serverInfo.SysContact = &sysInfo.SysContact
		}
		if sysInfo.SysName != "" && serverInfo.SysName == nil {
			serverInfo.SysName = &sysInfo.SysName
		}
		if sysInfo.SysLocation != "" && serverInfo.SysLocation == nil {
			serverInfo.SysLocation = &sysInfo.SysLocation
		}
		if sysInfo.SysServices > 0 && serverInfo.SysServices == nil {
			serverInfo.SysServices = &sysInfo.SysServices
		}
	}
}

// ExtractStringValue converts various SNMP value types to string.
// Returns empty string for nil values to avoid "<nil>" literals.
func ExtractStringValue(value interface{}) string {
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case []byte:
		return string(v)
	case string:
		return v
	default:
		return ""
	}
}

// ParseEngineID analyzes the engine ID format and extracts relevant information.
func ParseEngineID(engineID []byte) (format, data string, enterprise int) {
	if len(engineID) < 5 {
		return "unknown", "", 0
	}

	enterprise = (int(engineID[0])<<24 | int(engineID[1])<<16 | int(engineID[2])<<8 | int(engineID[3])) & 0x7FFFFFFF

	if len(engineID) < 6 {
		return "enterprise", "", enterprise
	}

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

// FormatUptime converts seconds to a human-readable format.
func FormatUptime(seconds int) string {
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

// LookupEnterpriseName returns the enterprise name for a given enterprise ID.
func LookupEnterpriseName(enterpriseID int) string {
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

// CommonNoAuthUsernames are the default usernames tested for NoAuthNoPriv access.
var CommonNoAuthUsernames = []string{
	"public",
	"initial",
	"admin",
	"snmpuser",
	"default",
	"monitor",
	"noauth",
	"",
}
