// Package plugins provides SNMP service fingerprinting using GoSNMP library
package plugins

import (
	"context"
	"fmt"
	"net"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	snmplib "github.com/Method-Security/networkscan/internal/protocol/snmp"
	"github.com/gosnmp/gosnmp"
)

type SNMPFingerprinter struct{}

func (SNMPFingerprinter) Name() string { return "snmp" }

func (SNMPFingerprinter) DefaultPorts() []int { return []int{161, 162} }

func (SNMPFingerprinter) Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error) {
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port %d out of range", port)
	}
	snmpPort := uint16(port)

	fingerprintTimeout := 1
	if timeout < fingerprintTimeout {
		fingerprintTimeout = timeout
	}

	var allVersions []string
	var allCommunities []string
	var v3Info *snmplib.SNMPv3EngineInfo
	var sysInfo *snmplib.SNMPSystemInfo

	// Try SNMPv3 discovery FIRST (use at least 2 seconds for discovery round-trip)
	v3Timeout := fingerprintTimeout
	if v3Timeout < 2 {
		v3Timeout = 2
	}
	if v3InfoResult, sysDescr, err := snmplib.TrySNMPv3Discovery(ip, snmpPort, v3Timeout); err == nil && v3InfoResult != nil {
		allVersions = append(allVersions, "SNMPv3")
		v3Info = v3InfoResult
		if sysDescr != "" && sysInfo == nil {
			sysInfo = &snmplib.SNMPSystemInfo{SysDescr: sysDescr}
		}
	}

	// Try v1/v2c with community strings
	communityTimeout := fingerprintTimeout / 2
	if communityTimeout < 1 {
		communityTimeout = 1
	}

	type versionTest struct {
		version     gosnmp.SnmpVersion
		versionName string
	}
	versionTests := []versionTest{
		{gosnmp.Version2c, "SNMPv2c"},
		{gosnmp.Version1, "SNMPv1"},
	}
	communities := []string{"public", "private"}
	workingCommunities := make(map[string]bool)

	for _, vt := range versionTests {
		versionWorks := false
		for _, community := range communities {
			success, sysInfoResult, err := snmplib.TrySNMPCommunityCheck(ip, snmpPort, communityTimeout, community, vt.version)
			if err == nil && success {
				versionWorks = true
				if !workingCommunities[community] {
					allCommunities = append(allCommunities, community)
					workingCommunities[community] = true
				}
				if sysInfo == nil || sysInfo.SysName == "" {
					sysInfo = sysInfoResult
				}
			}
		}
		if versionWorks {
			allVersions = append(allVersions, vt.versionName)
		}
	}

	if len(allVersions) > 0 {
		return createSNMPResult(ip, port, host, allVersions, allCommunities, v3Info, sysInfo), nil
	}

	return nil, fmt.Errorf("no SNMP response")
}

// createSNMPResult creates a ServiceDetails result combining all detected SNMP versions
func createSNMPResult(ip net.IP, port int, host string, versions []string, communities []string, v3Info *snmplib.SNMPv3EngineInfo, sysInfo *snmplib.SNMPSystemInfo) *discoverfern.ServiceDetails {
	metadata := &protocol.SnmpServerInfo{
		Versions: versions,
	}

	if len(communities) > 0 {
		metadata.CommunityStrings = communities
	}

	snmplib.PopulateServerInfo(metadata, v3Info, sysInfo)

	versionStr := versions[len(versions)-1]
	return &discoverfern.ServiceDetails{
		Host:      host,
		Ip:        ip.String(),
		Port:      port,
		Tls:       false,
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeSnmp,
		Version:   &versionStr,
		Metadata:  discoverfern.NewServiceMetadataFromSnmp(metadata),
	}
}
