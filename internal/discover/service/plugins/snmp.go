// Package plugins provides SNMP service fingerprinting using GoSNMP library
package plugins

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Method-Security/networkscan/generated/go/common"
	"github.com/Method-Security/networkscan/generated/go/common/protocol"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	"github.com/Method-Security/networkscan/internal/discover/service/helpers"
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
	ctx, cancel := helpers.Context(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var allVersions []string
	var allCommunities []string
	var v3Info *snmplib.SNMPv3EngineInfo
	var sysInfo *snmplib.SNMPSystemInfo

	if v3InfoResult, sysDescr, err := snmplib.TrySNMPv3DiscoveryContext(ctx, ip, snmpPort, snmpCheckBudget(ctx, 5, 2*time.Second)); err == nil && v3InfoResult != nil {
		allVersions = append(allVersions, "SNMPv3")
		v3Info = v3InfoResult
		if sysDescr != "" && sysInfo == nil {
			sysInfo = &snmplib.SNMPSystemInfo{SysDescr: sysDescr}
		}
	}

	// Try v1/v2c with community strings
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
	remainingChecks := len(versionTests) * len(communities)

	for _, vt := range versionTests {
		versionWorks := false
		for _, community := range communities {
			budget := snmpCheckBudget(ctx, remainingChecks, time.Second)
			remainingChecks--
			success, sysInfoResult, err := snmplib.TrySNMPCommunityCheckContext(ctx, ip, snmpPort, budget, community, vt.version)
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

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(allVersions) > 0 {
		return createSNMPResult(ip, port, host, allVersions, allCommunities, v3Info, sysInfo), nil
	}

	return nil, fmt.Errorf("no SNMP response")
}

func snmpCheckBudget(ctx context.Context, remainingChecks int, limit time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		// Share the remaining attempt across pending checks and result delivery,
		// so optional metadata cannot consume the outer plugin deadline.
		return min(limit, time.Until(deadline)/time.Duration(remainingChecks+1))
	}
	return limit
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
		Transport: common.TransportTypeUdp,
		Protocol:  common.ProtocolTypeSnmp,
		Version:   &versionStr,
		Metadata:  &discoverfern.ServiceMetadata{Snmp: metadata},
	}
}
