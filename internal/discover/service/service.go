// Package service implements service fingerprinting functionality for discovering running services.
package service

import (
	// Standard
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	// Generated
	"github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"

	// External
	plugins "github.com/praetorian-inc/fingerprintx/pkg/plugins"
	scan "github.com/praetorian-inc/fingerprintx/pkg/scan"

	// Custom fingerprinters (includes fingerprintx plugin registration)
	localPlugins "github.com/Method-Security/networkscan/internal/discover/service/plugins"
	// Fingerprintx plugins
	_ "github.com/Method-Security/networkscan/internal/discover/service/plugins/fingerprintx"
	// Internal
	"github.com/Method-Security/networkscan/internal/common/ntlm"
	// Utilities
	"github.com/Method-Security/networkscan/utils"
)

/* -------------------------------------------------------------------------- */
/*  Custom-fingerprinter interface & registry                                 */
/* -------------------------------------------------------------------------- */

// Fingerprinter detects **one** specific application protocol (gRPC, MQTT, …).
// On match: (*ServiceDetails, nil)
// On "not mine": (nil, nil)
// On fatal error: (nil, err)
type Fingerprinter interface {
	Name() string
	Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error)
}

// List the modules you want to run after fingerprintx fails.
var customFingerprintModules = []Fingerprinter{
	&localPlugins.GrpcFingerprinter{},
}

// UDP fingerprinters mapped to their specific ports
// Each UDP service is only probed on its well-known port(s)
var udpFingerprinters = map[uint16]Fingerprinter{
	53:  &localPlugins.DNSFingerprinter{},     // DNS
	67:  &localPlugins.DHCPFingerprinter{},    // DHCP Server
	123: &localPlugins.NTPFingerprinter{},     // NTP
	137: &localPlugins.NetBIOSFingerprinter{}, // NetBIOS Name Service
	161: &localPlugins.SNMPFingerprinter{},    // SNMP
	162: &localPlugins.SNMPFingerprinter{},    // SNMP Trap
}

// RunServiceFingerprint fingerprints the service at target:port.
//  1. If UDP mode is enabled, scan common UDP ports on the target host.
//  2. If stealth mode is enabled, use targeted fingerprinting for the specified service type.
//  3. Otherwise, let fingerprintx try first.
//  4. If fingerprintx fails, run the custom modules in order until one hits.
func RunServiceFingerprint(ctx context.Context, config discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
	report := &discoverfern.DiscoverServiceReport{Config: &config}
	var results []*discoverfern.ServiceDetails

	// Check if UDP mode is enabled
	if config.Udp != nil && *config.Udp {
		return RunUDPServiceDiscovery(ctx, config)
	}

	// Parse target to get host and port
	host, port := utils.ParseHostPort(config.Target, 80) // Default to port 80 if no port specified

	ips, err := utils.GetIPs(host)
	if err != nil {
		return report, err
	}

	// Check if stealth mode is enabled
	if config.Stealth != nil {
		return RunStealthServiceFingerprint(ctx, config, ips)
	}

	// Standard fingerprinting path
	fingerprintConfig := scan.Config{
		FastMode:       false,
		DefaultTimeout: time.Duration(config.Timeout) * time.Second,
		UDP:            false,
		Verbose:        true,
	}

	for _, ip := range ips {
		addrPort := netip.AddrPortFrom(netip.MustParseAddr(ip.String()), uint16(port))
		fingerprintTarget := plugins.Target{Address: addrPort, Host: host}
		serviceFound := false

		/* --- 1. fingerprintx ------------------------------------------------- */
		if fingerprintResult, fingerprintError := fingerprintConfig.SimpleScanTarget(fingerprintTarget); fingerprintError == nil && fingerprintResult != nil && fingerprintResult.Protocol != "" {
			results = append(results, fxToServiceDetails(fingerprintResult))
			serviceFound = true
			continue // done with this IP
		}

		/* --- 2. custom modules ---------------------------------------------- */
		for _, fingerprinter := range customFingerprintModules {
			detection, err := fingerprinter.Detect(ctx, ip, port, host, config.Timeout)
			if err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("%s(%s): %v", fingerprinter.Name(), ip, err))
				continue
			}
			if detection != nil { // hit!
				results = append(results, detection)
				serviceFound = true
				break
			}
		}

		/* --- 3. no service found -------------------------------------------- */
		if !serviceFound {
			report.Errors = append(report.Errors, fmt.Sprintf("no service found on ip address: %s and port: %d", ip, port))
		}
	}

	report.Result = &discoverfern.DiscoverServiceResult{Services: results}
	return report, nil
}

// fxToServiceDetails converts fingerprintx result to ServiceDetails
func fxToServiceDetails(result *plugins.Service) *discoverfern.ServiceDetails {
	serviceDetails := &discoverfern.ServiceDetails{
		Host: result.Host,
		Ip:   result.IP,
		Port: result.Port,
		Tls:  result.TLS,
		Transport: func() common.TransportType {
			if transport, err := common.NewTransportTypeFromString(strings.ToUpper(result.Transport)); err == nil {
				return transport
			}
			return common.TransportTypeUnknown
		}(),
		Protocol: func() common.ProtocolType {
			if protocol, err := common.NewProtocolTypeFromString(strings.ToUpper(result.Protocol)); err == nil {
				return protocol
			}
			return common.ProtocolTypeUnknown
		}(),
		Version: &result.Version,
		Metadata: map[string]string{
			"raw": string(result.Raw),
		},
	}

	// Parse Windows OS version from NTLM metadata if available
	var rawData map[string]interface{}
	if err := json.Unmarshal(result.Raw, &rawData); err == nil {
		if osVersion, exists := rawData["osVersion"]; exists {
			if osVersionStr, ok := osVersion.(string); ok && osVersionStr != "" {
				// Extract build number from version like "10.0.20348" -> "Build 20348"
				parts := strings.Split(osVersionStr, ".")
				if len(parts) >= 3 {
					buildVersion := fmt.Sprintf("Build %s", parts[2])
					serviceDetails.Metadata["mappedOsVersion"] = ntlm.ParseWindowsVersion(buildVersion)
				}
			}
		}
	}

	return serviceDetails
}

// RunUDPServiceDiscovery scans common UDP ports on the target host and fingerprints discovered services.
// It uses custom UDP fingerprinters for DNS, NTP, SNMP, NetBIOS-NS, and DHCP.
// Each service is only probed on its well-known port(s) to avoid false positives.
func RunUDPServiceDiscovery(ctx context.Context, config discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
	report := &discoverfern.DiscoverServiceReport{Config: &config}
	var results []*discoverfern.ServiceDetails

	// Parse target to get host (should be just IP or hostname, no port)
	host := config.Target
	// Strip port if someone accidentally included it
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}

	ips, err := utils.GetIPs(host)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("failed to resolve target %s: %v", host, err))
		return report, nil
	}

	// Scan each IP
	for _, ip := range ips {
		// Try each UDP port that has a custom fingerprinter
		for port, fingerprinter := range udpFingerprinters {
			detection, err := fingerprinter.Detect(ctx, ip, int(port), host, config.Timeout)
			if err != nil {
				// UDP errors are expected when services aren't running
				// We silently skip these as they're normal behavior
				continue
			}
			if detection != nil {
				results = append(results, detection)
			}
		}
	}

	if len(results) == 0 {
		report.Errors = append(report.Errors, fmt.Sprintf("no UDP services found on %s", host))
	}

	report.Result = &discoverfern.DiscoverServiceResult{Services: results}
	return report, nil
}
