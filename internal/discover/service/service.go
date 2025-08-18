// Package service implements service fingerprinting functionality for discovering running services.
package service

import (
	// Standard
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	// External
	plugins "github.com/praetorian-inc/fingerprintx/pkg/plugins"
	scan "github.com/praetorian-inc/fingerprintx/pkg/scan"

	// Custom fingerprinters (includes fingerprintx plugin registration)
	localPlugins "github.com/Method-Security/networkscan/internal/discover/service/plugins"
	// Fingerprintx plugins
	_ "github.com/Method-Security/networkscan/internal/discover/service/plugins/fingerprintx"
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
	&localPlugins.KerberosFingerprinter{},
}

// RunServiceFingerprint fingerprints the service at target:port.
//  1. If stealth mode is enabled, use targeted fingerprinting for the specified service type.
//  2. Otherwise, let fingerprintx try first.
//  3. If fingerprintx fails, run the custom modules in order until one hits.
func RunServiceFingerprint(ctx context.Context, config discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
	report := &discoverfern.DiscoverServiceReport{Config: &config}
	var results []*discoverfern.ServiceDetails

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

		/* --- 1. fingerprintx ------------------------------------------------- */
		if fingerprintResult, fingerprintError := fingerprintConfig.SimpleScanTarget(fingerprintTarget); fingerprintError == nil && fingerprintResult != nil && fingerprintResult.Protocol != "" {
			results = append(results, fxToServiceDetails(fingerprintResult))
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
				break
			}
		}
	}

	report.Result = &discoverfern.DiscoverServiceResult{Services: results}
	return report, nil
}

// fxToServiceDetails converts fingerprintx result to ServiceDetails
func fxToServiceDetails(result *plugins.Service) *discoverfern.ServiceDetails {
	return &discoverfern.ServiceDetails{
		Host:      result.Host,
		Ip:        result.IP,
		Port:      result.Port,
		Tls:       result.TLS,
		Transport: utils.GetTransportTypeEnum(result.Transport),
		Protocol:  utils.GetProtocolTypeEnum(result.Protocol),
		Version:   &result.Version,
		Metadata: map[string]string{
			"raw": string(result.Raw),
		},
	}
}
