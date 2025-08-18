package service

import (
	// Standard
	"context"
	"fmt"
	"net"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	// Plugins
	"github.com/Method-Security/networkscan/internal/discover/service/plugins"
	// Utilities
	"github.com/Method-Security/networkscan/utils"
)

// RunStealthServiceFingerprint performs targeted service fingerprinting for a specific service type
func RunStealthServiceFingerprint(ctx context.Context, config discoverfern.DiscoverServiceConfig, ips []net.IP) (*discoverfern.DiscoverServiceReport, error) {
	report := &discoverfern.DiscoverServiceReport{Config: &config}
	var results []*discoverfern.ServiceDetails

	// Parse target to get host and port - require explicit port for stealth mode
	host, portStr, err := net.SplitHostPort(config.Target)
	if err != nil {
		report.Errors = append(report.Errors, "stealth mode requires explicit port specification (use format host:port)")
		return report, nil
	}
	port := utils.ParsePort(portStr)
	if port == 0 {
		report.Errors = append(report.Errors, fmt.Sprintf("invalid port specified: %s", portStr))
		return report, nil
	}

	for _, ip := range ips {
		var detection *discoverfern.ServiceDetails
		var err error

		// Get the appropriate fingerprinter based on service type
		var fingerprinter interface {
			Detect(ctx context.Context, ip net.IP, port int, host string, timeout int) (*discoverfern.ServiceDetails, error)
		}

		switch config.Stealth.ServiceType {
		case discoverfern.StealthServiceTypeGrpc:
			fingerprinter = &plugins.GrpcFingerprinter{}
		case discoverfern.StealthServiceTypeSsh:
			fingerprinter = &plugins.SSHFingerprinter{}
		case discoverfern.StealthServiceTypeHttp:
			fingerprinter = &plugins.HTTPFingerprinter{}
		case discoverfern.StealthServiceTypeSmb:
			fingerprinter = &plugins.SMBFingerprinter{}
		case discoverfern.StealthServiceTypeLdap:
			fingerprinter = &plugins.LDAPFingerprinter{}
		case discoverfern.StealthServiceTypeKerberos:
			fingerprinter = &plugins.KerberosFingerprinter{}
		default:
			report.Errors = append(report.Errors, fmt.Sprintf("unsupported stealth service type: %s", config.Stealth.ServiceType))
			continue
		}

		// Use the fingerprinter to detect the service
		detection, err = fingerprinter.Detect(ctx, ip, port, host, config.Timeout)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s(%s:%d): %v", config.Stealth.ServiceType, ip, port, err))
			continue
		}

		if detection != nil {
			results = append(results, detection)
		}
	}

	report.Result = &discoverfern.DiscoverServiceResult{Services: results}
	return report, nil
}
