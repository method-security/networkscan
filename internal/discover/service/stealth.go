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
)

// runStealthServiceFingerprintTargets performs targeted service fingerprinting for a specific service type.
func runStealthServiceFingerprintTargets(ctx context.Context, config discoverfern.DiscoverServiceConfig, targets []serviceTarget) (*discoverfern.DiscoverServiceReport, error) {
	report := &discoverfern.DiscoverServiceReport{Config: &config}
	var results []*discoverfern.ServiceDetails

	for _, target := range targets {
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
		detection, err = fingerprinter.Detect(ctx, target.ip, target.port, target.host, config.Timeout)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s(%s:%d): %v", config.Stealth.ServiceType, target.ip, target.port, err))
			continue
		}

		if detection != nil {
			results = append(results, detection)
		} else {
			// No service found for this specific service type
			report.Errors = append(report.Errors, fmt.Sprintf("no %s service found on %s:%d", config.Stealth.ServiceType, target.ip, target.port))
		}
	}

	report.Result = &discoverfern.DiscoverServiceResult{Services: results}
	return report, nil
}
