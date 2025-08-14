// Package discover implements network discovery functionality for finding live hosts and services.
package discover

import (
	// Standard
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"time"

	// Generated
	common "github.com/Method-Security/networkscan/generated/go/common"
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"

	// External
	plugins "github.com/praetorian-inc/fingerprintx/pkg/plugins"
	scan "github.com/praetorian-inc/fingerprintx/pkg/scan"

	// Custom fingerprinters
	grpcfp "github.com/Method-Security/networkscan/internal/discover/plugins/service/grpc"
	_ "github.com/Method-Security/networkscan/internal/discover/plugins/service/kerberos" // Kerberos
)

/* -------------------------------------------------------------------------- */
/*  Custom-fingerprinter interface & registry                                 */
/* -------------------------------------------------------------------------- */

// Fingerprinter detects **one** specific application protocol (gRPC, MQTT, …).
// On match: (*ServiceDetails, nil)
// On “not mine”: (nil, nil)
// On fatal error: (nil, err)
type Fingerprinter interface {
	Name() string
	Detect(ctx context.Context, ip net.IP, cfg discoverfern.DiscoverServiceConfig) (*discoverfern.ServiceDetails, error)
}

// List the modules you want to run after fingerprintx fails.
var customFingerprintModules = []Fingerprinter{
	&grpcfp.Fingerprinter{},
}

/* -------------------------------------------------------------------------- */
/*  Public entry-point                                                        */
/* -------------------------------------------------------------------------- */

// RunServiceFingerprint fingerprints the service at target:port.
//  1. Let fingerprintx try first.
//  2. If it cannot decide, run the custom modules in order until one hits.
func RunServiceFingerprint(ctx context.Context, config discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
	report := &discoverfern.DiscoverServiceReport{Config: &config}
	var results []*discoverfern.ServiceDetails

	ips, err := getIPs(config.Target)
	if err != nil {
		return report, err
	}

	fingerprintConfig := scan.Config{
		FastMode:       false,
		DefaultTimeout: time.Duration(config.Timeout) * time.Second,
		UDP:            false,
		Verbose:        true,
	}

	for i, ip := range ips {
		// Apply attempt delay if configured (except for first attempt)
		if config.AttemptDelay != nil && *config.AttemptDelay > 0 && i > 0 {
			time.Sleep(time.Duration(*config.AttemptDelay) * time.Second)
		}

		addrPort := netip.AddrPortFrom(netip.MustParseAddr(ip.String()), uint16(config.Port))
		fingerprintTarget := plugins.Target{Address: addrPort, Host: config.Target}

		/* --- 1. fingerprintx ------------------------------------------------- */
		if fingerprintResult, fingerprintError := fingerprintConfig.SimpleScanTarget(fingerprintTarget); fingerprintError == nil && fingerprintResult != nil && fingerprintResult.Protocol != "" {
			results = append(results, fxToServiceDetails(fingerprintResult))
			continue // done with this IP
		}

		/* --- 2. custom modules ---------------------------------------------- */
		for _, fingerprinter := range customFingerprintModules {
			detection, err := fingerprinter.Detect(ctx, ip, config)
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

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

func fxToServiceDetails(result *plugins.Service) *discoverfern.ServiceDetails {
	metadata := metadataMap(result.Metadata())
	version := result.Version

	return &discoverfern.ServiceDetails{
		Host:      result.Host,
		Ip:        result.IP,
		Port:      result.Port,
		Tls:       result.TLS,
		Version:   &version,
		Transport: getTransportTypeEnum(result.Transport),
		Protocol:  getProtocolTypeEnum(result.Protocol),
		Metadata:  metadata,
	}
}

// metadataMap converts plugin metadata into a string map.
func metadataMap(metadata plugins.Metadata) map[string]string {
	output := make(map[string]string)
	if metadata == nil {
		return output
	}
	if mapper, ok := metadata.(interface{ Map() map[string]string }); ok {
		return mapper.Map()
	}
	value := reflect.ValueOf(metadata)
	switch value.Kind() {
	case reflect.Map:
		for _, key := range value.MapKeys() {
			output[key.String()] = fmt.Sprintf("%v", value.MapIndex(key).Interface())
		}
	case reflect.Struct:
		structType := value.Type()
		for i := 0; i < value.NumField(); i++ {
			field := structType.Field(i)
			if field.PkgPath == "" { // exported
				output[field.Name] = fmt.Sprintf("%v", value.Field(i).Interface())
			}
		}
	}
	return output
}

func getIPs(target string) ([]net.IP, error) {
	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("no IP addresses found for host")
	}
	return ips, nil
}

func getTransportTypeEnum(input string) common.TransportType {
	enumValue, err := common.NewTransportTypeFromString(strings.ToUpper(input))
	if err != nil {
		enumValue, _ = common.NewTransportTypeFromString("UNKNOWN")
	}
	return enumValue
}

func getProtocolTypeEnum(input string) common.ProtocolType {
	enumValue, err := common.NewProtocolTypeFromString(strings.ToUpper(input))
	if err != nil {
		enumValue, _ = common.NewProtocolTypeFromString("UNKNOWN")
	}
	return enumValue
}
