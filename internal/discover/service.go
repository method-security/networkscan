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
	_ "github.com/Method-Security/networkscan/internal/discover/plugins/service/grpc" // Register the grpc plugin
	plugins "github.com/praetorian-inc/fingerprintx/pkg/plugins"
	scan "github.com/praetorian-inc/fingerprintx/pkg/scan"
)

// RunServiceFingerprint performs service fingerprinting on the specified target and port.
// It uses the fingerprintx library to identify running services and their characteristics.
// Returns a report containing service details and any errors encountered during the process.
func RunServiceFingerprint(ctx context.Context, config discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
	resources := discoverfern.DiscoverServiceReport{Config: &config}
	errors := []string{}

	fxConfig := scan.Config{
		FastMode:       false,
		DefaultTimeout: time.Duration(*config.Timeout) * time.Second,
		UDP:            false,
		Verbose:        true,
	}

	ips, err := getIPs(config.Target)
	if err != nil {
		return &resources, err
	}

	var fingerprintResults []*discoverfern.ServiceDetails
	for _, ip := range ips {
		ipAddr, err := netip.ParseAddr(ip.String())
		if err != nil {
			return &resources, err
		}

		fxTarget := plugins.Target{
			Address: netip.AddrPortFrom(ipAddr, uint16(config.Port)),
			Host:    config.Target,
		}

		result, err := fxConfig.SimpleScanTarget(fxTarget)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		if result == nil {
			errors = append(errors, "scan result is empty")
			continue
		}

		metadata := metadataMap(result.Metadata())
		fingerprintResult := discoverfern.ServiceDetails{
			Host:      result.Host,
			Ip:        result.IP,
			Port:      result.Port,
			Tls:       result.TLS,
			Version:   result.Version,
			Transport: getTransportTypeEnum(result.Transport),
			Protocol:  getProtocolTypeEnum(result.Protocol),
			Metadata:  metadata,
		}
		fingerprintResults = append(fingerprintResults, &fingerprintResult)
	}

	return &discoverfern.DiscoverServiceReport{
		Config: &config,
		Result: &discoverfern.DiscoverServiceResult{Services: fingerprintResults},
		Errors: errors,
	}, nil
}

// metadataMap converts plugin metadata into a string map.
// It handles different metadata types (maps, structs) and extracts their key-value pairs.
func metadataMap(metadata plugins.Metadata) map[string]string {
	result := make(map[string]string)
	// Check if metadata is nil
	if metadata == nil {
		return result
	}
	// Check if metadata implements the standard Map() method
	if mapper, ok := metadata.(interface{ Map() map[string]string }); ok {
		return mapper.Map()
	}
	// Use reflection as a fallback
	v := reflect.ValueOf(metadata)
	switch v.Kind() {
	case reflect.Map:
		// Handle the case where metadata is a map
		for _, key := range v.MapKeys() {
			value := v.MapIndex(key)
			result[key.String()] = fmt.Sprintf("%v", value.Interface())
		}
	case reflect.Struct:
		// Handle the case where metadata is a struct
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := t.Field(i)
			// Skip unexported fields
			if field.PkgPath != "" {
				continue
			}
			value := v.Field(i)
			result[field.Name] = fmt.Sprintf("%v", value.Interface())
		}
	default:
		return result
	}

	return result
}

// getIPs resolves the target hostname to a list of IP addresses.
// Returns an error if the hostname cannot be resolved or no IPs are found.
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

// getTransportTypeEnum converts a transport type string to our internal enum type.
// Returns UNKNOWN if the transport type is not recognized.
func getTransportTypeEnum(transport string) common.TransportType {
	transportTypeEnum, err := common.NewTransportTypeFromString(strings.ToUpper(transport))
	if err != nil {
		transportTypeEnum, _ = common.NewTransportTypeFromString("UNKNOWN")
	}
	return transportTypeEnum
}

// getProtocolTypeEnum converts a protocol type string to our internal enum type.
// Returns UNKNOWN if the protocol type is not recognized.
func getProtocolTypeEnum(protocol string) common.ProtocolType {
	protocolTypeEnum, err := common.NewProtocolTypeFromString(strings.ToUpper(protocol))
	if err != nil {
		protocolTypeEnum, _ = common.NewProtocolTypeFromString("UNKNOWN")
	}
	return protocolTypeEnum
}
