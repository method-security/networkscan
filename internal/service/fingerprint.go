package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"time"

	serviceFern "github.com/Method-Security/networkscan/generated/go/service"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"
)

// RunServiceFingerprint performs a banner grab on the specified target
func RunServiceFingerprint(ctx context.Context, timeout int, target string, port uint16) (*serviceFern.ServiceFingerprintReport, error) {
	resources := serviceFern.ServiceFingerprintReport{Target: target}
	errors := []string{}

	fxConfig := scan.Config{
		FastMode:       false,
		DefaultTimeout: time.Duration(timeout) * time.Second,
		UDP:            false,
		Verbose:        true,
	}

	ips, err := getIPs(target)
	if err != nil {
		return &resources, err
	}

	var fingerprintResults []*serviceFern.ServiceFingerprint
	for _, ip := range ips {
		ipAddr, err := netip.ParseAddr(ip.String())
		if err != nil {
			return &resources, err
		}

		fxTarget := plugins.Target{
			Address: netip.AddrPortFrom(ipAddr, port),
			Host:    target,
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
		fingerprintResult := serviceFern.ServiceFingerprint{
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

	resources.ServiceFingerprints = fingerprintResults
	resources.Errors = errors
	return &resources, nil
}

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

func getTransportTypeEnum(transport string) serviceFern.TransportType {
	transportTypeEnum, err := serviceFern.NewTransportTypeFromString(strings.ToUpper(transport))
	if err != nil {
		transportTypeEnum, _ = serviceFern.NewTransportTypeFromString("UNKNOWN")
	}
	return transportTypeEnum
}

func getProtocolTypeEnum(protocol string) serviceFern.ProtocolType {
	serviceTypeEnum, err := serviceFern.NewProtocolTypeFromString(strings.ToUpper(protocol))
	if err != nil {
		serviceTypeEnum, _ = serviceFern.NewProtocolTypeFromString("UNKNOWN")
	}
	return serviceTypeEnum
}
