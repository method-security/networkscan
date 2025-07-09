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
func RunServiceFingerprint(ctx context.Context, cfg discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
	rep := &discoverfern.DiscoverServiceReport{Config: &cfg}
	var results []*discoverfern.ServiceDetails

	ips, err := getIPs(cfg.Target)
	if err != nil {
		return rep, err
	}

	fxCfg := scan.Config{
		FastMode:       false,
		DefaultTimeout: time.Duration(cfg.Timeout) * time.Second,
		UDP:            false,
		Verbose:        true,
	}

	for _, ip := range ips {
		addrPort := netip.AddrPortFrom(netip.MustParseAddr(ip.String()), uint16(cfg.Port))
		fxTarget := plugins.Target{Address: addrPort, Host: cfg.Target}

		/* --- 1. fingerprintx ------------------------------------------------- */
		if fxRes, fxErr := fxCfg.SimpleScanTarget(fxTarget); fxErr == nil && fxRes != nil && fxRes.Protocol != "" {
			results = append(results, fxToServiceDetails(fxRes))
			continue // done with this IP
		}

		/* --- 2. custom modules ---------------------------------------------- */
		for _, fp := range customFingerprintModules {
			det, err := fp.Detect(ctx, ip, cfg)
			if err != nil {
				rep.Errors = append(rep.Errors, fmt.Sprintf("%s(%s): %v", fp.Name(), ip, err))
				continue
			}
			if det != nil { // hit!
				results = append(results, det)
				break
			}
		}
	}

	rep.Result = &discoverfern.DiscoverServiceResult{Services: results}
	return rep, nil
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

func fxToServiceDetails(res *plugins.Service) *discoverfern.ServiceDetails {
	md := metadataMap(res.Metadata())
	ver := res.Version

	return &discoverfern.ServiceDetails{
		Host:      res.Host,
		Ip:        res.IP,
		Port:      res.Port,
		Tls:       res.TLS,
		Version:   &ver,
		Transport: getTransportTypeEnum(res.Transport),
		Protocol:  getProtocolTypeEnum(res.Protocol),
		Metadata:  md,
	}
}

// metadataMap converts plugin metadata into a string map.
func metadataMap(metadata plugins.Metadata) map[string]string {
	out := make(map[string]string)
	if metadata == nil {
		return out
	}
	if m, ok := metadata.(interface{ Map() map[string]string }); ok {
		return m.Map()
	}
	v := reflect.ValueOf(metadata)
	switch v.Kind() {
	case reflect.Map:
		for _, k := range v.MapKeys() {
			out[k.String()] = fmt.Sprintf("%v", v.MapIndex(k).Interface())
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath == "" { // exported
				out[f.Name] = fmt.Sprintf("%v", v.Field(i).Interface())
			}
		}
	}
	return out
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

func getTransportTypeEnum(s string) common.TransportType {
	e, err := common.NewTransportTypeFromString(strings.ToUpper(s))
	if err != nil {
		e, _ = common.NewTransportTypeFromString("UNKNOWN")
	}
	return e
}

func getProtocolTypeEnum(s string) common.ProtocolType {
	e, err := common.NewProtocolTypeFromString(strings.ToUpper(s))
	if err != nil {
		e, _ = common.NewProtocolTypeFromString("UNKNOWN")
	}
	return e
}
