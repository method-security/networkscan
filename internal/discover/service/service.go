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

	// Custom fingerprinters
	localPlugins "github.com/Method-Security/networkscan/internal/discover/service/plugins"
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
	// DefaultPorts returns the list of default ports for this service
	// Empty list means the service can run on any port (no port restrictions)
	DefaultPorts() []int
}

// Custom fingerprinters for protocols that need specialized detection
// These run BEFORE fingerprintx to provide more specific detection
var customFingerprintModules = []Fingerprinter{
	&localPlugins.SSHFingerprinter{},       // SSH (Secure Shell)
	&localPlugins.GrpcFingerprinter{},      // gRPC can run on any port
	&localPlugins.MongoDBFingerprinter{},   // MongoDB driver manages its own connections
	&localPlugins.BGPFingerprinter{},       // BGP protocol detection
	&localPlugins.DCERPCFingerprinter{},    // Windows DCE/RPC
	&localPlugins.IPPFingerprinter{},       // Internet Printing Protocol
	&localPlugins.WinRMFingerprinter{},     // Windows Remote Management
	&localPlugins.KerberosFingerprinter{},  // Kerberos (Kerberos 5),
	&localPlugins.SMBFingerprinter{},       // SMB (Server Message Block),
	&localPlugins.FortiGateFingerprinter{}, // FortiGate FGFM (FortiGate to FortiManager),
	&localPlugins.PcworxFingerprinter{},    // PCWORX (Phoenix Contact PLCs)
	&localPlugins.OpcuaFingerprinter{},     // OPC UA (OPC Unified Architecture)
	&localPlugins.X11Fingerprinter{},       // X11 (X Window System)
	&localPlugins.PcomFingerprinter{},      // Unitronics PCOM (PLC Communication)
	&localPlugins.Iec104Fingerprinter{},    // IEC 60870-5-104 (SCADA protocol)
	&localPlugins.GesrtpFingerprinter{},    // GE SRTP (Service Request Transport Protocol)
	&localPlugins.FinsFingerprinter{},      // FINS (Omron PLC)
	&localPlugins.AtgFingerprinter{},       // ATG (Automatic Tank Gauging)
	&localPlugins.ArdFingerprinter{},       // ARD (Apple Remote Desktop)
	&localPlugins.PptpFingerprinter{},      // PPTP (Point-to-Point Tunneling Protocol)
	&localPlugins.MsmqFingerprinter{},      // MSMQ (Microsoft Message Queuing)
	&localPlugins.MmsFingerprinter{},       // MMS (Manufacturing Message Specification)
	&localPlugins.HartFingerprinter{},      // HART-IP (Highway Addressable Remote Transducer)
	&localPlugins.FoxFingerprinter{},       // FOX (Tridium Niagara Framework)
	&localPlugins.MemcachedFingerprinter{}, // MEMCACHED
	&localPlugins.UnistreamFingerprinter{}, // Unitronics UniStream (EtherNet/IP)
}

// UDP fingerprinters mapped to their specific ports
// Each UDP service is only probed on its well-known port(s)
var udpFingerprinters = map[uint16]Fingerprinter{
	53:    &localPlugins.DNSFingerprinter{},      // DNS
	67:    &localPlugins.DHCPFingerprinter{},     // DHCP Server
	69:    &localPlugins.TFTPFingerprinter{},     // TFTP (Trivial File Transfer Protocol)
	123:   &localPlugins.NTPFingerprinter{},      // NTP
	137:   &localPlugins.NetBIOSFingerprinter{},  // NetBIOS Name Service
	161:   &localPlugins.SNMPFingerprinter{},     // SNMP
	162:   &localPlugins.SNMPFingerprinter{},     // SNMP Trap
	177:   &localPlugins.XdmcpFingerprinter{},    // XDMCP (X Display Manager Control Protocol)
	427:   &localPlugins.SlpFingerprinter{},      // SLP (Service Location Protocol)
	500:   &localPlugins.IKEFingerprinter{},      // IKE (Internet Key Exchange)
	623:   &localPlugins.IPMIFingerprinter{},     // IPMI (Intelligent Platform Management Interface)
	1900:  &localPlugins.SSDPFingerprinter{},     // SSDP (Simple Service Discovery Protocol)
	4500:  &localPlugins.IKEFingerprinter{},      // IKE NAT-T (NAT Traversal)
	5060:  &localPlugins.SIPFingerprinter{},      // SIP (Session Initiation Protocol)
	10001: &localPlugins.UbiquitiFingerprinter{}, // Ubiquiti Discovery Protocol
}

// RunServiceFingerprint fingerprints the service at target:port.
//  1. If UDP mode is enabled, scan common UDP ports on the target host.
//  2. If stealth mode is enabled, use targeted fingerprinting for the specified service type.
//  3. Otherwise, for TCP (port-priority system):
//     Phase 1: Run custom fingerprinters ONLY if port matches their default ports
//     Phase 2: Run fingerprintx (which has its own port priority)
//     Phase 3: If nothing found, run custom fingerprinters on all ports (comprehensive fallback)
func RunServiceFingerprint(ctx context.Context, config discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
	report := &discoverfern.DiscoverServiceReport{Config: &config}
	var results []*discoverfern.ServiceDetails

	// Check if UDP mode is enabled
	if config.Udp != nil && *config.Udp {
		return runUDPServiceDiscovery(ctx, config)
	}

	// Parse target to get host and port
	host, port := utils.ParseHostPort(config.Target, 80) // Default to port 80 if no port specified

	ips, err := utils.GetIPs(host)
	if err != nil {
		report.Result = &discoverfern.DiscoverServiceResult{}
		return report, err
	}

	// Check if stealth mode is enabled
	if config.Stealth != nil {
		return RunStealthServiceFingerprint(ctx, config, ips)
	}

	// Standard fingerprinting path
	fingerprintConfig := scan.Config{
		FastMode:       true,
		DefaultTimeout: time.Duration(config.Timeout) * time.Second,
		UDP:            false,
		Verbose:        true,
	}

	for _, ip := range ips {
		addrPort := netip.AddrPortFrom(netip.MustParseAddr(ip.String()), uint16(port))
		fingerprintTarget := plugins.Target{Address: addrPort, Host: host}
		serviceFound := false
		var fingerprintResult *plugins.Service

		/* --- Phase 1: Run custom fingerprinters on default ports only ------- */
		// Collect applicable fingerprinters for this port
		var applicableFingerprinters []Fingerprinter
		for _, fingerprinter := range customFingerprintModules {
			defaultPorts := fingerprinter.DefaultPorts()
			// Skip if this fingerprinter has port restrictions and current port doesn't match
			if len(defaultPorts) > 0 {
				portMatches := false
				for _, p := range defaultPorts {
					if p == port {
						portMatches = true
						break
					}
				}
				if !portMatches {
					continue
				}
			}
			applicableFingerprinters = append(applicableFingerprinters, fingerprinter)
		}

		// Run applicable fingerprinters in parallel
		if len(applicableFingerprinters) > 0 {
			if detection := runFingerprintersParallel(ctx, applicableFingerprinters, ip, port, host, config.Timeout); detection != nil {
				results = append(results, detection)
				serviceFound = true
			}
		}

		/* --- Phase 2: Run fingerprintx (has its own port priority) --------- */
		if !serviceFound {
			// Wrap fingerprintx in context timeout to prevent hanging (if timeout > 0)
			var fxCtx context.Context
			var cancel context.CancelFunc

			if config.FingerprintxTimeout > 0 {
				fxCtx, cancel = context.WithTimeout(ctx, time.Duration(config.FingerprintxTimeout)*time.Second)
			} else {
				fxCtx, cancel = context.WithCancel(ctx)
			}

			resultChan := make(chan *plugins.Service, 1)
			errChan := make(chan error, 1)

			go func() {
				defer func() {
					if r := recover(); r != nil {
						errChan <- fmt.Errorf("fingerprintx panic: %v", r)
					}
				}()

				result, err := fingerprintConfig.SimpleScanTarget(fingerprintTarget)
				if err != nil {
					errChan <- err
					return
				}
				resultChan <- result
			}()

			select {
			case <-fxCtx.Done():
				// fingerprintx timed out or context cancelled - move to Phase 3
			case fxResult := <-resultChan:
				if fxResult != nil && fxResult.Protocol != "" {
					fingerprintResult = fxResult
					results = append(results, fxToServiceDetails(fingerprintResult))
					serviceFound = true
				}
			case err := <-errChan:
				// fingerprintx failed - continue to Phase 3
				_ = err
			}
			cancel()
		}

		/* --- Phase 3: Run custom fingerprinters on all ports (fallback) ---- */
		if !serviceFound {
			// Collect fingerprinters we haven't tried yet
			var fallbackFingerprinters []Fingerprinter
			for _, fingerprinter := range customFingerprintModules {
				defaultPorts := fingerprinter.DefaultPorts()
				// Skip if we already tried this fingerprinter in phase 1
				if len(defaultPorts) > 0 {
					portMatches := false
					for _, p := range defaultPorts {
						if p == port {
							portMatches = true
							break
						}
					}
					if portMatches {
						continue // Already tried in phase 1
					}
				}
				fallbackFingerprinters = append(fallbackFingerprinters, fingerprinter)
			}

			// Run fallback fingerprinters in parallel
			if len(fallbackFingerprinters) > 0 {
				if detection := runFingerprintersParallel(ctx, fallbackFingerprinters, ip, port, host, config.Timeout); detection != nil {
					results = append(results, detection)
					serviceFound = true
				}
			}
		}

		/* --- No service found ---------------------------------------------- */
		if !serviceFound {
			report.Errors = append(report.Errors, fmt.Sprintf("no service found on ip address: %s and port: %d", ip, port))
		}
	}

	report.Result = &discoverfern.DiscoverServiceResult{Services: results}
	return report, nil
}

// runFingerprintersParallel runs multiple fingerprinters concurrently and returns the first successful detection
func runFingerprintersParallel(ctx context.Context, fingerprinters []Fingerprinter, ip net.IP, port int, host string, timeout int) *discoverfern.ServiceDetails {
	// Create a cancellable context so we can stop remaining fingerprinters once we find a match
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultChan := make(chan *discoverfern.ServiceDetails, len(fingerprinters))
	doneChan := make(chan struct{})

	// Launch all fingerprinters concurrently
	for _, fp := range fingerprinters {
		go func(fingerprinter Fingerprinter) {
			select {
			case <-ctx.Done():
				return
			default:
				detection, err := fingerprinter.Detect(ctx, ip, port, host, timeout)
				if err == nil && detection != nil {
					select {
					case resultChan <- detection:
					case <-ctx.Done():
					}
				}
			}
		}(fp)
	}

	// Wait for either a result or all fingerprinters to complete
	go func() {
		// Simple completion tracking - just wait for context to be cancelled
		<-ctx.Done()
		close(doneChan)
	}()

	// Return first successful result
	select {
	case result := <-resultChan:
		cancel() // Cancel remaining fingerprinters
		return result
	case <-time.After(time.Duration(timeout) * time.Second):
		return nil
	}
}

// fxToServiceDetails converts fingerprintx result to ServiceDetails
func fxToServiceDetails(result *plugins.Service) *discoverfern.ServiceDetails {
	// Parse fingerprintx result into a map so we can enrich it
	var meta map[string]interface{}
	if len(result.Raw) > 0 {
		if err := json.Unmarshal(result.Raw, &meta); err != nil {
			// If parsing fails, create new map with raw data as string
			meta = map[string]interface{}{
				"raw": string(result.Raw),
			}
		}
	} else {
		meta = make(map[string]interface{})
	}

	// Parse Windows OS version from NTLM metadata if available
	if osVersion, exists := meta["osVersion"]; exists {
		if osVersionStr, ok := osVersion.(string); ok && osVersionStr != "" {
			// Extract build number from version like "10.0.20348" -> "Build 20348"
			parts := strings.Split(osVersionStr, ".")
			if len(parts) >= 3 {
				buildVersion := fmt.Sprintf("Build %s", parts[2])
				meta["mappedOsVersion"] = ntlm.ParseWindowsVersion(buildVersion)
			}
		}
	}

	// Convert map[string]interface{} to map[string]string for GenericServiceMetadata
	metadataMap := make(map[string]string)
	for k, v := range meta {
		metadataMap[k] = fmt.Sprintf("%v", v)
	}

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
		Version:  &result.Version,
		Metadata: discoverfern.NewServiceMetadataFromGeneric(&discoverfern.GenericServiceMetadata{Metadata: metadataMap}),
	}

	return serviceDetails
}

// runUDPServiceDiscovery scans common UDP ports on the target host and fingerprints discovered services.
// It uses custom UDP fingerprinters for DNS, NTP, SNMP, NetBIOS-NS, and DHCP.
// Each service is only probed on its well-known port(s) to avoid false positives.
func runUDPServiceDiscovery(ctx context.Context, config discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
	report := &discoverfern.DiscoverServiceReport{Config: &config}
	var results []*discoverfern.ServiceDetails

	// Parse target to get host (should be just IP, hostname, or CIDR)
	host := config.Target
	// Strip port if someone accidentally included it
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}

	// Use ParseTargetHosts to handle CIDR notation, IP ranges, and hostnames
	hostStrs, err := utils.ParseTargetHosts(host)
	if err != nil {
		report.Result = &discoverfern.DiscoverServiceResult{}
		report.Errors = append(report.Errors, fmt.Sprintf("failed to resolve target %s: %v", host, err))
		return report, nil
	}

	var ips []net.IP
	for _, h := range hostStrs {
		ips = append(ips, net.ParseIP(h))
	}

	// Scan each IP
	for _, ip := range ips {
		ipStr := ip.String()

		// Collect all UDP fingerprinters with their ports
		type udpFingerprintTask struct {
			port          int
			fingerprinter Fingerprinter
		}
		var tasks []udpFingerprintTask
		for port, fingerprinter := range udpFingerprinters {
			tasks = append(tasks, udpFingerprintTask{
				port:          int(port),
				fingerprinter: fingerprinter,
			})
		}

		// Run all UDP fingerprinters in parallel
		resultChan := make(chan *discoverfern.ServiceDetails, len(tasks))
		doneChan := make(chan struct{}, len(tasks))

		for _, task := range tasks {
			go func(t udpFingerprintTask) {
				detection, err := t.fingerprinter.Detect(ctx, ip, t.port, ipStr, config.Timeout)
				if err == nil && detection != nil {
					select {
					case resultChan <- detection:
					case <-ctx.Done():
					}
				}
				select {
				case doneChan <- struct{}{}:
				case <-ctx.Done():
				}
			}(task)
		}

		// Collect results - wait for all fingerprinters to complete or timeout
		// Each fingerprinter has its own timeout, so we give extra time for all to finish
		overallTimeout := time.After(time.Duration(config.Timeout+2) * time.Second)
		completedTasks := 0
	collectLoop:
		for completedTasks < len(tasks) {
			select {
			case detection := <-resultChan:
				results = append(results, detection)
			case <-doneChan:
				completedTasks++
			case <-overallTimeout:
				break collectLoop
			}
		}
	}

	if len(results) == 0 {
		report.Errors = append(report.Errors, fmt.Sprintf("no UDP services found on %s", host))
	}

	report.Result = &discoverfern.DiscoverServiceResult{Services: results}
	return report, nil
}
