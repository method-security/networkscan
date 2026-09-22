// Package service implements service fingerprinting functionality for discovering running services.
package service

import (
	// Standard
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	// Internal
	servicehelpers "github.com/Method-Security/networkscan/internal/discover/service/helpers"
	// Utilities
	"github.com/Method-Security/networkscan/utils"
)

// RunServiceFingerprint fingerprints services using the transport selected in
// config. New callers should prefer RunTCPServiceFingerprint or
// RunUDPServiceFingerprint directly.
func RunServiceFingerprint(ctx context.Context, config discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
	if config.Udp != nil && *config.Udp {
		return RunUDPServiceFingerprint(ctx, config)
	}
	return RunTCPServiceFingerprint(ctx, config)
}

// RunTCPServiceFingerprint fingerprints the TCP service at target:port.
//  1. If stealth mode is enabled, use targeted fingerprinting for the specified service type.
//  2. Otherwise, for TCP (port-priority system):
//     Phase 1: Run custom fingerprinters ONLY if port matches their default ports
//     Phase 2: If nothing found, run the remaining plugins on non-default ports.
func RunTCPServiceFingerprint(ctx context.Context, config discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
	report := &discoverfern.DiscoverServiceReport{Config: &config}

	if config.Stealth != nil {
		for _, target := range config.Targets {
			_, portStr, err := net.SplitHostPort(target)
			if err != nil {
				report.Errors = append(report.Errors, "stealth mode requires explicit port specification (use format host:port)")
				return report, nil
			}
			if utils.ParsePort(portStr) == 0 {
				report.Errors = append(report.Errors, fmt.Sprintf("invalid port specified: %s", portStr))
				return report, nil
			}
		}
	}

	targets, err := parseTCPServiceTargets(config.Targets)
	if err != nil {
		report.Result = &discoverfern.DiscoverServiceResult{}
		return report, err
	}

	// Check if stealth mode is enabled
	if config.Stealth != nil {
		return runStealthServiceFingerprintTargets(ctx, config, targets)
	}

	resultsByIP := make([][]*discoverfern.ServiceDetails, len(targets))
	errorsByIP := make([][]string, len(targets))
	runTargetsParallel(ctx, targets, config.Threads, func(targetCtx context.Context, index int, target serviceTarget) {
		resultsByIP[index], errorsByIP[index] = runTCPServiceFingerprintForIP(targetCtx, config, target.host, target.port, target.ip)
	})

	var results []*discoverfern.ServiceDetails
	for index := range targets {
		results = append(results, resultsByIP[index]...)
		report.Errors = append(report.Errors, errorsByIP[index]...)
	}

	report.Result = &discoverfern.DiscoverServiceResult{Services: results}
	return report, nil
}

// RunUDPServiceFingerprint scans common UDP ports on one or more target hosts.
func RunUDPServiceFingerprint(ctx context.Context, config discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
	return runUDPServiceDiscovery(ctx, config)
}

type serviceTarget struct {
	ip   net.IP
	host string
	port int
}

func parseServiceTargets(target string) ([]serviceTarget, error) {
	hostStrs, ipToHostname, err := utils.ParseTargetHostsWithMapping(target)
	if err != nil {
		return nil, err
	}

	targets := make([]serviceTarget, 0, len(hostStrs))
	for _, hostStr := range hostStrs {
		ip := net.ParseIP(hostStr)
		if ip == nil {
			continue
		}

		fingerprintHost := hostStr
		if hostname, ok := ipToHostname[hostStr]; ok {
			fingerprintHost = hostname
		}
		targets = append(targets, serviceTarget{ip: ip, host: fingerprintHost})
	}
	return targets, nil
}

func parseTCPServiceTargets(targets []string) ([]serviceTarget, error) {
	var expandedTargets []serviceTarget
	for _, target := range targets {
		host, port := utils.ParseHostPort(target, 80)
		targetsForHost, err := parseServiceTargets(host)
		if err != nil {
			return nil, err
		}
		for _, targetForHost := range targetsForHost {
			targetForHost.port = port
			expandedTargets = append(expandedTargets, targetForHost)
		}
	}
	return expandedTargets, nil
}

func runTCPServiceFingerprintForIP(ctx context.Context, config discoverfern.DiscoverServiceConfig, host string, port int, ip net.IP) ([]*discoverfern.ServiceDetails, []string) {
	var results []*discoverfern.ServiceDetails
	var errors []string

	serviceFound := false

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
		if detection := runFingerprintersParallel(ctx, applicableFingerprinters, ip, port, host, config.Timeout, config.PluginThreads); detection != nil {
			results = append(results, detection)
			serviceFound = true
		}
	}

	/* --- Phase 2: Run remaining fingerprinters on all ports (fallback) ---- */
	if !serviceFound {
		// Collect fingerprinters we haven't tried yet
		var fallbackFingerprinters []Fingerprinter
		for _, fingerprinter := range customFingerprintModules {
			defaultPorts := fingerprinter.DefaultPorts()
			if len(defaultPorts) == 0 {
				continue
			} // Unrestricted plugins already ran in phase 1.
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
			if detection := runFingerprintersParallel(ctx, fallbackFingerprinters, ip, port, host, config.Timeout, config.PluginThreads); detection != nil {
				results = append(results, detection)
				serviceFound = true
			}
		}
	}

	/* --- No service found ---------------------------------------------- */
	if !serviceFound {
		errors = append(errors, fmt.Sprintf("no service found on ip address: %s and port: %d", ip, port))
	}

	return results, errors
}

type fingerprinterResult struct {
	index   int
	details *discoverfern.ServiceDetails
}

type fingerprinterAttemptResult struct {
	details *discoverfern.ServiceDetails
	err     error
}

// runFingerprinterAttempt stops waiting when the attempt timeout expires, even
// if the plugin does not return promptly after its context is cancelled.
func runFingerprinterAttempt(ctx context.Context, timeout int, detect func(context.Context) (*discoverfern.ServiceDetails, error)) (*discoverfern.ServiceDetails, error) {
	pluginCtx, cancel := servicehelpers.Context(ctx, timeout)
	defer cancel()

	select {
	case <-pluginCtx.Done():
		return nil, pluginCtx.Err()
	default:
	}

	resultChan := make(chan fingerprinterAttemptResult, 1)
	go func() {
		result := fingerprinterAttemptResult{}
		defer func() {
			if recovered := recover(); recovered != nil {
				result.err = fmt.Errorf("fingerprinter panic: %v", recovered)
			}
			resultChan <- result
		}()
		result.details, result.err = detect(pluginCtx)
	}()

	select {
	case result := <-resultChan:
		return result.details, result.err
	case <-pluginCtx.Done():
		return nil, pluginCtx.Err()
	}
}

// runFingerprintersParallel runs multiple fingerprinters concurrently and returns
// the highest-priority successful detection based on registry order.
func runFingerprintersParallel(ctx context.Context, fingerprinters []Fingerprinter, ip net.IP, port int, host string, timeout int, threads int) *discoverfern.ServiceDetails {
	if len(fingerprinters) == 0 {
		return nil
	}

	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultChan := make(chan fingerprinterResult, len(fingerprinters))
	sem := make(chan struct{}, effectivePluginThreads(threads, len(fingerprinters)))

	for index, fingerprinter := range fingerprinters {
		go func(index int, fingerprinter Fingerprinter) {
			result := fingerprinterResult{index: index}
			defer func() {
				if recover() != nil {
					result.details = nil
				}
				resultChan <- result
			}()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-probeCtx.Done():
				return
			}

			detection, err := runFingerprinterAttempt(probeCtx, timeout, func(pluginCtx context.Context) (*discoverfern.ServiceDetails, error) {
				return fingerprinter.Detect(pluginCtx, ip, port, host, timeout)
			})
			if err == nil && detection != nil {
				result.details = detection
			}
		}(index, fingerprinter)
	}

	completed := make([]bool, len(fingerprinters))
	bestIndex := len(fingerprinters)
	var best *discoverfern.ServiceDetails

	for completedCount := 0; completedCount < len(fingerprinters); {
		select {
		case result := <-resultChan:
			completedCount++
			completed[result.index] = true
			if result.details != nil && result.index < bestIndex {
				bestIndex = result.index
				best = result.details
			}
			// A match is final only after all earlier registry entries have
			// completed; an earlier entry may be a more-specific overlap.
			if best != nil && noEarlierFingerprintersPending(completed, bestIndex) {
				return best
			}
		case <-ctx.Done():
			cancel()
			return best
		}
	}
	return best
}

func effectivePluginThreads(configured int, total int) int {
	if total <= 0 {
		return 0
	}
	if configured <= 0 {
		return 1
	}
	if configured > total {
		return total
	}
	return configured
}

func runTargetsParallel[T any](ctx context.Context, targets []T, threads int, run func(context.Context, int, T)) {
	if len(targets) == 0 {
		return
	}

	sem := make(chan struct{}, effectivePluginThreads(threads, len(targets)))
	var wg sync.WaitGroup
	for index, target := range targets {
		wg.Add(1)
		go func(index int, target T) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			run(ctx, index, target)
		}(index, target)
	}
	wg.Wait()
}

func noEarlierFingerprintersPending(completed []bool, bestIndex int) bool {
	for i := 0; i < bestIndex; i++ {
		if !completed[i] {
			return false
		}
	}
	return true
}

// runUDPServiceDiscovery scans common UDP ports on the target host and fingerprints discovered services.
// Each service is only probed on its well-known port(s) to avoid false positives.
func runUDPServiceDiscovery(ctx context.Context, config discoverfern.DiscoverServiceConfig) (*discoverfern.DiscoverServiceReport, error) {
	report := &discoverfern.DiscoverServiceReport{Config: &config}

	var targets []serviceTarget
	for _, rawTarget := range config.Targets {
		host := rawTarget
		// Strip port if someone accidentally included it
		if strings.Contains(host, ":") {
			host, _, _ = net.SplitHostPort(host)
		}

		targetsForHost, err := parseServiceTargets(host)
		if err != nil {
			report.Result = &discoverfern.DiscoverServiceResult{}
			report.Errors = append(report.Errors, fmt.Sprintf("failed to resolve target %s: %v", host, err))
			return report, nil
		}
		targets = append(targets, targetsForHost...)
	}

	resultsByIP := make([][]*discoverfern.ServiceDetails, len(targets))
	runTargetsParallel(ctx, targets, config.Threads, func(targetCtx context.Context, index int, target serviceTarget) {
		resultsByIP[index] = runUDPServiceDiscoveryForIP(targetCtx, config, target.ip, target.host)
	})

	var results []*discoverfern.ServiceDetails
	for index := range targets {
		results = append(results, resultsByIP[index]...)
	}

	if len(results) == 0 {
		report.Errors = append(report.Errors, fmt.Sprintf("no UDP services found on %s", strings.Join(config.Targets, ",")))
	}

	report.Result = &discoverfern.DiscoverServiceResult{Services: results}
	return report, nil
}

func runUDPServiceDiscoveryForIP(ctx context.Context, config discoverfern.DiscoverServiceConfig, ip net.IP, host string) []*discoverfern.ServiceDetails {
	type udpFingerprintTask struct {
		port   int
		detect func(context.Context) (*discoverfern.ServiceDetails, error)
	}
	var tasks []udpFingerprintTask
	for port, fingerprinter := range udpFingerprinters {
		port := int(port)
		fingerprinter := fingerprinter
		tasks = append(tasks, udpFingerprintTask{
			port: port,
			detect: func(pluginCtx context.Context) (*discoverfern.ServiceDetails, error) {
				return fingerprinter.Detect(pluginCtx, ip, port, host, config.Timeout)
			},
		})
	}

	resultChan := make(chan *discoverfern.ServiceDetails, len(tasks))
	sem := make(chan struct{}, effectivePluginThreads(config.PluginThreads, len(tasks)))

	for _, task := range tasks {
		go func(t udpFingerprintTask) {
			var detection *discoverfern.ServiceDetails
			defer func() {
				resultChan <- detection
			}()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			result, err := runFingerprinterAttempt(ctx, config.Timeout, t.detect)
			if err == nil {
				detection = result
			}
		}(task)
	}

	var results []*discoverfern.ServiceDetails
	for completedTasks := 0; completedTasks < len(tasks); completedTasks++ {
		select {
		case detection := <-resultChan:
			if detection != nil {
				results = append(results, detection)
			}
		case <-ctx.Done():
			return results
		}
	}

	return results
}
