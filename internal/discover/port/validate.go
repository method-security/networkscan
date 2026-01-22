package discover

import (
	// Standard
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"

	// Generated
	discoverfern "github.com/Method-Security/networkscan/generated/go/discover"
	// Internal
	discoverservice "github.com/Method-Security/networkscan/internal/discover/service"
	"github.com/Method-Security/networkscan/utils"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// validatePortScan verifies that discovered ports actually have legitimate services running on them.
//
// Many port scanners report false positives - ports that appear open but don't actually host services,
// or services that are blocked by CDNs. This function performs service fingerprinting on each
// discovered port to confirm genuine service availability and filters out protected or non-responsive endpoints.
//
// Validation steps:
// 1. Performs service fingerprinting on each discovered port
// 2. Filters out ports that don't respond to service detection probes
// 3. Detects and removes CDN protected services that return blocking responses
// 4. Returns only sockets containing ports with confirmed active services
func validatePortScan(ctx context.Context, config discoverfern.DiscoverPortConfig, sockets []*discoverfern.SocketDetails) ([]*discoverfern.SocketDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Validating ports", svc1log.SafeParam("threads", config.ValidateThreads))

	var errorsMutex sync.Mutex
	errors := []string{}
	validatedSockets := []*discoverfern.SocketDetails{}

	// Determine number of validation threads (use CPU cores if 0 or not specified)
	maxThreads := runtime.NumCPU()
	if config.ValidateThreads != nil && *config.ValidateThreads > 0 {
		maxThreads = *config.ValidateThreads
	}

	// Resolve validation hostname once before processing all ports
	// This avoids repeated DNS lookups for every single port
	var resolvedValidationIP string
	if config.ValidateHostname != nil {
		log.Info("Resolving validation hostname once", svc1log.SafeParam("hostname", *config.ValidateHostname))
		// Import needed: "github.com/Method-Security/networkscan/utils"
		ips, err := utils.GetIPs(*config.ValidateHostname)
		if err != nil {
			errorsMutex.Lock()
			errors = append(errors, fmt.Sprintf("failed to resolve validation hostname %s: %v", *config.ValidateHostname, err))
			errorsMutex.Unlock()
			// Continue with IP-based validation only
		} else if len(ips) > 0 {
			resolvedValidationIP = ips[0].String()
			log.Info("Resolved validation hostname", svc1log.SafeParam("hostname", *config.ValidateHostname), svc1log.SafeParam("ip", resolvedValidationIP))
		}
	}

	for _, socket := range sockets {
		if socket == nil || socket.Ports == nil {
			continue
		}

		var portsMutex sync.Mutex
		validatedPorts := []*discoverfern.PortDetails{}

		// Create channel for work distribution
		portChan := make(chan *discoverfern.PortDetails, len(socket.Ports))
		var wg sync.WaitGroup

		// Start worker goroutines
		for i := 0; i < maxThreads && i < len(socket.Ports); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for port := range portChan {
					log.Info("Validating port", svc1log.SafeParam("port", port.Port))

					// Use RunServiceFingerprint to check if there's a service on this port
					// Use pre-resolved IP to avoid repeated DNS lookups
					var targetStr string
					if resolvedValidationIP != "" {
						targetStr = utils.FormatHostPort(resolvedValidationIP, port.Port)
					} else {
						targetStr = utils.FormatHostPort(socket.Ip, port.Port)
					}
					serviceConfig := discoverfern.DiscoverServiceConfig{
						Target:  targetStr,
						Timeout: *config.ValidateAttemptTimeout,
					}

					serviceReport, err := discoverservice.RunServiceFingerprint(ctx, serviceConfig)
					if err != nil {
						// Don't fail validation on errors, just log them
						errorsMutex.Lock()
						errors = append(errors, err.Error())
						errorsMutex.Unlock()
						continue
					}

					// If we found any services on this port, check if they're real services or just CDN responses
					if serviceReport != nil && serviceReport.Result != nil && serviceReport.Result.Services != nil && len(serviceReport.Result.Services) > 0 {
						hasValidService := false
						for _, service := range serviceReport.Result.Services {
							// Skip services that are only CDN responses
							if !isCDNResponse(ctx, service) {
								hasValidService = true
								break
							}
						}

						if hasValidService {
							log.Info("Valid service detected", svc1log.SafeParam("port", port.Port))
							// Valid service detected - keep this port
							portsMutex.Lock()
							validatedPorts = append(validatedPorts, port)
							portsMutex.Unlock()
						} else {
							log.Info("Only CDN responses detected, filtering out port", svc1log.SafeParam("port", port.Port))
						}
					}
				}
			}()
		}

		// Send all ports to workers
		for _, port := range socket.Ports {
			if port != nil {
				portChan <- port
			}
		}
		close(portChan)

		// Wait for all workers to complete
		wg.Wait()

		// Only include the socket if it has validated ports
		if len(validatedPorts) > 0 {
			validatedSocket := &discoverfern.SocketDetails{
				Host:  socket.Host,
				Ip:    socket.Ip,
				Ports: validatedPorts,
			}
			validatedSockets = append(validatedSockets, validatedSocket)
		}
	}

	return validatedSockets, errors
}

// isCDNResponse detects if a service response indicates a CDN blocking access.
// It checks for common patterns in HTTP/HTTPS responses that indicate CDN protection.
func isCDNResponse(ctx context.Context, service *discoverfern.ServiceDetails) bool {
	if service == nil || service.Metadata == nil {
		return false
	}

	protocol := strings.ToLower(string(service.Protocol))

	// Only check HTTP and HTTPS services
	if protocol != "http" && protocol != "https" {
		return false
	}

	// Extract metadata based on type
	// For generic metadata, use the metadata map directly
	metadataMap := make(map[string]string)
	if service.Metadata.Generic != nil && service.Metadata.Generic.Metadata != nil {
		metadataMap = service.Metadata.Generic.Metadata
	}

	// Check for specific CDN indicators regardless of status code
	return hasCDNIndicators(ctx, service.Port, metadataMap)
}

// hasCDNIndicators checks for specific headers and content patterns that indicate CDN responses.
func hasCDNIndicators(ctx context.Context, port int, metadata map[string]string) bool {
	log := svc1log.FromContext(ctx)
	if metadata == nil {
		return false
	}
	log.Info("Checking for CDN indicators", svc1log.SafeParam("port", port), svc1log.SafeParam("metadata", metadata))

	// Create case-insensitive metadata map for lookups
	normalizedMetadata := make(map[string]string)
	for key, value := range metadata {
		normalizedMetadata[strings.ToLower(key)] = value
	}

	// Check response status patterns that commonly indicate firewall blocking
	firewallStatusPatterns := []string{
		"service unavailable",
		"forbidden",
		"access denied",
		"blocked",
		"unauthorized",
		"too many requests",
		"rate limit",
		"security block",
	}
	if status, exists := normalizedMetadata["status"]; exists {
		status = strings.ToLower(status)

		for _, pattern := range firewallStatusPatterns {
			if strings.Contains(status, pattern) {
				log.Info("CDN detected via status", svc1log.SafeParam("port", port), svc1log.SafeParam("status", status), svc1log.SafeParam("pattern", pattern))
				return true
			}
		}
	}

	return false
}
