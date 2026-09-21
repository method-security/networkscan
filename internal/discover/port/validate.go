package discover

import (
	// Standard
	"context"
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

var runServiceFingerprintForValidation = discoverservice.RunTCPServiceFingerprint

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
//
// Conclusion:
// Returns only sockets containing ports with confirmed active services
func validatePortScan(ctx context.Context, config discoverfern.DiscoverPortConfig, sockets []*discoverfern.SocketDetails) ([]*discoverfern.SocketDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Validating ports", svc1log.SafeParam("threads", config.ValidateThreads))

	var errorsMutex sync.Mutex
	errors := []string{}

	// Determine number of validation threads (use CPU cores if 0 or not specified)
	maxThreads := runtime.NumCPU()
	if config.ValidateThreads != nil && *config.ValidateThreads > 0 {
		maxThreads = *config.ValidateThreads
	}

	if config.ValidateAttemptTimeout == nil {
		defaultTimeout := 30
		config.ValidateAttemptTimeout = &defaultTimeout
	}

	type validationTask struct {
		socketIndex int
		socket      *discoverfern.SocketDetails
		port        *discoverfern.PortDetails
	}

	var taskCount int
	for _, socket := range sockets {
		if socket != nil {
			taskCount += len(socket.Ports)
		}
	}
	if taskCount == 0 {
		return nil, errors
	}

	validatedPortsBySocket := make([][]*discoverfern.PortDetails, len(sockets))
	var portsMutex sync.Mutex
	taskChan := make(chan validationTask, taskCount)
	var wg sync.WaitGroup

	workerCount := maxThreads
	if workerCount > taskCount {
		workerCount = taskCount
	}
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskChan {
				log.Info("Validating port", svc1log.SafeParam("ip", task.socket.Ip), svc1log.SafeParam("port", task.port.Port))

				// Use TCP service fingerprinting to check if there's a service on this port.
				targetStr := utils.FormatHostPort(task.socket.Ip, task.port.Port)
				serviceConfig := discoverfern.DiscoverServiceConfig{
					Target:  targetStr,
					Timeout: *config.ValidateAttemptTimeout,
					Threads: config.ValidatePluginThreads,
				}

				serviceReport, err := runServiceFingerprintForValidation(ctx, serviceConfig)
				if err != nil {
					// Don't fail validation on errors, just log them
					errorsMutex.Lock()
					errors = append(errors, err.Error())
					errorsMutex.Unlock()
					continue
				}

				// If we found any services on this port, check if they're real services or just CDN responses.
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
						log.Info("Valid service detected", svc1log.SafeParam("ip", task.socket.Ip), svc1log.SafeParam("port", task.port.Port))
						portsMutex.Lock()
						validatedPortsBySocket[task.socketIndex] = append(validatedPortsBySocket[task.socketIndex], task.port)
						portsMutex.Unlock()
					} else {
						log.Info("Only CDN responses detected, filtering out port", svc1log.SafeParam("ip", task.socket.Ip), svc1log.SafeParam("port", task.port.Port))
					}
				}
			}
		}()
	}

	for socketIndex, socket := range sockets {
		if socket == nil || socket.Ports == nil {
			continue
		}
		for _, port := range socket.Ports {
			if port != nil {
				taskChan <- validationTask{socketIndex: socketIndex, socket: socket, port: port}
			}
		}
	}
	close(taskChan)
	wg.Wait()

	validatedSockets := []*discoverfern.SocketDetails{}
	for socketIndex, socket := range sockets {
		if socket == nil || len(validatedPortsBySocket[socketIndex]) == 0 {
			continue
		}
		validatedSockets = append(validatedSockets, &discoverfern.SocketDetails{
			Host:  socket.Host,
			Ip:    socket.Ip,
			Ports: validatedPortsBySocket[socketIndex],
		})
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
