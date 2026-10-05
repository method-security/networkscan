package discover

import (
	// Standard
	"context"
	"runtime"
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
// Many port scanners report false positives - ports that appear open but don't actually host services.
// This function performs service fingerprinting on each discovered port to confirm service availability.
//
// Validation steps:
// 1. Performs service fingerprinting on each discovered port
// 2. Filters out ports that don't respond to service detection probes
// Conclusion:
// Returns only sockets containing ports with confirmed active services
func validatePortScan(ctx context.Context, config discoverfern.DiscoverPortConfig, sockets []*discoverfern.SocketDetails) ([]*discoverfern.SocketDetails, []string) {
	validatedPortsBySocket, errors := validatePortsBySocket(ctx, config, sockets)

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

// validatePortsBySocket verifies ports while preserving the input socket indexes.
// This lets callers validate only selected sockets and merge the filtered ports
// back into a larger scan result without affecting unrelated hosts.
func validatePortsBySocket(ctx context.Context, config discoverfern.DiscoverPortConfig, sockets []*discoverfern.SocketDetails) ([][]*discoverfern.PortDetails, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Validating ports", svc1log.SafeParam("threads", config.ValidateThreads))

	var errorsMutex sync.Mutex
	errors := []string{}
	validatedPortsBySocket := make([][]*discoverfern.PortDetails, len(sockets))

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
		return validatedPortsBySocket, errors
	}

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
					Targets:       []string{targetStr},
					Timeout:       *config.ValidateAttemptTimeout,
					Threads:       1,
					PluginThreads: config.ValidatePluginThreads,
				}

				serviceReport, err := runServiceFingerprintForValidation(ctx, serviceConfig)
				if err != nil {
					// Don't fail validation on errors, just log them
					errorsMutex.Lock()
					errors = append(errors, err.Error())
					errorsMutex.Unlock()
					continue
				}

				// A detected service confirms the port is open, regardless of its response metadata.
				if serviceReport != nil && serviceReport.Result != nil && serviceReport.Result.Services != nil && len(serviceReport.Result.Services) > 0 {
					log.Info("Valid service detected", svc1log.SafeParam("ip", task.socket.Ip), svc1log.SafeParam("port", task.port.Port))
					portsMutex.Lock()
					validatedPortsBySocket[task.socketIndex] = append(validatedPortsBySocket[task.socketIndex], task.port)
					portsMutex.Unlock()
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

	return validatedPortsBySocket, errors
}
