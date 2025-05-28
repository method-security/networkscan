// Package enumerate implements service enumeration functionality for various network protocols.
package enumerate

import (
	// Standard
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	// Generated
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	// Internal
	ftp "github.com/Method-Security/networkscan/internal/enumerate/ftp"
	grpc "github.com/Method-Security/networkscan/internal/enumerate/grpc"
	smtp "github.com/Method-Security/networkscan/internal/enumerate/smtp"
	ssh "github.com/Method-Security/networkscan/internal/enumerate/ssh"
)

// NetworkApplicationLibrary defines the interface for service-specific enumeration implementations.
// Each service type (SSH, FTP, SMTP, gRPC) must implement this interface.
type NetworkApplicationLibrary interface {
	EnumerateTarget(ctx context.Context, target string) (*enumeratefern.EnumerateServiceDetails, []string)
}

// NetworkApplicationEngine provides a wrapper around service-specific enumeration libraries.
// It manages the execution of enumeration tasks for different network services.
type NetworkApplicationEngine struct {
	Library NetworkApplicationLibrary
}

// RunServiceEnumerate performs concurrent enumeration of multiple targets for a specific service type.
// It manages timeouts, error handling, and result collection for each target.
// Returns a report containing enumeration details and any errors encountered.
func RunServiceEnumerate(ctx context.Context, targets []string, serviceType enumeratefern.ServiceType, timeout int) (enumeratefern.EnumerateServiceReport, error) {
	log.Printf("[INFO] Starting enumeration for %d targets with a timeout of %ds", len(targets), timeout)
	resource := enumeratefern.EnumerateServiceReport{Targets: targets}

	engine, err := getEngine(serviceType)
	if err != nil {
		return enumeratefern.EnumerateServiceReport{}, err
	}

	// Create channels for collecting results and errors
	detailsChan := make(chan *enumeratefern.EnumerateServiceDetails, len(targets))
	errorsChan := make(chan string, len(targets))
	var wg sync.WaitGroup

	// Process each target concurrently
	for _, target := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()

			// Create a context with timeout for each target
			targetCtx, targetCancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
			defer targetCancel()

			// Start enumeration
			resultChan := make(chan struct {
				detail *enumeratefern.EnumerateServiceDetails
				errs   []string
			}, 1)

			go func() {
				detail, errs := engine.Library.EnumerateTarget(targetCtx, target)
				resultChan <- struct {
					detail *enumeratefern.EnumerateServiceDetails
					errs   []string
				}{detail, errs}
			}()

			// Wait for either completion or timeout
			select {
			case <-targetCtx.Done():
				if targetCtx.Err() == context.DeadlineExceeded {
					errMsg := fmt.Sprintf("Timeout (%ds) while enumerating %s", timeout, target)
					errorsChan <- errMsg
					log.Printf("[ERROR] %s", errMsg)
				}
			case result := <-resultChan:
				if result.detail != nil {
					detailsChan <- result.detail
					log.Printf("[INFO] Collected enumeration details for target %s", target)
				}
				for _, err := range result.errs {
					errorsChan <- err
					log.Printf("[ERROR] %s", err)
				}
			}
		}(target)
	}

	// Close channels after all workers are done
	go func() {
		wg.Wait()
		close(detailsChan)
		close(errorsChan)
	}()

	// Collect results
	var details []*enumeratefern.EnumerateServiceDetails
	var errors []string

	for detail := range detailsChan {
		details = append(details, detail)
	}
	for err := range errorsChan {
		errors = append(errors, err)
	}

	log.Printf("[INFO] Enumeration complete. Processed %d targets with %d errors", len(targets), len(errors))
	resource.Details = details
	resource.Errors = errors
	return resource, nil
}

// getEngine creates and returns the appropriate enumeration engine for the specified service type.
// It acts as a factory function to instantiate service-specific enumeration libraries.
func getEngine(serviceType enumeratefern.ServiceType) (NetworkApplicationEngine, error) {
	switch serviceType {
	case enumeratefern.ServiceTypeSsh:
		return NetworkApplicationEngine{Library: &ssh.LibraryEnumerateSSH{}}, nil
	case enumeratefern.ServiceTypeFtp:
		return NetworkApplicationEngine{Library: &ftp.LibraryEnumerateFTP{}}, nil
	case enumeratefern.ServiceTypeSmtp:
		return NetworkApplicationEngine{Library: &smtp.LibraryEnumerateSMTP{}}, nil
	case enumeratefern.ServiceTypeGrpc:
		return NetworkApplicationEngine{Library: &grpc.LibraryEnumerateGRPC{}}, nil
	default:
		return NetworkApplicationEngine{}, fmt.Errorf("unsupported network application: %v", serviceType)
	}
}
