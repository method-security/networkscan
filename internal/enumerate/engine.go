// Package enumerate implements service enumeration functionality for various network protocols.
package enumerate

import (
	// Standard
	"context"
	"fmt"
	"sync"
	"time"

	// Generated
	enumeratefern "github.com/Method-Security/networkscan/generated/go/enumerate"
	// Internal
	ftp "github.com/Method-Security/networkscan/internal/enumerate/ftp"
	grpc "github.com/Method-Security/networkscan/internal/enumerate/grpc"
	ike "github.com/Method-Security/networkscan/internal/enumerate/ike"
	ldap "github.com/Method-Security/networkscan/internal/enumerate/ldap"
	smb "github.com/Method-Security/networkscan/internal/enumerate/smb"
	smtp "github.com/Method-Security/networkscan/internal/enumerate/smtp"
	snmp "github.com/Method-Security/networkscan/internal/enumerate/snmp"
	ssh "github.com/Method-Security/networkscan/internal/enumerate/ssh"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// NetworkApplicationLibrary defines the interface for service-specific enumeration implementations.
// Each service type (SSH, FTP, SMTP, gRPC, SMB, LDAP) must implement this interface.
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
func RunServiceEnumerate(ctx context.Context, config enumeratefern.EnumerateServiceConfig) (enumeratefern.EnumerateServiceReport, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting enumeration for targets",
		svc1log.SafeParam("targets", len(config.Targets)),
		svc1log.SafeParam("timeout", config.Timeout))
	resource := enumeratefern.EnumerateServiceReport{Config: &config}

	engine, err := getEngine(config)
	if err != nil {
		return enumeratefern.EnumerateServiceReport{}, err
	}

	// Create channels for collecting results and errors
	detailsChan := make(chan *enumeratefern.EnumerateServiceDetails, len(config.Targets))
	errorsChan := make(chan string, len(config.Targets)*20)
	var wg sync.WaitGroup

	// Process each target concurrently
	for _, target := range config.Targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()

			// Create a context with timeout for each target
			targetCtx, targetCancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
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
					errMsg := fmt.Sprintf("Timeout (%ds) while enumerating %s", config.Timeout, target)
					errorsChan <- errMsg
					log.Error("Enumeration timeout",
						svc1log.SafeParam("target", target),
						svc1log.SafeParam("timeout", config.Timeout))
				}
			case result := <-resultChan:
				if result.detail != nil {
					detailsChan <- result.detail
					log.Info("Collected enumeration details for target", svc1log.SafeParam("target", target))
				}
				for _, err := range result.errs {
					errorsChan <- err
					log.Error("Enumeration error", svc1log.SafeParam("error", err))
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

	log.Info("Enumeration complete",
		svc1log.SafeParam("targets", len(config.Targets)),
		svc1log.SafeParam("errors", len(errors)))
	resource.Result = &enumeratefern.EnumerateServiceResult{Details: details}
	resource.Errors = errors
	return resource, nil
}

// getEngine creates and returns the appropriate enumeration engine for the specified service type.
// It acts as a factory function to instantiate service-specific enumeration libraries.
func getEngine(config enumeratefern.EnumerateServiceConfig) (NetworkApplicationEngine, error) {
	switch config.Service {
	case enumeratefern.SupportedServiceTypeSsh:
		return NetworkApplicationEngine{Library: &ssh.LibraryEnumerateSSH{}}, nil
	case enumeratefern.SupportedServiceTypeFtp:
		return NetworkApplicationEngine{Library: &ftp.LibraryEnumerateFTP{}}, nil
	case enumeratefern.SupportedServiceTypeSmtp:
		return NetworkApplicationEngine{Library: &smtp.LibraryEnumerateSMTP{Wordlist: config.Wordlist}}, nil
	case enumeratefern.SupportedServiceTypeGrpc:
		return NetworkApplicationEngine{Library: &grpc.LibraryEnumerateGRPC{}}, nil
	case enumeratefern.SupportedServiceTypeSmb:
		return NetworkApplicationEngine{Library: &smb.LibraryEnumerateSMB{}}, nil
	case enumeratefern.SupportedServiceTypeLdap:
		return NetworkApplicationEngine{Library: &ldap.LibraryEnumerateLDAP{}}, nil
	case enumeratefern.SupportedServiceTypeIke:
		return NetworkApplicationEngine{Library: &ike.LibraryEnumerateIKE{}}, nil
	case enumeratefern.SupportedServiceTypeSnmp:
		return NetworkApplicationEngine{Library: &snmp.LibraryEnumerateSNMP{}}, nil
	default:
		return NetworkApplicationEngine{}, fmt.Errorf("unsupported network application: %v", config.Service)
	}
}
