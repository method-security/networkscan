package utils

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	utilsFern "github.com/Method-Security/networkscan/generated/go/utils"
	ftp "github.com/Method-Security/networkscan/internal/ftp/enumerate"
	smtp "github.com/Method-Security/networkscan/internal/smtp/enumerate"
	ssh "github.com/Method-Security/networkscan/internal/ssh/enumerate"
)

type NetworkApplicationLibrary interface {
	EnumerateTarget(ctx context.Context, target string) (*utilsFern.NetworkApplicationEnumerateDetails, []string)
}

type NetworkApplicationEngine struct {
	Library NetworkApplicationLibrary
}

func RunNetworkApplicationEnumerate(ctx context.Context, targets []string, networkApplication utilsFern.NetworkApplication, timeout int) (utilsFern.NetworkApplicationEnumerateReport, error) {
	log.Printf("[INFO] Starting enumeration for %d targets with a timeout of %ds", len(targets), timeout)
	resource := utilsFern.NetworkApplicationEnumerateReport{Targets: targets}

	engine, err := getEngine(networkApplication)
	if err != nil {
		return utilsFern.NetworkApplicationEnumerateReport{}, err
	}

	// Create channels for collecting results and errors
	detailsChan := make(chan *utilsFern.NetworkApplicationEnumerateDetails, len(targets))
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
				detail *utilsFern.NetworkApplicationEnumerateDetails
				errs   []string
			}, 1)

			go func() {
				detail, errs := engine.Library.EnumerateTarget(targetCtx, target)
				resultChan <- struct {
					detail *utilsFern.NetworkApplicationEnumerateDetails
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
	var details []*utilsFern.NetworkApplicationEnumerateDetails
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

// Factory function to create the appropriate engine
func getEngine(application utilsFern.NetworkApplication) (NetworkApplicationEngine, error) {
	switch application {
	case utilsFern.NetworkApplicationSsh:
		return NetworkApplicationEngine{Library: &ssh.LibraryEnumerateSSH{}}, nil
	case utilsFern.NetworkApplicationFtp:
		return NetworkApplicationEngine{Library: &ftp.LibraryEnumerateFTP{}}, nil
	case utilsFern.NetworkApplicationSmtp:
		return NetworkApplicationEngine{Library: &smtp.LibraryEnumerateSMTP{}}, nil
	default:
		return NetworkApplicationEngine{}, fmt.Errorf("unsupported network application: %v", application)
	}
}
