// Package discover implements network discovery functionality for finding live hosts and services.
package discover

import (
	// Standard
	"context"
	"fmt"

	// External
	nmap "github.com/Ullaakut/nmap/v3"
)

// Report contains the results of an OS fingerprinting scan, including the nmap run results
// and any errors encountered during the process.
type Report struct {
	Run    nmap.Run `json:"run" yaml:"run"`
	Errors []string `json:"errors" yaml:"errors"`
}

// RunOsFingerprint performs OS fingerprinting on the specified target using nmap.
// It returns a report containing the detected operating system information and any errors encountered.
func RunOsFingerprint(ctx context.Context, target string) (Report, error) {
	errors := []string{}

	hostFingerprintResult, err := getFingerprint(ctx, target)
	if err != nil {
		errors = append(errors, err.Error())
	}

	return Report{
		Run:    hostFingerprintResult,
		Errors: errors,
	}, nil
}

// getFingerprint configures and runs an nmap scan with OS detection enabled.
// It uses the nmap library to perform the actual OS fingerprinting and returns the scan results.
func getFingerprint(ctx context.Context, target string) (nmap.Run, error) {
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithOSDetection(),
	)
	if err != nil {
		return nmap.Run{}, err
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		fmt.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		return nmap.Run{}, err
	}

	return *result, nil
}
