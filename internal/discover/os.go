// Package host provides the data structures and logic necessary for interacting with hosts on a network.
package discover

import (
	"context"
	"fmt"

	"github.com/Ullaakut/nmap/v3"
)

type Report struct {
	Run    nmap.Run `json:"run" yaml:"run"`
	Errors []string `json:"errors" yaml:"errors"`
}

// RunHostFingerprint takes a target host and returns a report of all hosts and OS that were detected
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
