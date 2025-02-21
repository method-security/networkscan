package host

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/Method-Security/networkscan/generated/go/address/bruteforce"
	modules "github.com/Method-Security/networkscan/internal/address/bruteforce/modules"
)

type BruteforceLibrary interface {
	BruteForce(host string, port int, credPair *bruteforce.CredentialPair, config *bruteforce.BruteForceRunConfig) (*bruteforce.AttemptInfo, []string)
	AnalyzeResponse(response *bruteforce.ResponseUnion) *bruteforce.ResultInfo
	StandardPorts() []int
}

type BruteforceEngine struct {
	Library BruteforceLibrary
}

func (be *BruteforceEngine) Run(ctx context.Context, target string, credPair *bruteforce.CredentialPair, config *bruteforce.BruteForceRunConfig) ([]*bruteforce.AttemptInfo, bool, []string) {
	var (
		attempts   []*bruteforce.AttemptInfo
		successful bool
		errors     []string
	)

	host, ports, err := getHostAndPorts(target, be.Library.StandardPorts())
	if err != nil {
		return attempts, successful, append(errors, err.Error())
	}

	for _, port := range ports {
		for i := 0; i < config.Retries; i++ {
			var attempt *bruteforce.AttemptInfo
			var errs []string

			attempt, errs = be.Library.BruteForce(host, port, credPair, config)

			errors = append(errors, errs...)
			attempts = append(attempts, attempt)

			if attempt.Result != nil {
				if attempt.Result.Login {
					successful = true
					break
				}
				if attempt.Result.Ratelimit {
					time.Sleep(time.Duration(config.Sleep) * time.Millisecond)
				}
			}
		}
	}

	return attempts, successful, errors
}

func (be *BruteforceEngine) gatherAttemptStatistics(attempts []*bruteforce.AttemptInfo, config *bruteforce.BruteForceRunConfig) *bruteforce.StatisticsInfo {
	stats := &bruteforce.StatisticsInfo{
		NumUsernames: len(config.Usernames),
		NumPasswords: len(config.Passwords),
	}

	for _, attempt := range attempts {
		if attempt.Result != nil && attempt.Result.Login {
			stats.NumSuccessful++
		}
	}
	stats.NumFailed = len(attempts) - stats.NumSuccessful

	return stats
}

func BruteForceAttack(ctx context.Context, config *bruteforce.BruteForceRunConfig) (*bruteforce.BruteForceReport, error) {
	resources := bruteforce.BruteForceReport{}
	errors := []string{}

	var engine *BruteforceEngine
	switch config.Module {
	case "ssh":
		engine = &BruteforceEngine{
			Library: &modules.SSHLibrary{},
		}
	case "telnet":
		engine = &BruteforceEngine{
			Library: &modules.TelnetLibrary{},
		}
	case "ftp":
		engine = &BruteforceEngine{
			Library: &modules.FTPLibrary{},
		}
	case "smtp":
		engine = &BruteforceEngine{
			Library: &modules.SMTPLibrary{},
		}
	default:
		return &resources, fmt.Errorf("unsupported module: %s", config.Module)
	}

	var bruteForceResults []*bruteforce.BruteForceAttempt
	for _, target := range config.Targets {
		var attempts []*bruteforce.AttemptInfo

		// UnAuthenticated attempt
		attempt, successful, errs := engine.Run(ctx, target, nil, config)
		errors = append(errors, errs...)
		attempts = append(attempts, attempt...)

		// Authenticated attempts
		if !successful {
			credPairs := getCredentialPairs(config.Usernames, config.Passwords)
			totalPairs := len(credPairs)
			interval := (totalPairs / 20) + 1 // For when (totalPairs / 20) == 0

			for i, credPair := range credPairs {
				attempt, successful, errs := engine.Run(ctx, target, &credPair, config)
				errors = append(errors, errs...)
				attempts = append(attempts, attempt...)

				if successful && config.StopFirstSuccess {
					break
				}

				if i%interval == 0 {
					fmt.Printf("%d credential pairs have been tried (%d/%d)\n", i, i, totalPairs)
				}
			}
		}

		stats := engine.gatherAttemptStatistics(attempts, config)
		stats.RunConfig = config

		if config.SuccessfulOnly {
			successfulAttempts := []*bruteforce.AttemptInfo{}
			for _, attempt := range attempts {
				if attempt.Result.Login {
					successfulAttempts = append(successfulAttempts, attempt)
				}
			}
			attempts = successfulAttempts
		}

		bruteForceResult := bruteforce.BruteForceAttempt{
			Target:     target,
			Attempts:   attempts,
			Statistics: stats,
		}
		bruteForceResults = append(bruteForceResults, &bruteForceResult)
	}

	resources.Module = config.Module
	resources.BruteForceAttempts = bruteForceResults
	resources.Errors = errors
	return &resources, nil
}

func getCredentialPairs(usernames []string, passwords []string) []bruteforce.CredentialPair {
	pairs := []bruteforce.CredentialPair{}
	if len(usernames) == 0 {
		for _, password := range passwords {
			pairs = append(pairs, bruteforce.CredentialPair{Password: password, Username: ""})
		}
		return pairs
	}
	for _, password := range passwords {
		for _, username := range usernames {
			pairs = append(pairs, bruteforce.CredentialPair{Password: password, Username: username})
		}
	}
	return pairs
}

func getHostAndPorts(target string, standardPorts []int) (string, []int, error) {
	var ports []int
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		ports = standardPorts
	} else {
		intPort, err := strconv.Atoi(port)
		if err != nil {
			return "", nil, err
		}
		ports = []int{intPort}
	}
	return host, ports, nil
}
