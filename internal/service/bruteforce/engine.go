package bruteforce

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/Method-Security/networkscan/generated/go/service/bruteforce"
	modules "github.com/Method-Security/networkscan/internal/service/bruteforce/modules"
)

type Library interface {
	BruteForce(host string, port int, credPair *bruteforce.CredentialPair, config *bruteforce.BruteForceRunConfig) (*bruteforce.AttemptInfo, []string)
	AnalyzeResponse(response *bruteforce.ResponseUnion) *bruteforce.ResultInfo
	StandardPorts() []int
}

type Engine struct {
	Library Library
}

func (e *Engine) Run(ctx context.Context, target string, credPair *bruteforce.CredentialPair, config *bruteforce.BruteForceRunConfig) ([]*bruteforce.AttemptInfo, bool, []string) {
	var (
		attempts   []*bruteforce.AttemptInfo
		successful bool
		errors     []string
	)

	host, ports, err := getHostAndPorts(target, e.Library.StandardPorts())
	if err != nil {
		return attempts, successful, append(errors, err.Error())
	}

	for _, port := range ports {
		for i := 0; i < config.Retries; i++ {
			var attempt *bruteforce.AttemptInfo
			var errs []string

			attempt, errs = e.Library.BruteForce(host, port, credPair, config)

			errors = append(errors, errs...)
			attempts = append(attempts, attempt)

			if attempt.Result.Login {
				successful = true
				break
			}
			if config.Sleep > 0 {
				time.Sleep(time.Duration(config.Sleep) * time.Millisecond)
			}
		}
	}

	return attempts, successful, errors
}

func (e *Engine) gatherAttemptStatistics(attempts []*bruteforce.AttemptInfo, config *bruteforce.BruteForceRunConfig) *bruteforce.StatisticsInfo {
	stats := &bruteforce.StatisticsInfo{
		NumUsernames: len(config.Usernames),
		NumPasswords: len(config.Passwords),
	}

	for _, attempt := range attempts {
		if attempt.Result.Login {
			stats.NumSuccessful++
		}
	}
	stats.NumFailed = len(attempts) - stats.NumSuccessful

	return stats
}

func Attack(ctx context.Context, config *bruteforce.BruteForceRunConfig) (*bruteforce.BruteForceReport, error) {
	resources := bruteforce.BruteForceReport{}
	errors := []string{}

	var engine *Engine
	switch config.Module {
	case "ssh":
		engine = &Engine{
			Library: &modules.SSHLibrary{},
		}
	case "telnet":
		engine = &Engine{
			Library: &modules.TelnetLibrary{},
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
