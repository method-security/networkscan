package fingerprint

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	addressfern "github.com/Method-Security/networkscan/generated/go/address"
	"github.com/Method-Security/networkscan/internal/address/fingerprint/modules/database"
	remoteaccess "github.com/Method-Security/networkscan/internal/address/fingerprint/modules/remoteaccess"
)

type Module interface {
	StandardPorts() []int
	Name() *addressfern.AddressFingerprintResourceModule
	TryProtocols(address string, timeout time.Duration) addressfern.TryProtocols
	AnalyzeResponse(connectionData string) bool
}

type Engine struct {
	Library Module
	Config  *addressfern.AddressFingerprintConfig
	Modules map[addressfern.AddressFingerprintResourceType]map[addressfern.AddressFingerprintResourceModule]Module
}

func NewEngine(config *addressfern.AddressFingerprintConfig) *Engine {
	return &Engine{
		Config: config,
		Modules: map[addressfern.AddressFingerprintResourceType]map[addressfern.AddressFingerprintResourceModule]Module{
			addressfern.AddressFingerprintResourceTypeDatabase: {
				*addressfern.NewAddressFingerprintResourceModuleFromDatabaseModule(addressfern.DatabaseModuleMysql):      &database.MySQLLibrary{},
				*addressfern.NewAddressFingerprintResourceModuleFromDatabaseModule(addressfern.DatabaseModulePostgresql): &database.PostgreSQLLibrary{},
			},
			addressfern.AddressFingerprintResourceTypeRemoteaccess: {
				*addressfern.NewAddressFingerprintResourceModuleFromRemoteAccessModule(addressfern.RemoteAccessModuleWindowsrdp): &remoteaccess.WindowsRDPLibrary{},
			},
		},
	}
}

func (e *Engine) GetModules() ([]Module, error) {
	var moduleLibs []Module

	appendModules := func(resourceModules map[addressfern.AddressFingerprintResourceModule]Module) {
		if len(e.Config.Modules) == 0 {
			for _, module := range resourceModules {
				moduleLibs = append(moduleLibs, module)
			}
		} else {
			for _, moduleName := range e.Config.Modules {
				if module, exists := resourceModules[*moduleName]; exists {
					moduleLibs = append(moduleLibs, module)
				}
			}
		}
	}

	switch e.Config.ResourceType {
	case addressfern.AddressFingerprintResourceTypeDatabase:
		appendModules(e.Modules[addressfern.AddressFingerprintResourceTypeDatabase])
	case addressfern.AddressFingerprintResourceTypeRemoteaccess:
		appendModules(e.Modules[addressfern.AddressFingerprintResourceTypeRemoteaccess])
	default:
		return nil, fmt.Errorf("unsupported module type: %s", e.Config.ResourceType)
	}

	return moduleLibs, nil
}

func (e *Engine) Run(ctx context.Context, target string) ([]*addressfern.AddressFingerprintAttemptInfo, []string) {
	var (
		attempts []*addressfern.AddressFingerprintAttemptInfo
		errors   []string
		portList []int
	)

	// Get standard ports for the current module
	ports := e.Library.StandardPorts()

	log.Printf("[INFO] Running detection on %s", target)

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		portList = ports
	} else if portInt, convErr := strconv.Atoi(port); convErr == nil {
		portList = []int{portInt}
	} else {
		errors = append(errors, fmt.Sprintf("Error converting port from string to int: %s", convErr))
	}

	for _, port := range portList {
		attempt := &addressfern.AddressFingerprintAttemptInfo{
			Module:  e.Library.Name(),
			Host:    host,
			Port:    port,
			Finding: false,
		}

		targetAddress := net.JoinHostPort(host, strconv.Itoa(port))
		log.Printf("[INFO] Attempting to connect to %s", targetAddress)

		// Use RDP protocol detection
		tryProtocolsFunction := e.Library.TryProtocols(targetAddress, time.Duration(e.Config.Timeout)*time.Second)
		if len(tryProtocolsFunction.Errors) > 0 {
			errors = append(errors, tryProtocolsFunction.Errors...)
		}

		// Set attempt details
		attempt.Protocol = &tryProtocolsFunction.Protocol

		// if connection data is not nil, analyze the response
		if tryProtocolsFunction.ConnectionData != nil {
			// Analyze response
			if e.Library.AnalyzeResponse(*tryProtocolsFunction.ConnectionData) {
				attempt.Finding = true
				log.Printf("[INFO] %s service detected on %s", *e.Library.Name(), targetAddress)
			} else {
				log.Printf("[INFO] Connected but %s service not detected on %s", *e.Library.Name(), targetAddress)
			}
		} else {
			log.Printf("[INFO] Failed to connect to %s", targetAddress)
		}

		attempts = append(attempts, attempt)
	}
	return attempts, errors
}

func (e *Engine) RunAddressFingerprint(ctx context.Context) (*addressfern.AddressFingerprintReport, error) {
	report := addressfern.AddressFingerprintReport{Config: e.Config}
	errors := []string{}

	moduleLibs, err := e.GetModules()
	if err != nil {
		return nil, err
	}

	var targets []*addressfern.AddressFingerprintTargetInfo
	for _, target := range e.Config.Targets {
		var attempts []*addressfern.AddressFingerprintAttemptInfo
		for _, moduleLib := range moduleLibs {
			// Set current module library in the engine
			e.Library = moduleLib

			// Marshal Attempt results
			attempt, errs := e.Run(ctx, target)
			attempts = append(attempts, attempt...)
			errors = append(errors, errs...)
		}

		if e.Config.SuccessfulOnly {
			successfulAttempts := []*addressfern.AddressFingerprintAttemptInfo{}
			for _, attempt := range attempts {
				if attempt.Finding {
					successfulAttempts = append(successfulAttempts, attempt)
				}
			}
			attempts = successfulAttempts
		}

		target := addressfern.AddressFingerprintTargetInfo{Target: target, Attempts: attempts}
		targets = append(targets, &target)
	}

	// Marshal Report
	report.Targets = targets
	report.Errors = errors
	return &report, nil
}
