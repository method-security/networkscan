package fingerprint

import (
	"context"
	"fmt"

	addressfern "github.com/Method-Security/networkscan/generated/go/address"
	remoteaccess "github.com/Method-Security/networkscan/internal/address/fingerprint/modules/remoteaccess"
)

type Module interface {
	StandardPorts() []int
	Name() *addressfern.AddressFingerprintResourceModule
	ModuleRun(ctx context.Context, target string, timeout int) ([]*addressfern.AddressFingerprintAttemptInfo, []string)
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
			addressfern.AddressFingerprintResourceTypeRemoteaccess: {
				*addressfern.NewAddressFingerprintResourceModuleFromRemoteAccessModule(addressfern.RemoteAccessModuleCitrixGateway): &remoteaccess.CitrixGatewayLibrary{},
				*addressfern.NewAddressFingerprintResourceModuleFromRemoteAccessModule(addressfern.RemoteAccessModuleMicrosoftRdp):  &remoteaccess.RDPLibrary{},
				*addressfern.NewAddressFingerprintResourceModuleFromRemoteAccessModule(addressfern.RemoteAccessModuleVmwareHorizon): &remoteaccess.VMwareHorizonLibrary{},
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
	case addressfern.AddressFingerprintResourceTypeRemoteaccess:
		appendModules(e.Modules[addressfern.AddressFingerprintResourceTypeRemoteaccess])
	default:
		return nil, fmt.Errorf("unsupported module type: %s", e.Config.ResourceType)
	}

	return moduleLibs, nil
}

func (e *Engine) Run(ctx context.Context, target string) ([]*addressfern.AddressFingerprintAttemptInfo, []string) {
	return e.Library.ModuleRun(ctx, target, e.Config.Timeout)
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
