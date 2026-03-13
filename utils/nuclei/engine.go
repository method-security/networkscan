package nuclei

import (
	// Standard
	"context"
	"io/fs"
	"net"
	"strconv"

	// Generated
	nuclei "github.com/Method-Security/networkscan/generated/go/common/nuclei"
	// Utils
	report "github.com/Method-Security/networkscan/utils/nuclei/report"
	runner "github.com/Method-Security/networkscan/utils/nuclei/runner"
	templates "github.com/Method-Security/networkscan/utils/nuclei/templates"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// RunNucleiEngine runs the Nuclei engine with the given config for network CVE scanning.
func RunNucleiEngine(ctx context.Context, config nuclei.NucleiConfig) ([]*nuclei.NucleiTargetInfo, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Nuclei Run")

	// Parse ports from targets for template filtering
	targetPorts := parsePortsFromTargets(config.Targets)
	if len(targetPorts) > 0 {
		log.Info("Parsed ports from targets for template filtering",
			svc1log.SafeParam("targetPorts", targetPorts))
	}

	// Get the template and workflow file systems
	var templateFileSystems []fs.FS
	var err error

	// Get template file systems, filtering by ports extracted from targets
	if config.TemplatePaths != nil {
		templateFileSystems, err = templates.GetTemplateFileSystem(ctx, config.TemplatePaths, targetPorts)
		if err != nil {
			return nil, err
		}
	}

	// Get the runner config
	runnerConfig := runner.GetRunnerConfig(templateFileSystems, config)

	// Build the report builder and run the nuclei engine
	builder := report.NewBuilder()
	return runner.Run(ctx, runnerConfig, builder)
}

// parsePortsFromTargets extracts unique port numbers from target strings.
// Targets can be "host:port", "host", or bare IPs. Targets without an explicit
// port are skipped so that no accidental filtering occurs.
func parsePortsFromTargets(targets []string) []int {
	seen := make(map[int]bool)
	var ports []int

	for _, target := range targets {
		_, portStr, err := net.SplitHostPort(target)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 {
			continue
		}
		if !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
	}
	return ports
}
