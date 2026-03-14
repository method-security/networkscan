package nuclei

import (
	// Standard
	"context"
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
// Targets are grouped by port so that each group only runs templates matching
// its port. Bare-IP targets (no port) run all templates unfiltered.
// Non-fatal errors (e.g. no templates matched a port) are returned in the warnings slice.
func RunNucleiEngine(ctx context.Context, config nuclei.NucleiConfig) ([]*nuclei.NucleiTargetInfo, []string, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Nuclei Run")

	groups := groupTargetsByPort(config.Targets)
	log.Info("Grouped targets by port", svc1log.SafeParam("groups", len(groups)))

	builder := report.NewBuilder()
	var warnings []string

	for _, g := range groups {
		log.Info("Running scan group",
			svc1log.SafeParam("port", g.port),
			svc1log.SafeParam("targets", g.targets))

		var portFilter []int
		if g.port > 0 {
			portFilter = []int{g.port}
		}

		if config.TemplatePaths == nil {
			continue
		}

		templateFS, err := templates.GetTemplateFileSystem(ctx, config.TemplatePaths, portFilter)
		if err != nil {
			log.Warn("No templates for port group, skipping",
				svc1log.SafeParam("port", g.port),
				svc1log.SafeParam("error", err.Error()))
			warnings = append(warnings, err.Error())
			continue
		}

		groupConfig := config
		groupConfig.Targets = g.targets

		runnerConfig := runner.GetRunnerConfig(templateFS, groupConfig)
		if _, err := runner.Run(ctx, runnerConfig, builder); err != nil {
			return nil, warnings, err
		}
	}

	return builder.Final(), warnings, nil
}

// targetGroup represents a set of targets that share the same port.
type targetGroup struct {
	port    int // 0 means bare IP — no port filter
	targets []string
}

// groupTargetsByPort partitions targets by their port number.
// Bare-IP targets (no port) get port=0, meaning all templates should run.
func groupTargetsByPort(targets []string) []targetGroup {
	order := []int{}
	groups := make(map[int][]string)

	for _, target := range targets {
		_, portStr, err := net.SplitHostPort(target)
		if err != nil {
			// Bare IP — group under port 0
			if _, ok := groups[0]; !ok {
				order = append(order, 0)
			}
			groups[0] = append(groups[0], target)
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 {
			if _, ok := groups[0]; !ok {
				order = append(order, 0)
			}
			groups[0] = append(groups[0], target)
			continue
		}
		if _, ok := groups[port]; !ok {
			order = append(order, port)
		}
		groups[port] = append(groups[port], target)
	}

	result := make([]targetGroup, 0, len(order))
	for _, p := range order {
		result = append(result, targetGroup{port: p, targets: groups[p]})
	}
	return result
}
