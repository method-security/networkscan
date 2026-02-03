package nuclei

import (
	// Standard
	"context"
	"io/fs"

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

	// Get the template and workflow file systems
	var templateFileSystems []fs.FS
	var err error

	// Get template file systems
	if config.TemplatePaths != nil {
		templateFileSystems, err = templates.GetTemplateFileSystem(ctx, config.TemplatePaths)
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
