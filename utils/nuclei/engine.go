package nuclei

import (
	// Standard
	"context"
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
// Templates are filtered by application protocol (e.g., FTP, SSH, HTTP) when specified
// in the config. Non-fatal errors (e.g. no templates matched) are returned in the warnings slice.
func RunNucleiEngine(ctx context.Context, config nuclei.NucleiConfig) ([]*nuclei.NucleiTargetInfo, []string, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Nuclei Run")

	builder := report.NewBuilder()
	var warnings []string

	if config.TemplatePaths == nil {
		return builder.Final(), warnings, nil
	}

	var protocolFilter string
	if config.Protocol != nil {
		protocolFilter = *config.Protocol
	}

	log.Info("Filtering templates by protocol",
		svc1log.SafeParam("protocol", protocolFilter),
		svc1log.SafeParam("targets", config.Targets))

	templateFS, err := templates.GetTemplateFileSystem(ctx, config.TemplatePaths, protocolFilter)
	if err != nil {
		log.Warn("No templates matched protocol filter",
			svc1log.SafeParam("protocol", protocolFilter),
			svc1log.SafeParam("error", err.Error()))
		warnings = append(warnings, err.Error())
		return builder.Final(), warnings, nil
	}

	runnerConfig := runner.GetRunnerConfig(templateFS, config)
	if _, err := runner.Run(ctx, runnerConfig, builder); err != nil {
		return builder.Final(), warnings, err
	}

	return builder.Final(), warnings, nil
}
