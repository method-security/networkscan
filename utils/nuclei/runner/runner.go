package nuclei

import (
	// Standard
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	// Generated
	nuclei "github.com/Method-Security/networkscan/generated/go/common/nuclei"
	// Utils
	report "github.com/Method-Security/networkscan/utils/nuclei/report"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
	useragent "github.com/projectdiscovery/useragent"
)

type Config struct {
	Targets         []string
	TemplateFS      []fs.FS // template sources
	Threads         int
	SuccessfulOnly  *bool
	VerboseLogs     bool
	Timeout         int
	GlobalRateLimit int
}

func validateConfig(cfg Config) error {
	if len(cfg.Targets) == 0 {
		return fmt.Errorf("runner: no Targets provided")
	}
	if cfg.Threads <= 0 {
		cfg.Threads = 25
	}
	return nil
}

func copyFilesToTmpDirs(cfg Config) (templateDir string, err error) {
	// Create template directory
	templateDir, err = os.MkdirTemp("", "networkscan-tpl-*")
	if err != nil {
		return "", err
	}

	// Copy templates. Preserve the relative path from each source filesystem
	// under a per-source subdirectory so nested layouts retain their structure
	// and identical basenames from different sources do not overwrite each
	// other.
	for i, src := range cfg.TemplateFS {
		srcDir := filepath.Join(templateDir, fmt.Sprintf("src-%d", i))
		if walkErr := fs.WalkDir(src, ".", func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			ext := filepath.Ext(p)
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}
			data, err := fs.ReadFile(src, p)
			if err != nil {
				return err
			}
			dst := filepath.Join(srcDir, p)
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			return os.WriteFile(dst, data, 0o600)
		}); walkErr != nil {
			// Surface walk/copy failures so callers don't operate on an empty
			// or partial template tree as if it were complete.  Best-effort
			// cleanup of the half-populated temp dir before returning.
			_ = os.RemoveAll(templateDir)
			return "", fmt.Errorf("copy templates from source %d: %w", i, walkErr)
		}
	}

	return templateDir, nil
}

func buildNucleiOptions(cfg Config, templateDir string) []nucleilib.NucleiSDKOptions {
	templateSources := nucleilib.TemplateSources{}

	// Only add template directory if it has content
	if len(cfg.TemplateFS) > 0 {
		templateSources.Templates = []string{templateDir}
	}

	opts := []nucleilib.NucleiSDKOptions{
		nucleilib.WithTemplatesOrWorkflows(templateSources),
		nucleilib.EnableSelfContainedTemplates(),
		nucleilib.DisableUpdateCheck(),
		nucleilib.WithNetworkConfig(nucleilib.NetworkConfig{
			Timeout: cfg.Timeout,
		}),
		nucleilib.WithConcurrency(nucleilib.Concurrency{
			HostConcurrency:               cfg.Threads,
			TemplateConcurrency:           cfg.Threads,
			TemplatePayloadConcurrency:    cfg.Threads,
			JavascriptTemplateConcurrency: cfg.Threads,
			ProbeConcurrency:              cfg.Threads,
			HeadlessHostConcurrency:       cfg.Threads,
			HeadlessTemplateConcurrency:   cfg.Threads,
		}),

		// Set global rate limit if specified (0 means use default nuclei rate limit)
		func() nucleilib.NucleiSDKOptions {
			if cfg.GlobalRateLimit > 0 {
				return nucleilib.WithGlobalRateLimit(cfg.GlobalRateLimit, time.Second)
			}
			return func(*nucleilib.NucleiEngine) error { return nil } // no-op, use default
		}(),

		// Explicitly set StopAtFirstMatch to false to ensure we get all requests
		func(e *nucleilib.NucleiEngine) error {
			e.Options().StopAtFirstMatch = false
			// Add timeout configuration
			e.Options().Timeout = cfg.Timeout
			return nil
		},
	}

	// Add verbose logs if enabled
	if cfg.VerboseLogs {
		opts = append(opts, nucleilib.WithVerbosity(nucleilib.VerbosityOptions{Silent: false, Debug: true, Verbose: true}))
	}

	// Add random user agent
	randomUserAgent := useragent.PickRandom()
	opts = append(opts, nucleilib.WithHeaders([]string{fmt.Sprintf("User-Agent:%s", randomUserAgent.Raw)}))

	return opts
}

func loadTargets(eng *nucleilib.NucleiEngine, cfg Config) error {
	// Network scan mode: load targets by URL
	eng.LoadTargets(cfg.Targets, false)
	return nil
}

// GetRunnerConfig returns a runner config from a nuclei config.
func GetRunnerConfig(templateFileSystems []fs.FS, config nuclei.NucleiConfig) Config {
	rconfig := Config{
		Targets:         config.Targets,
		TemplateFS:      templateFileSystems,
		Threads:         config.Threads,
		VerboseLogs:     config.VerboseLogs,
		Timeout:         config.Timeout,
		GlobalRateLimit: config.GlobalRateLimit,
	}
	return rconfig
}

func Run(ctx context.Context, cfg Config, reportBuilder *report.Builder) ([]*nuclei.NucleiTargetInfo, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Validating config")
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	// Add a maximum execution timeout for the entire scan to prevent hanging
	maxScanTime := time.Duration(cfg.Timeout*20) * time.Second // 20x timeout for total scan time
	scanCtx, cancel := context.WithTimeout(ctx, maxScanTime)
	defer cancel()

	log.Info("Scan will timeout after", svc1log.SafeParam("maxScanTime", maxScanTime))

	log.Info("Copying templates and workflows to tmp dirs")
	templateDir, err := copyFilesToTmpDirs(cfg)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = os.RemoveAll(templateDir)
	}()

	log.Info("Building Nuclei options")
	opts := buildNucleiOptions(cfg, templateDir)

	log.Info("Creating Nuclei engine")
	eng, err := nucleilib.NewNucleiEngineCtx(scanCtx, opts...)
	if err != nil {
		return nil, err
	}
	defer eng.Close()

	eng.Options().MatcherStatus = false
	log.Info("Set matcher status", svc1log.SafeParam("status", eng.Options().MatcherStatus))

	log.Info("Loading targets")
	if err := loadTargets(eng, cfg); err != nil {
		return nil, err
	}

	log.Info("Populating probes")
	if err := reportBuilder.PopulateProbes(eng); err != nil {
		return nil, err
	}

	log.Info("Executing Nuclei engine")
	if err := eng.ExecuteCallbackWithCtx(scanCtx, reportBuilder.Consume); err != nil {
		return nil, err
	}

	log.Info("Returning report")
	return reportBuilder.Final(), nil
}
