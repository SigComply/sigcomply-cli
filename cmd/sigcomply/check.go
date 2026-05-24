package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sigcomply/sigcomply-cli/internal/frameworks/iso27001"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/builtin" // side-effect: registers every in-tree source factory
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/submitter"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
)

type checkFlags struct {
	config             string
	verbose            bool
	cloudOn            bool
	cloudOff           bool
	cloudURL           string
	capturePayloadPath string
	cadence            string
	onPush             bool
}

func newCheckCmd() *cobra.Command {
	var flags checkFlags
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Collect evidence, evaluate policies, and submit aggregated counts",
		Long: "`sigcomply check` runs the full pipeline:\n" +
			"  1. Plan policies for the selected framework and current period.\n" +
			"  2. Collect evidence from bound source plugins.\n" +
			"  3. Evaluate each policy's rule.\n" +
			"  4. Persist signed envelopes + per-policy results + run manifest to the vault.\n" +
			"  5. Optionally submit aggregated counts to the configured cloud endpoint.\n",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCheck(cmd.Context(), cmd.OutOrStdout(), &flags)
		},
	}
	cmd.Flags().StringVarP(&flags.config, "config", "c", ".sigcomply.yaml", "Path to project config")
	cmd.Flags().BoolVarP(&flags.verbose, "verbose", "v", false, "Verbose logging")
	cmd.Flags().BoolVar(&flags.cloudOn, "cloud", false, "Force cloud submission (requires OIDC)")
	cmd.Flags().BoolVar(&flags.cloudOff, "no-cloud", false, "Disable cloud submission")
	cmd.Flags().StringVar(&flags.cloudURL, "cloud-url", "", "Cloud base URL override (defaults to .sigcomply.yaml cloud.base_url)")
	cmd.Flags().StringVar(&flags.capturePayloadPath, "capture-cloud-payload", "", "Write the cloud SubmissionPayload to this file instead of POSTing it (auditor escape hatch)")
	cmd.Flags().StringVar(&flags.cadence, "cadence", "", "Only evaluate policies whose effective cadence matches (continuous|hourly|daily|weekly|monthly|quarterly|annual)")
	cmd.Flags().BoolVar(&flags.onPush, "on-push", false, "Only evaluate policies whose on_push attribute is true (mutually exclusive with --cadence)")
	cmd.MarkFlagsMutuallyExclusive("cadence", "on-push")
	return cmd
}

func runCheck(ctx context.Context, stdout io.Writer, flags *checkFlags) error {
	cfg, registries, err := orchestrator.Bootstrap(flags.config)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}
	logger := log.New(os.Stderr, flags.verbose)

	var manualCatalog map[string]manual.CatalogEntry
	switch cfg.Framework {
	case soc2.FrameworkID:
		if err := soc2.Register(registries); err != nil {
			return &exitCodeError{code: orchestrator.ExitConfig, err: fmt.Errorf("register soc2: %w", err)}
		}
		manualCatalog = soc2.ManualCatalog()
	case iso27001.FrameworkID:
		if err := iso27001.Register(registries); err != nil {
			return &exitCodeError{code: orchestrator.ExitConfig, err: fmt.Errorf("register iso27001: %w", err)}
		}
		manualCatalog = iso27001.ManualCatalog()
	default:
		return &exitCodeError{code: orchestrator.ExitConfig,
			err: fmt.Errorf("framework %q not supported in v1-alpha (only soc2, iso27001)", cfg.Framework)}
	}

	if err := registerProductionSources(ctx, registries, cfg, manualCatalog); err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}

	v, err := vault.FromConfig(ctx, &cfg.Vault)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: fmt.Errorf("vault: %w", err)}
	}

	cloudBase := cfg.Cloud.BaseURL
	if flags.cloudURL != "" {
		cloudBase = flags.cloudURL
	}

	commitSHA, commitTime := gitContext(ctx, logger)
	res, err := orchestrator.Run(ctx, &orchestrator.Options{
		Config:             cfg,
		Registries:         registries,
		Vault:              v,
		CLIVersion:         cliVersion,
		CommitSHA:          commitSHA,
		CommitTime:         commitTime,
		Branch:             detectBranch(),
		Stdout:             stdout,
		Logger:             logger,
		ForceCloud:         flags.cloudOn,
		DisableCloud:       flags.cloudOff,
		CapturePayloadPath: flags.capturePayloadPath,
		Filter: planner.Filter{
			Cadence: flags.cadence,
			OnPush:  flags.onPush,
		},
		SubmitterOpts: submitter.Options{
			BaseURL:    cloudBase,
			Force:      flags.cloudOn,
			Disable:    flags.cloudOff,
			CLIVersion: cliVersion,
		},
	})
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitExecution, err: err}
	}
	if res.ExitCode != orchestrator.ExitOK {
		return &exitCodeError{code: res.ExitCode}
	}
	return nil
}

// registerProductionSources iterates cfg.Sources and dispatches each
// entry through the process-global sources.RegisterFactory registry
// (populated by package init() of every in-tree plugin and any
// project-local plugin compiled in via `sigcomply build`). The check
// command has no per-source knowledge — adding a new source is a
// matter of dropping a package under internal/sources/<id>/ (or
// .sigcomply/plugins/<id>/) with an init() that calls
// sources.RegisterFactory.
//
// See docs/architecture/04-source-plugins.md §The factory contract.
func registerProductionSources(ctx context.Context, registries *registry.Set, cfg *spec.ProjectConfig, catalog map[string]manual.CatalogEntry) error {
	extras := map[string]any{
		manual.FrameworkCatalogKey: catalog,
	}
	for id, raw := range cfg.Sources {
		env := sources.Env{
			Config:          withRegionDefault(raw, cfg.Vault.Region),
			FrameworkExtras: extras,
		}
		plugin, err := sources.Build(ctx, id, env)
		if err != nil {
			return fmt.Errorf("source %q: %w", id, err)
		}
		if err := registries.Sources.Register(plugin); err != nil {
			return fmt.Errorf("register source %q: %w", id, err)
		}
	}
	return nil
}

// withRegionDefault preserves the legacy convenience that AWS source
// plugins fall back to the vault's region when their own config omits
// it. Other sources ignore the region key.
func withRegionDefault(raw map[string]any, vaultRegion string) map[string]any {
	if vaultRegion == "" {
		return raw
	}
	if _, hasRegion := raw["region"]; hasRegion {
		return raw
	}
	out := make(map[string]any, len(raw)+1)
	for k, v := range raw {
		out[k] = v
	}
	out["region"] = vaultRegion
	return out
}

func detectBranch() string {
	for _, env := range []string{"GITHUB_REF_NAME", "CI_COMMIT_REF_NAME", "GIT_BRANCH"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return ""
}

// gitContext returns the head commit SHA and time, falling back to
// environment variables (CI provides them) before invoking git. A
// missing git context is non-fatal — the run proceeds with zeroed
// values.
func gitContext(ctx context.Context, logger *log.Logger) (string, time.Time) {
	sha := os.Getenv("GITHUB_SHA")
	if sha == "" {
		sha = os.Getenv("CI_COMMIT_SHA")
	}
	if sha == "" {
		out, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
		if err == nil {
			sha = strings.TrimSpace(string(out))
		}
	}
	timeStr := os.Getenv("GITHUB_EVENT_HEAD_COMMIT_TIMESTAMP")
	if timeStr == "" {
		out, err := exec.CommandContext(ctx, "git", "show", "-s", "--format=%cI", "HEAD").Output()
		if err == nil {
			timeStr = strings.TrimSpace(string(out))
		}
	}
	commitTime := time.Now().UTC()
	if timeStr != "" {
		if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
			commitTime = t
		} else {
			logger.Debugf("git: parse commit time: %s", err.Error())
		}
	}
	return sha, commitTime
}
