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
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sources/aws/iam"
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
			return runCheck(cmd.Context(), cmd.OutOrStdout(), flags)
		},
	}
	cmd.Flags().StringVarP(&flags.config, "config", "c", ".sigcomply.yaml", "Path to project config")
	cmd.Flags().BoolVarP(&flags.verbose, "verbose", "v", false, "Verbose logging")
	cmd.Flags().BoolVar(&flags.cloudOn, "cloud", false, "Force cloud submission (requires OIDC)")
	cmd.Flags().BoolVar(&flags.cloudOff, "no-cloud", false, "Disable cloud submission")
	cmd.Flags().StringVar(&flags.cloudURL, "cloud-url", "", "Cloud base URL override (defaults to .sigcomply.yaml cloud.base_url)")
	cmd.Flags().StringVar(&flags.capturePayloadPath, "capture-cloud-payload", "", "Write the cloud SubmissionPayload to this file instead of POSTing it (auditor escape hatch)")
	return cmd
}

func runCheck(ctx context.Context, stdout io.Writer, flags checkFlags) error {
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

// registerProductionSources binds the in-tree plugins declared by
// cfg.Sources to the registry. M6 supports aws.iam (real AWS) and
// manual.pdf (backed by the local filesystem under a configured
// directory). Wider plugin support is the post-M6 plugin-set work.
func registerProductionSources(ctx context.Context, registries *registry.Set, cfg *spec.ProjectConfig, catalog map[string]manual.CatalogEntry) error {
	for id, raw := range cfg.Sources {
		switch id {
		case iam.SourceID:
			region := stringOpt(raw, "region")
			if region == "" {
				region = cfg.Vault.Region
			}
			plugin, err := iam.NewFromAWS(ctx, region)
			if err != nil {
				return fmt.Errorf("aws.iam: %w", err)
			}
			if err := registries.Sources.Register(plugin); err != nil {
				return fmt.Errorf("register aws.iam: %w", err)
			}
		case manual.SourceID:
			reader, scheme, bucket, prefix, err := buildManualReader(raw)
			if err != nil {
				return fmt.Errorf("manual.pdf: %w", err)
			}
			plugin := manual.New(manual.Options{
				Reader:  reader,
				Bucket:  bucket,
				Prefix:  prefix,
				Scheme:  scheme,
				Catalog: catalog,
			})
			if err := registries.Sources.Register(plugin); err != nil {
				return fmt.Errorf("register manual.pdf: %w", err)
			}
		default:
			return fmt.Errorf("source %q is not supported in v1-alpha (see post-M6 plugin-set work)", id)
		}
	}
	return nil
}

// stringOpt reads a string-valued entry from a YAML-unmarshaled map,
// returning "" when missing or the wrong type. The map values come
// from spec.ProjectConfig.Sources which is map[string]any by design.
func stringOpt(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// buildManualReader constructs the Reader backing the manual.pdf
// plugin. M6 ships only a local-filesystem reader; cloud-backed
// readers (S3 / GCS / Azure Blob) are part of the post-M6 plugin
// work, since the manual.pdf reader is a separate concern from the
// general-purpose vault backends.
func buildManualReader(raw map[string]any) (reader manual.Reader, scheme, bucket, prefix string, err error) {
	backend := stringOpt(raw, "backend")
	if backend == "" {
		backend = "local"
	}
	switch backend {
	case "local":
		root := stringOpt(raw, "path")
		if root == "" {
			return nil, "", "", "", fmt.Errorf("manual.pdf.local: path required")
		}
		bucket = stringOpt(raw, "bucket")
		if bucket == "" {
			bucket = root
		}
		prefix = stringOpt(raw, "prefix")
		if prefix == "" {
			prefix = "manual/"
		}
		return &localManualReader{root: root}, "file", bucket, prefix, nil
	default:
		// Cloud-backed manual.pdf readers are part of the post-M6
		// plugin-set work (see docs/architecture/09-implementation-
		// roadmap.md §Post-M6 work plan).
		return nil, "", "", "", fmt.Errorf("manual.pdf backend %q not supported in v1-alpha (use \"local\")", backend)
	}
}

// localManualReader satisfies manual.Reader against a local directory.
type localManualReader struct {
	root string
}

func (r *localManualReader) Get(_ context.Context, uri string) ([]byte, time.Time, error) {
	full := strings.TrimRight(r.root, "/") + "/" + uri
	info, err := os.Stat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, time.Time{}, manual.ErrNotFound
		}
		return nil, time.Time{}, err
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, time.Time{}, err
	}
	return data, info.ModTime().UTC(), nil
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
