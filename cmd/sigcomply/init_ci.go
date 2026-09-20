package cmd

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sigcomply/sigcomply-cli/internal/frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
)

// templatesFS holds the workflow templates shipped with the CLI. They
// are static YAML (no Go template substitution today) — `init-ci`
// writes them verbatim and the customer fills in the placeholders
// (`AWS_ROLE_ARN`, `SIGCOMPLY_VERSION`, etc.).
//
//go:embed templates/github/*.yml templates/gitlab/.gitlab-ci.yml
var templatesFS embed.FS

// CI provider identifiers accepted by --ci.
const (
	ciGitHub = "github"
	ciGitLab = "gitlab"
)

// supportedCIs is the canonical list. Kept in sync with templatesFS;
// the post-M6 work plan calls out that other providers are v1.x.
var supportedCIs = []string{ciGitHub, ciGitLab}

// frameworkSupported reports whether init-ci will scaffold for the
// framework. Today that is soc2 only — but NOT because the templates are
// framework-specific. They are not: nothing under templates/ mentions a
// framework, `check` has no --framework flag (it reads the framework from
// config), and both shipped frameworks use the same three cadences, so
// the emitted files would be byte-identical and correct for ISO 27001.
// The gate is v1-alpha conservatism about a set that has only ever been
// exercised against soc2. Lifting it is a one-line change here plus the
// ~10 docs that currently state the limit.
func frameworkSupported(framework string) bool {
	return framework == soc2.FrameworkID
}

type initCIFlags struct {
	framework string
	ci        string
	outDir    string
	force     bool
	config    string
}

func newInitCICmd() *cobra.Command {
	var flags initCIFlags
	cmd := &cobra.Command{
		Use:   "init-ci",
		Short: "Scaffold the per-cadence CI workflow set (github | gitlab)",
		Long: "`sigcomply init-ci` writes the canonical workflow set for the chosen CI provider:\n" +
			"  - GitHub Actions: one workflow per cadence under .github/workflows/.\n" +
			"  - GitLab CI: a single .gitlab-ci.yml with cadence-keyed jobs driven by\n" +
			"    pipeline schedules ($CADENCE).\n" +
			"\n" +
			"The scaffolded files are starter templates. Customize cron times, runner\n" +
			"types, and placeholder values (AWS_ROLE_ARN, SIGCOMPLY_VERSION) to suit.\n",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInitCI(cmd.OutOrStdout(), flags)
		},
	}
	cmd.Flags().StringVar(&flags.framework, "framework", "", "Framework to scaffold for: soc2 only in v1-alpha (defaults to .sigcomply.yaml framework, else soc2)")
	cmd.Flags().StringVar(&flags.ci, "ci", "", "CI provider: github | gitlab (required)")
	cmd.Flags().StringVar(&flags.outDir, "out", "", "Output directory (defaults to .github/workflows/ for github, repo root for gitlab)")
	cmd.Flags().BoolVar(&flags.force, "force", false, "Overwrite existing files (default: refuse if any target file exists)")
	cmd.Flags().StringVarP(&flags.config, "config", "c", ".sigcomply.yaml", "Path to project config (used to default --framework)")
	// --ci is required, but we validate it in runInitCI (via validateCI)
	// rather than cmd.MarkFlagRequired so a missing flag returns exit 3
	// (configuration error) per the exit-code taxonomy, not cobra's
	// default exit 2.
	return cmd
}

func runInitCI(stdout io.Writer, flags initCIFlags) error {
	if err := validateCI(flags.ci); err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}
	framework := resolveInitCIFramework(flags)
	if !frameworkSupported(framework) {
		return &exitCodeError{code: orchestrator.ExitConfig,
			err: fmt.Errorf("init-ci: framework %q not scaffolded in v1-alpha "+
				"(the shipped cadence templates are validated against soc2 only; "+
				"copy one from examples/ and adapt it — see docs/guides/ci-github.md)", framework)}
	}
	plan, err := scaffoldPlan(flags.ci, flags.outDir)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitConfig, err: err}
	}
	if !flags.force {
		if conflict, err := firstConflict(plan); err != nil {
			return &exitCodeError{code: orchestrator.ExitExecution, err: err}
		} else if conflict != "" {
			return &exitCodeError{code: orchestrator.ExitConfig,
				err: fmt.Errorf("init-ci: refusing to overwrite existing file %q (re-run with --force to override)", conflict)}
		}
	}
	written, err := writeScaffold(plan)
	if err != nil {
		return &exitCodeError{code: orchestrator.ExitExecution, err: err}
	}
	printSummary(stdout, framework, flags.ci, written)
	return nil
}

func validateCI(ci string) error {
	if ci == "" {
		return fmt.Errorf("init-ci: --ci is required (one of %s)", strings.Join(supportedCIs, ", "))
	}
	for _, ok := range supportedCIs {
		if ci == ok {
			return nil
		}
	}
	return fmt.Errorf("init-ci: --ci %q is not one of %s", ci, strings.Join(supportedCIs, ", "))
}

// resolveInitCIFramework reads the flag if set, else peeks at the
// project config, else falls back to soc2. The peek is intentionally
// best-effort — init-ci can run in an empty repo before a config
// exists, so a missing or unparseable config is not an error here.
func resolveInitCIFramework(flags initCIFlags) string {
	if flags.framework != "" {
		return flags.framework
	}
	if data, err := os.ReadFile(flags.config); err == nil {
		if fw := scanFrameworkLine(string(data)); fw != "" {
			return fw
		}
	}
	return soc2.FrameworkID
}

// scanFrameworkLine extracts the top-level `framework:` value from the
// raw YAML without parsing the full schema. init-ci needs only this
// one field; pulling in the spec loader would couple init-ci to the
// rest of the orchestrator's validation rules (which would refuse a
// config that's still being scaffolded).
func scanFrameworkLine(body string) string {
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "framework:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(line, "framework:"))
		v = strings.Trim(v, `"'`)
		if v != "" {
			return v
		}
	}
	return ""
}

// scaffoldFile is one source → destination mapping in the scaffold.
type scaffoldFile struct {
	embeddedPath string // path inside templatesFS
	relDest      string // path written to disk, relative to the repo root
	outPath      string // absolute path the file lands at
}

func scaffoldPlan(ci, outDir string) ([]scaffoldFile, error) {
	switch ci {
	case ciGitHub:
		return scaffoldPlanGitHub(outDir)
	case ciGitLab:
		return scaffoldPlanGitLab(outDir)
	default:
		// Already validated upstream; defensive.
		return nil, fmt.Errorf("init-ci: unknown ci %q", ci)
	}
}

func scaffoldPlanGitHub(outDir string) ([]scaffoldFile, error) {
	// Default: write into .github/workflows/ relative to cwd. If the
	// caller already pointed --out at a workflows dir, respect it.
	base := outDir
	if base == "" {
		base = filepath.Join(".github", "workflows")
	}
	entries, err := fs.ReadDir(templatesFS, "templates/github")
	if err != nil {
		return nil, fmt.Errorf("init-ci: read embedded github templates: %w", err)
	}
	plan := make([]scaffoldFile, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		plan = append(plan, scaffoldFile{
			embeddedPath: "templates/github/" + e.Name(),
			relDest:      filepath.Join(base, e.Name()),
			outPath:      filepath.Join(base, e.Name()),
		})
	}
	sort.Slice(plan, func(i, j int) bool { return plan[i].embeddedPath < plan[j].embeddedPath })
	return plan, nil
}

func scaffoldPlanGitLab(outDir string) ([]scaffoldFile, error) {
	base := outDir
	if base == "" {
		base = "."
	}
	return []scaffoldFile{{
		embeddedPath: "templates/gitlab/.gitlab-ci.yml",
		relDest:      filepath.Join(base, ".gitlab-ci.yml"),
		outPath:      filepath.Join(base, ".gitlab-ci.yml"),
	}}, nil
}

func firstConflict(plan []scaffoldFile) (string, error) {
	for _, f := range plan {
		_, err := os.Stat(f.outPath)
		if err == nil {
			return f.outPath, nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("init-ci: stat %q: %w", f.outPath, err)
		}
	}
	return "", nil
}

func writeScaffold(plan []scaffoldFile) ([]string, error) {
	written := make([]string, 0, len(plan))
	for _, f := range plan {
		body, err := fs.ReadFile(templatesFS, f.embeddedPath)
		if err != nil {
			return nil, fmt.Errorf("init-ci: read embedded %q: %w", f.embeddedPath, err)
		}
		if err := os.MkdirAll(filepath.Dir(f.outPath), 0o750); err != nil {
			return nil, fmt.Errorf("init-ci: mkdir %q: %w", filepath.Dir(f.outPath), err)
		}
		if err := os.WriteFile(f.outPath, body, 0o600); err != nil {
			return nil, fmt.Errorf("init-ci: write %q: %w", f.outPath, err)
		}
		written = append(written, f.outPath)
	}
	return written, nil
}

func printSummary(stdout io.Writer, framework, ci string, written []string) {
	var b strings.Builder
	fmt.Fprintf(&b, "sigcomply init-ci: scaffolded %d file(s) for framework=%q ci=%q\n", len(written), framework, ci)
	for _, p := range written {
		fmt.Fprintf(&b, "  wrote %s\n", p)
	}
	b.WriteString("\nNext steps:\n")
	b.WriteString("  1. Replace AWS_ROLE_ARN placeholders with the IAM role you've configured\n")
	b.WriteString("     for OIDC role assumption (aud: https://api.sigcomply.com).\n")
	b.WriteString("  2. SIGCOMPLY_VERSION is pinned to a tagged release; bump it to adopt a\n")
	b.WriteString("     newer version (or set it to \"latest\" to always track the newest).\n")
	switch ci {
	case ciGitLab:
		b.WriteString("  3. Create one GitLab pipeline schedule per cadence (daily, weekly,\n")
		b.WriteString("     monthly, quarterly, annual) and set the CADENCE variable accordingly.\n")
	case ciGitHub:
		b.WriteString("  3. Commit the workflow files; cron schedules will fire automatically.\n")
	}
	_, _ = stdout.Write([]byte(b.String())) //nolint:errcheck // status output; nothing useful to do on failure
}
