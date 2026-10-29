package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sigcomply/sigcomply-cli/internal/frameworks"
	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
)

// defaultFramework is the framework selected when neither a flag nor
// $SIGCOMPLY_FRAMEWORK is set. Defined here (production) so init.go and
// evidence.go share one literal.
const defaultFramework = "soc2"

type initFlags struct {
	framework string
	out       string
	force     bool
}

func newInitCmd() *cobra.Command {
	var flags initFlags
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Scaffold a starter .sigcomply.yaml with sensible defaults",
		Long: "`sigcomply init` writes a ready-to-edit .sigcomply.yaml for the chosen\n" +
			"framework. The generated config runs out of the box: the vault defaults\n" +
			"to a local folder and policies auto-bind to whatever sources you list, so\n" +
			"no bindings: block is needed to get started. Commented sections show how\n" +
			"to add sources, narrow bindings, set cadences, declare exceptions, and\n" +
			"enable cloud submission as you grow.\n",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(cmd.OutOrStdout(), flags)
		},
	}
	cmd.Flags().StringVarP(&flags.framework, "framework", "f", "", "Framework to scaffold for: soc2 | iso27001 (defaults to $SIGCOMPLY_FRAMEWORK, else soc2)")
	cmd.Flags().StringVarP(&flags.out, "out", "o", ".sigcomply.yaml", "Path to write the config to")
	cmd.Flags().BoolVar(&flags.force, "force", false, "Overwrite an existing config file (default: refuse)")
	return cmd
}

func runInit(stdout io.Writer, flags initFlags) error {
	fw := resolveInitFramework(flags.framework)
	if _, ok := frameworks.Lookup(fw); !ok {
		return &exitCodeError{code: orchestrator.ExitConfig,
			err: fmt.Errorf("init: framework %q not supported (registered: %v)", fw, frameworks.IDs())}
	}

	if !flags.force {
		if _, err := os.Stat(flags.out); err == nil {
			return &exitCodeError{code: orchestrator.ExitConfig,
				err: fmt.Errorf("init: refusing to overwrite existing file %q (re-run with --force to override)", flags.out)}
		} else if !os.IsNotExist(err) {
			return &exitCodeError{code: orchestrator.ExitExecution, err: fmt.Errorf("init: stat %q: %w", flags.out, err)}
		}
	}

	if dir := filepath.Dir(flags.out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return &exitCodeError{code: orchestrator.ExitExecution, err: fmt.Errorf("init: mkdir %q: %w", dir, err)}
		}
	}
	if err := os.WriteFile(flags.out, []byte(starterConfig(fw)), 0o600); err != nil {
		return &exitCodeError{code: orchestrator.ExitExecution, err: fmt.Errorf("init: write %q: %w", flags.out, err)}
	}

	// Step 3 is framework-aware because init-ci gates on soc2: telling an
	// ISO 27001 project to run it would send the operator straight into an
	// exit-3 config error one command after we told them to.
	step3 := "  3. Run `sigcomply init-ci --ci github` (or gitlab) to scaffold CI workflows."
	if fw != defaultFramework {
		step3 = "  3. CI scaffolding: `sigcomply init-ci` accepts only --framework soc2, and its\n" +
			"     workflows read the framework from this config, so run\n" +
			"     `sigcomply init-ci --ci github --framework soc2` (or --ci gitlab)."
	}
	nextSteps := "Next steps:\n" +
		"  1. Edit sources: to list the providers you use; credentials come from the\n" +
		"     environment (AWS_* / GITHUB_TOKEN / GCP ADC / OKTA_API_TOKEN).\n" +
		"  2. Run `sigcomply check` locally to see which policies evaluate.\n" +
		step3 + "\n" +
		gitignoreHint(flags.out)
	_, _ = fmt.Fprintf(stdout, "sigcomply init: wrote %s (framework=%s)\n\n", flags.out, fw) //nolint:errcheck // status output
	_, _ = fmt.Fprintln(stdout, nextSteps)                                                   //nolint:errcheck // status output
	return nil
}

// gitignoreHint reminds the user to keep the local vault out of git when
// the project's .gitignore does not already mention it. A local run
// writes hundreds of files there, and `git add .` would commit them.
// init only prints the line: editing a file it did not create is not
// its call.
func gitignoreHint(configPath string) string {
	ignore := filepath.Join(filepath.Dir(configPath), ".gitignore")
	if data, err := os.ReadFile(ignore); err == nil && strings.Contains(string(data), ".sigcomply/") {
		return ""
	}
	return "  Keep the local vault out of git: echo '.sigcomply/vault/' >> .gitignore\n"
}

// resolveInitFramework mirrors the rest of the CLI: explicit flag wins,
// then $SIGCOMPLY_FRAMEWORK, then the soc2 default.
func resolveInitFramework(flag string) string {
	if flag != "" {
		return flag
	}
	if env := os.Getenv("SIGCOMPLY_FRAMEWORK"); env != "" {
		return env
	}
	return defaultFramework
}

// awsSourcesCommented lists, in the order docs/reference/sources.md
// does, every aws.* source the starter config shows commented out. With
// the three active IAM sources it must cover every registered aws.*
// source (TestStarterConfig_ListsEveryAWSSource), so enabling AWS fully
// is a matter of uncommenting lines, not reading the reference.
var awsSourcesCommented = []string{
	"aws.acm", "aws.backup", "aws.cloudtrail", "aws.cloudwatch", "aws.config",
	"aws.dynamodb", "aws.ec2", "aws.ecr", "aws.eks", "aws.guardduty",
	"aws.identity_center", "aws.inspector", "aws.kms", "aws.lambda", "aws.rds",
	"aws.s3", "aws.secretsmanager", "aws.security_alert", "aws.security_group",
	"aws.security_services", "aws.vpc",
}

func commentedAWSSources() string {
	var b strings.Builder
	for _, id := range awsSourcesCommented {
		fmt.Fprintf(&b, "  # %s: { region: us-east-1 }\n", id)
	}
	return b.String()
}

// starterConfig returns the scaffolded .sigcomply.yaml body for fw. It is
// deliberately heavy on comments — the file is the customer's first
// contact with the config surface, and every optional section is shown
// (commented) so growth never requires hunting through docs. The active
// content must parse and validate (see init_test.go).
func starterConfig(fw string) string {
	return `# .sigcomply.yaml — generated by ` + "`sigcomply init`" + `.
# Full reference: https://github.com/SigComply/sigcomply-cli/blob/main/docs/configuration.md
schema_version: project.v1

# Compliance framework to evaluate. Shipped: soc2, iso27001.
framework: ` + fw + `

# ---------------------------------------------------------------------------
# Evidence sources
# ---------------------------------------------------------------------------
# Providers SigComply pulls evidence from. Credentials come from the ambient
# environment (AWS_* / GITHUB_TOKEN / GCP ADC / OKTA_API_TOKEN) — never this
# file. Policies AUTO-BIND to any configured source that emits the evidence
# type they need, so you do NOT need a bindings: block to get started. Replace
# the AWS sources below with the ones you actually use.
#
# AWS has one source per service; all read the same AWS credentials. The
# three active ones cover IAM users, access keys and the password policy.
# Uncomment the rest to cover every AWS service SigComply reads (what each
# one reads and the IAM actions it needs: docs/reference/sources.md#aws).
sources:
  aws.iam:
    region: us-east-1
  aws.iam_access_key:
    region: us-east-1
  aws.password_policy:
    region: us-east-1
` + commentedAWSSources() + `  # github:
  #   org: your-org
  # okta:
  #   org_url: https://your-org.okta.com

  # Manual evidence (a project-level singleton). Many ` + fw + ` controls need
  # documents an API can't produce — access reviews, signed NDAs, security-
  # training certificates, risk-acceptance declarations. Without this source
  # a run that evaluates any of those controls stops with a config error
  # (exit 3); with it they report fail ("evidence not found") until you upload. Drop
  # the files (PDF/JPEG/PNG/GIF/TIFF/WebP/BMP) into
  #     ./evidence/manual/<evidence_catalog_id>/<period_id>/
  # List the catalog IDs with ` + "`sigcomply evidence catalog -f " + fw + "`" + `. The optional
  # Evidence SPA renders only the declaration/checklist entries; export
  # certificates and HR reports are produced outside it. For production,
  # switch backend to s3 / gcs / azure_blob (one bucket per project).
  manual.pdf:
    backend: local
    path: ./evidence

# ---------------------------------------------------------------------------
# Vault — where signed evidence is stored (it never leaves your environment)
# ---------------------------------------------------------------------------
# Omit this whole block to use a local folder. For production switch to
# s3 / gcs / azure_blob, and make the bucket write-once / versioned for real
# tamper-resistance (S3 Object Lock, GCS Bucket Lock, Azure immutable storage).
vault:
  backend: local
  path: ./.sigcomply/vault
  # backend: s3
  # bucket: my-evidence-bucket
  # region: us-east-1
  # prefix: sigcomply/

# ---------------------------------------------------------------------------
# Per-policy customization (uncomment as needed)
# ---------------------------------------------------------------------------
# Everything about one policy lives under policies:<policy-id>. Each field is
# optional; omit the whole block to take framework defaults + auto-binding.
# policies:
#   <policy-id>:
#     # Narrow to specific sources (overrides auto-binding) — only needed when
#     # several sources emit the same evidence type and you want one:
#     bindings:
#       <slot>: [okta]
#     # Tune a parameter the policy declares. Shipped policies declare none,
#     # so this applies to project-local policies only:
#     parameters:
#       <parameter>: <value>
#     # Override the cadence
#     # (continuous|hourly|daily|weekly|monthly|quarterly|annual or every:<dur>):
#     cadence: weekly
#     # Run this policy from manual PDF evidence instead of an API:
#     evidence_mode: manual
#     catalog_entry: <catalog-id>
#     # Declare scoped waivers / not-applicable with an audit trail:
#     exceptions:
#       - state: waived          # waived | na
#         reason: "Compensating control in place"
#         approved_by: security@example.com
#         approved_at: 2026-01-15
#         # scope: { resource_id: "..." }   # omit to waive the whole policy
#
# ---------------------------------------------------------------------------
# Control-level decisions (uncomment as needed)
# ---------------------------------------------------------------------------
# Mark a whole control not-applicable (cascades na to all its policies) — e.g.
# physical-security controls for a cloud-only company:
# controls:
#   <control-id>:
#     applicability: not_applicable
#     reason: "Inherited from cloud provider; SOC 2 report on file."
#     approved_by: ciso@example.com
#
# Send pass/fail counts to SigComply Cloud (paid plan; runs in CI with an
# OIDC token). Nothing is sent unless base_url is set. project_id names the
# project the runs belong to; copy it from
# your project's page on the SigComply dashboard.
# cloud:
#   base_url: https://sigcomply.com
#   project_id: prj_...
#
# ---------------------------------------------------------------------------
# Declare the estate this project covers (uncomment to opt in)
# ---------------------------------------------------------------------------
# Without this, a source you forget to wire is silent: its policies bind
# nothing, get skipped, and drop out of the compliance score — so the
# omission raises your score instead of lowering it. Declaring the estate
# turns that silence into a finding (SCOPE INCOMPLETE, exit 1). Each listed
# source must be configured above, bound by a policy slot, and return at
# least one record.
# experimental:
#   scope:
#     declared_by: ciso@example.com
#     declared_at: "2026-01-15"
#     required_sources:
#       - aws.iam
#       - github
`
}
