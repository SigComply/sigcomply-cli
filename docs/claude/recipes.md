# Common Task Recipes

> **When to read**: First time doing a common task (adding integrations, policies, frameworks, etc.)

## Adding a New Service Integration (Data Source)

1. Create collector directory in `internal/data_sources/apis/<service>/`
   - Example: `internal/data_sources/apis/github/`
2. Create files following the service-split pattern:
   - `collector.go` - Auth, config, orchestration
   - `repos.go`, `members.go`, etc. - Service-specific collection
3. Implement multi-method authentication:
   - OIDC/Workload Identity (primary)
   - IAM roles (secondary)
   - Environment variables (fallback)
   - Log which auth method is being used
4. Implement `Collect(ctx) ([]evidence.Evidence, error)` method
5. Write unit tests with mocked API client
6. Add policies to relevant frameworks in `internal/compliance_frameworks/<framework>/policies/`
7. Document OIDC setup steps for users
8. Update reusable workflows to support new integration

## Adding a New Automated Compliance Policy

**Design Guideline: Framework-Specific Policies**
Each policy lives within its framework directory. Simplicity and readability over DRY abstraction.

1. Create Rego file in `internal/compliance_frameworks/<framework>/policies/<collector>/<control>_<name>.rego`. Policies are grouped by collector (`aws/`, `gcp/`, `github/`, `multi/`, `manual/`) — pick the one whose evidence the policy reads. Use `multi/` when the policy needs evidence from more than one collector.
   - Example: `internal/compliance_frameworks/soc2/policies/aws/cc6_1_mfa.rego`
   - Example: `internal/compliance_frameworks/soc2/policies/multi/cc6_6_open_ports.rego`
2. Use package naming: `package sigcomply.<framework>.<control>_<name>`
3. Include `metadata` with `id`, `name`, `framework`, `control`, `severity`, `evaluation_mode`, `resource_types`, and **`evidence_type: "automated"`** (required — the engine routes evaluation by this).
4. Define `violations` rule for policy checks
5. Write policy tests in `<policy>_test.rego`
6. Policy automatically embedded via framework's `go:embed` on next build

## Adding a New Manual Evidence Policy

Manual policies check that one or more customer-supplied files exist in the
catalog-resolved folder within the temporal window. The CLI scans the folder
`{prefix}{evidence_id}/{period_id}/` under the project's configured
manual-evidence backend. Any number of files may be placed there; supported
formats are PDF (pass-through), JPEG, PNG, GIF, TIFF, WebP, and BMP — images
are auto-converted to PDF and all files are merged into one before evaluation.
Unsupported extensions (e.g. `.docx`) surface as `unsupported_file_type`
failures so CI operators see an actionable error. The CLI does not read or
parse PDF contents — only presence, format validity, and upload timestamp matter.

1. **Add a catalog entry** in `internal/core/manual/catalogs/<framework>.yaml`:
   ```yaml
   - id: employee_nda
     control: CC1.1
     type: declaration              # descriptive hint only — CLI ignores this
     frequency: yearly
     temporal_rule: anytime         # or 'retrospective'
     grace_period: "30d"
     name: Employee NDA Acknowledgment
     description: Each employee acknowledges the NDA on hire and annually
     severity: high
     declaration_text: "I confirm…"  # descriptive hint
   ```
   `type`, `items`, `declaration_text`, and `accepted_formats` are descriptive hints — the CLI never branches on them. The optional Evidence SPA helper uses them to render a clickable form for declaration- and checklist-style entries; for evidence sourced externally (training certs, HR exports, scanned docs) the user produces the file themselves and the hints are ignored.

   The `filename` field (if present in older entries) is kept for display
   purposes only — the collector ignores it and scans the whole folder.
   There is no `path_template` override; the folder scheme
   `{prefix}{evidence_id}/{period_id}/` is canonical and fixed.

2. **Create the Rego policy** in `internal/compliance_frameworks/<framework>/policies/manual/<id>.rego`:
   ```rego
   package sigcomply.soc2.cc1_1_employee_nda

   import data.sigcomply.lib.manual

   metadata := {
       "id":              "soc2-cc1.1-employee-nda",
       "name":            "Employee NDA Acknowledgment",
       "framework":       "soc2",
       "control":         "CC1.1",
       "severity":        "high",
       "evaluation_mode": "individual",
       "resource_types":  ["manual:employee_nda"],
       "evidence_type":   "manual",
   }

   violations contains v if {
       input.resource_type == "manual:employee_nda"
       v := manual.presence_violation(input)
   }
   ```
   The `manual:` prefix on the resource type and the `evidence_type: "manual"` metadata key both tell the engine this is a manual policy.

3. **Write the test** at `<id>_test.rego` covering three cases: overdue+not_uploaded (→ one violation), uploaded+within_window (→ no violations), and wrong-resource-type (→ no violations).

4. The CLI's manual plugin (`internal/sources/manual/manual.go`) automatically picks up new catalog entries — no further wiring needed.

## Adding a New Compliance Framework

1. Create framework directory: `internal/compliance_frameworks/<framework>/`
2. Create `framework.go` implementing the `engine.Framework` interface (and `engine.ManualEvidenceProvider` if the framework supports manual evidence). Call `engine.RegisterFramework(New())` in an `init()` so the framework auto-registers when its package is imported.
3. Create `controls.go` with control hierarchy and mappings
4. Create `policies/<collector>/` subdirectories with at least one policy each (matches the SOC 2 / ISO 27001 layout)
5. Add `<framework>` to `SupportedFrameworks` in `internal/core/config/config.go`
6. (Optional) Add a manual catalog at `internal/core/manual/catalogs/<framework>.yaml`
7. Update README + docs/configuration.md framework lists

## Adding a New Storage Backend

1. Implement storage interface in `internal/core/storage/<backend>/`
2. Add configuration options
3. Write integration tests
4. Update storage documentation

**Required storage layout**: Any new backend must write evidence using the policy-first folder structure:

```
{framework}/{policy_id}/{timestamp}_{run_id_8chars}/
├── evidence/
│   └── {collector}-{resource_type}.json   # EvidenceEnvelope (self-contained, signed)
├── manual_attachments/{evidence_id}/merged.pdf      # only for manual policies (merged PDF of all source files)
└── result.json                             # StoredPolicyResult (full violations)
```

Where `timestamp` uses ISO 8601 basic format with no colons (e.g., `20260325T100000Z`) and `run_id_8chars` is the first 8 characters of the run UUID. See `ARCHITECTURE.md` Storage Layout for the full spec.

## Creating CI/CD Reusable Workflows

### GitHub Actions Workflow (`.github/workflows/compliance.yml`)

- Define reusable workflow with `workflow_call` trigger
- Add inputs for framework selection, custom policies, etc.
- Include OIDC token permissions (`id-token: write`)
- Install CLI binary
- Run compliance checks with proper error handling
- Output results and artifact attestations

### GitLab CI Component (`.gitlab/components/compliance.yml`)

- Define component with `spec:inputs` for parameters
- Use GitLab's built-in OIDC token (`$CI_JOB_JWT_V2`)
- Install CLI and execute checks
- Handle exit codes for pipeline pass/fail

### init-ci Command (Planned, Not Yet Wired)

When `sigcomply init-ci` is implemented, it should:

- Detect CI/CD platform (check for `$GITHUB_ACTIONS` or `$GITLAB_CI`)
- Generate minimal caller YAML in correct location
- Validate required secrets are configured
- Provide copy-paste setup instructions

The command isn't registered in `cmd/sigcomply/root.go` yet — see the
"Remaining" list in `CLAUDE.md` for the full set of unwired commands.
