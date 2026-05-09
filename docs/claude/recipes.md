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

1. Create Rego file in `internal/compliance_frameworks/<framework>/policies/<control>_<name>.rego`
   - Example: `internal/compliance_frameworks/soc2/policies/cc6_1_mfa.rego`
   - Example: `internal/compliance_frameworks/hipaa/policies/164_312_access.rego`
2. Use package naming: `package sigcomply.<framework>.<control>`
3. Include `metadata` with `id`, `name`, `framework`, `control`, `severity`, `evaluation_mode`, `resource_types`, and **`evidence_type: "automated"`** (required — the engine routes evaluation by this).
4. Define `violations` rule for policy checks
5. Write policy tests in `<policy>_test.rego`
6. Policy automatically embedded via framework's `go:embed` on next build

## Adding a New Manual Evidence Policy

Manual policies check that a customer-supplied PDF exists within the temporal
window. By default the CLI looks at `{framework}/{evidence_id}/{period}/evidence.pdf`
under the framework's configured manual-evidence backend, but a catalog entry
can override the path via `path_template` and `filename`. The CLI does not
read or parse the PDF in v1 — only its presence and hash matter. Future PDF
text-extraction policies layer on top of the presence check.

1. **Add a catalog entry** in `internal/core/manual/catalogs/<framework>.yaml`:
   ```yaml
   - id: employee_nda
     control: CC1.1
     type: declaration              # SPA-rendering hint only — CLI ignores this
     frequency: yearly
     temporal_rule: anytime         # or 'retrospective'
     grace_period: "30d"
     name: Employee NDA Acknowledgment
     description: Each employee acknowledges the NDA on hire and annually
     severity: high
     declaration_text: "I confirm…"  # SPA-rendering hint
   ```
   Render hints (`type`, `items`, `declaration_text`, `accepted_formats`) tell the SPA whether and how to render a clickable form. The CLI never branches on them.

   **Optional path override.** For evidence stored under a different layout (e.g.
   one shared annual training cert filed by year, not by framework):
   ```yaml
   - id: security_awareness_training
     control: CC1.4
     frequency: yearly
     grace_period: "30d"
     name: Annual Security Awareness Training
     description: All staff complete annual security awareness training
     severity: medium
     # Looks up:  shared/security_awareness_training/2026/training-cert.pdf
     path_template: "shared/{evidence_id}/{year}/{filename}"
     filename: training-cert.pdf
   ```
   Supported placeholders: `{framework}`, `{evidence_id}`, `{period}`, `{year}`,
   `{quarter}` (quarterly only), `{month}` (monthly/daily only), `{day}` (daily
   only), `{filename}`. The resolver rejects `..`, leading `/`, and non-PDF
   endings.

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

4. The CLI's manual reader (`internal/data_sources/manual/reader.go`) automatically picks up new catalog entries — no further wiring needed.

## Adding a New Compliance Framework

1. Create framework directory: `internal/compliance_frameworks/<framework>/`
2. Create `framework.go` implementing the Framework interface
3. Create `controls.go` with control hierarchy and mappings
4. Create `policies/` directory with at least one policy
5. Register framework in `internal/compliance_frameworks/engine/registry.go`
6. Add framework to CLI `--framework` flag options
7. Add documentation

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
└── result.json                             # PolicyRunResult (full violations)
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

### init-ci Command Implementation

- Detect CI/CD platform (check for `$GITHUB_ACTIONS` or `$GITLAB_CI`)
- Generate minimal caller YAML in correct location
- Validate required secrets are configured
- Provide copy-paste setup instructions
