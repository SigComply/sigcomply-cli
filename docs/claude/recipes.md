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

## Adding a New Compliance Policy

**Design Guideline: Framework-Specific Policies**
Each policy lives within its framework directory. Simplicity and readability over DRY abstraction.

1. Create Rego file in `internal/compliance_frameworks/<framework>/policies/<control>_<name>.rego`
   - Example: `internal/compliance_frameworks/soc2/policies/cc6_1_mfa.rego`
   - Example: `internal/compliance_frameworks/hipaa/policies/164_312_access.rego`
2. Use package naming: `package tracevault.<framework>.<control>`
3. Include metadata with id, name, framework, control, severity
4. Define `violations` rule for policy checks
5. Write policy tests in `<policy>_test.rego`
6. Policy automatically embedded via framework's `go:embed` on next build

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
