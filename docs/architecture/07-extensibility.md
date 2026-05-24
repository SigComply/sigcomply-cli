# 07 — Extensibility

The CLI ships with curated frameworks, policies, rules, and source
plugins. Customers extend the system *project-locally* under
`.sigcomply/` — their own policies, their own plugins, their own
evidence types — without forking the CLI repo.

This document specifies what can be customized, how to author each
artifact, the compilation/loading mechanism, and the path from a
project-local extension to an upstream contribution.

> **Status**: project-local Go extensions (custom policies with Go
> rules, custom source plugins) and project-local evidence types both
> require `sigcomply build` — roadmap milestone **M16**. The in-tree
> patterns (self-registering factories, embedded schema loading) are
> wired and used today; the project-local discovery and build-wrapper
> pieces are planned. Read this doc as the target design.

---

## What can be customized

| Artifact | Project-local | In-tree (upstream) |
|---|---|---|
| Framework spec | ❌ (frameworks are curated) | ✅ |
| Policy | ✅ under `.sigcomply/policies/` | ✅ in `internal/compliance_frameworks/<fw>/policies/` |
| Rule | ✅ as `rule.rego` or `rule.go` inside a custom policy dir | ✅ inside a shipped policy dir |
| Source plugin | ✅ under `.sigcomply/plugins/` (registered via `init()` factory; compiled in by `sigcomply build`) | ✅ in `internal/sources/` (same self-registration pattern) |
| Evidence type | ✅ under `.sigcomply/evidence_types/<id>.v<n>.json` (planned — M16) | ✅ in `internal/evidence_types/schemas/<id>.v<n>.json`, embedded via `go:embed` (see [`04a`](04a-evidence-type-registry.md)) |
| Manual catalog entries | ✅ under `.sigcomply/manual_catalog/` | ✅ in shipped framework's catalog |
| Project config (`.sigcomply.yaml`) | ✅ | n/a |
| Aggregation contract | ❌ (frozen schema) | ✅ (requires bump + security review) |

The pattern: **framework specs, evidence type schemas, and the
aggregation contract are curated by SigComply; everything else can be
authored project-locally and contributed back upstream.**

Reason: an auditor relying on SigComply needs to trust that the SOC 2
framework spec they're being measured against is the canonical one,
not a customer-tweaked variant. Customers extend by *adding*
(custom policies, custom plugins), not by *replacing* curated
artifacts.

---

## Project-local layout

```
<repo root>/
  .sigcomply.yaml                         # project config
  .sigcomply/
    policies/
      acme.custom.cc6.1.contractor_review/
        policy.yaml
        rule.rego                          # or rule.go
        tests/
          passes_when_signed.yaml
          fails_when_missing.yaml
        README.md
    plugins/
      acme.internal_iam/
        plugin.yaml
        plugin.go                          # required
        plugin_test.go
        README.md
    evidence_types/
      acme_principal.v1.json               # JSON Schema document
    manual_catalog/
      contractor_review.yaml
```

The CLI discovers everything under `.sigcomply/` at startup and merges
it into the registries (L2) alongside in-binary artifacts.

---

## `.sigcomply/` is the only extension surface

Three things and only three things make a customer extension visible
to the CLI:

| What | Where | When it's compiled in |
|---|---|---|
| **Policy** (Rego or Go rule + spec) | `.sigcomply/policies/<id>/` | Rego rules: at orchestrator bootstrap. Go rules: by `sigcomply build`. |
| **Source plugin** | `.sigcomply/plugins/<id>/` | By `sigcomply build`. |
| **Evidence type** | `.sigcomply/evidence_types/<id>.v<n>.json` | At orchestrator bootstrap (JSON Schema document; no Go). |

That's the entire third-party extensibility surface. There is no
runtime plugin loading, no shared library, no plugin DSL beyond the
existing rule DSLs, no IPC, no WASM. Customers extend SigComply by
dropping files in three known directories and running one build
command.

## Loading mechanism for project-local Go code

Custom policies (Go rules) and source plugins need to be compiled.
The CLI does not load Go plugins at runtime — Go's `plugin` package is
fragile across versions and Linux-only. Instead, the CLI ships a
**build wrapper**:

```bash
sigcomply build
```

This command (M16):

1. Scans `.sigcomply/policies/*/rule.go` and `.sigcomply/plugins/*/plugin.go`.
2. Generates a `cmd/sigcomply-custom/main.go` that imports the in-tree
   `sigcomply` library plus a **blank-import block** of every
   project-local Go package. The blank imports trigger each package's
   `init()`, which calls `sources.RegisterFactory(...)` (for plugins)
   or `rules.Register(...)` (for rules) into the same registries the
   in-tree code uses.
3. Invokes `go build` to produce `./bin/sigcomply` — a binary tailored
   to this project, with project-local code compiled in.
4. From this point, `./bin/sigcomply check` runs the project-tailored
   binary.

For projects with no Go-based extensions (only Rego rules, only YAML
DSL rules, only YAML evidence-type schemas), no build step is
required; the shipped `sigcomply` binary suffices.

CI integration: customers with Go extensions add a `sigcomply build`
step to their workflow before the `sigcomply check` step. The shipped
GitHub Actions workflow and the GitLab CI example handle both shapes.

**Security implication.** Project-local Go code runs in the same
process as the CLI. The customer's `plugin.go` has the same access as
the in-tree plugins — including credentials, the vault backend, and
the network. Customers should treat their `.sigcomply/` directory
with the same code-review rigor as their core application code. The
CLI's design provides isolation only against external systems; it does
not sandbox project-local Go code.

---

## Authoring a custom policy

Worked example: AcmeCorp has contractors who use their own laptops and
identities. AcmeCorp's compliance program requires a documented
quarterly review of contractor access by the engineering manager.
There is no shipped SOC 2 policy that captures this exact assertion;
AcmeCorp authors a custom policy.

### Step 1 — Create the directory

```bash
mkdir -p .sigcomply/policies/acme.custom.cc6.1.contractor_review/{tests,}
```

### Step 2 — Author `policy.yaml`

```yaml
# .sigcomply/policies/acme.custom.cc6.1.contractor_review/policy.yaml
schema_version: policy.v1
id: acme.custom.cc6.1.contractor_review
control: SOC2.CC6.1
severity: high
category: access_control
description: |
  AcmeCorp requires a documented quarterly review of contractor access
  signed by the engineering manager. Evidence is a single PDF uploaded
  to manual evidence storage.
remediation: |
  Engineering manager performs and signs the contractor access review.
  Upload the signed PDF to the configured manual evidence bucket.
slots:
  review_document:
    accepts: [signed_document]
    cardinality: exactly-one
    required: true
parameters: {}
rule: rules.manual_presence.v1   # reuses a shipped rule
```

AcmeCorp's policy reuses a shipped rule (`rules.manual_presence.v1`)
that checks for the presence of a manual document within the temporal
window. No new rule code required.

### Step 3 — Register the manual catalog entry

```yaml
# .sigcomply/manual_catalog/contractor_review.yaml
schema_version: manual_catalog.v1
id: contractor_review
emits_as: signed_document
cadence: quarterly
grace_period: 30d
temporal_rule: retrospective
filename: evidence.pdf
description: "Quarterly contractor access review signed by engineering manager."
```

### Step 4 — Bind it in project config

```yaml
# .sigcomply.yaml (excerpt)
bindings:
  acme.custom.cc6.1.contractor_review:
    review_document: [manual.pdf:contractor_review]
```

### Step 5 — Add a test

```yaml
# .sigcomply/policies/acme.custom.cc6.1.contractor_review/tests/passes_when_present.yaml
name: passes when PDF present in window
inputs:
  slots:
    review_document:
      - type: signed_document
        id: contractor_review/2026-Q1
        payload:
          file_present: true
          in_temporal_window: true
expected:
  status: pass
  violations: []
```

### Step 6 — Run

```bash
sigcomply check --policies acme.custom.cc6.1.contractor_review
```

The policy appears in run output and in the cloud submission payload
exactly like a framework-shipped policy.

---

## Authoring a custom policy that requires custom rule logic

Suppose AcmeCorp's contractor access review must additionally verify
that the contractor count is below a threshold. There's no shipped
rule for this; AcmeCorp authors one.

### Add `rule.go`

```go
// .sigcomply/policies/acme.custom.cc6.1.contractor_review/rule.go
package acme_custom_cc6_1_contractor_review

import (
    "context"
    "fmt"

    "github.com/sigcomply/sigcomply-cli/internal/core/rule"
)

type Rule struct{}

func (Rule) ID() string { return "rules.acme.contractor_review.v1" }

func (Rule) Evaluate(ctx context.Context, in rule.Input) (rule.Result, error) {
    docs := in.Records("review_document")
    if len(docs) == 0 || !docs[0].PayloadBool("file_present") {
        return rule.Result{
            Status: rule.StatusFail,
            Violations: []rule.Violation{{
                Reason: "Contractor review PDF missing for current period.",
            }},
        }, nil
    }

    contractorCount := docs[0].PayloadInt("contractor_count")
    maxAllowed := in.ParamInt("max_contractors", 25)

    if contractorCount > maxAllowed {
        return rule.Result{
            Status: rule.StatusFail,
            Violations: []rule.Violation{{
                Reason: fmt.Sprintf("Contractor count %d exceeds max %d.", contractorCount, maxAllowed),
            }},
        }, nil
    }
    return rule.Result{Status: rule.StatusPass}, nil
}

func init() { rule.Register(Rule{}) }
```

### Update `policy.yaml`

```yaml
rule: rules.acme.contractor_review.v1
parameters:
  max_contractors:
    type: int
    default: 25
    min: 0
    max: 1000
```

### Build and run

```bash
sigcomply build      # compiles project-tailored binary
./bin/sigcomply check
```

---

## Authoring a custom source plugin

Worked example: AcmeCorp has an internal IAM system
(`auth.acme-internal.com`) emitting user data over a private API. No
shipped plugin covers it. AcmeCorp authors one.

There are two paths depending on whether the data fits an existing
evidence type:

- **Path A (reuse `user_record`).** AcmeCorp's internal IAM records
  are functionally identical to AWS IAM and Okta users — same fields,
  same semantics. The plugin emits the shipped `user_record` type and
  becomes immediately consumable by every existing policy with
  `accepts: [user_record]`. **No policy changes needed anywhere.**
- **Path B (coin a new `acme_principal` type).** AcmeCorp's records
  carry extra fields (department, security clearance, manager_id)
  that they want their custom policies to consume. They register a
  new evidence type and add it to the relevant slots' `accepts:`
  lists.

We show both.

### Step 1 — Plugin manifest (shared between A and B)

```yaml
# .sigcomply/plugins/acme.internal_iam/plugin.yaml
schema_version: plugin.v1
id: acme.internal_iam
display_name: "Acme Internal IAM"
version: "0.1.0"
description: "Reads user records from Acme's internal IAM service."
emits: [user_record]                  # Path A; Path B adds acme_principal
config_schema:
  endpoint:
    type: string
    required: true
  token_env:
    type: string
    default: "ACME_IAM_TOKEN"
```

### Step 2 — Plugin implementation with a registered factory

```go
// .sigcomply/plugins/acme.internal_iam/plugin.go
package acme_internal_iam

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "os"

    "github.com/sigcomply/sigcomply-cli/internal/core"
    "github.com/sigcomply/sigcomply-cli/internal/sources"
)

const SourceID = "acme.internal_iam"

type Plugin struct {
    endpoint string
    token    string
}

func (p *Plugin) ID() string      { return SourceID }
func (p *Plugin) Emits() []string { return []string{"user_record"} }

func (p *Plugin) Init(ctx context.Context, cfg map[string]any) error {
    p.endpoint, _ = cfg["endpoint"].(string)
    if p.endpoint == "" {
        return fmt.Errorf("%s: endpoint is required", SourceID)
    }
    envName, _ := cfg["token_env"].(string)
    if envName == "" {
        envName = "ACME_IAM_TOKEN"
    }
    p.token = os.Getenv(envName)
    if p.token == "" {
        return fmt.Errorf("%s: %s not set", SourceID, envName)
    }
    return nil
}

func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
    httpReq, _ := http.NewRequestWithContext(ctx, "GET", p.endpoint+"/users", nil)
    httpReq.Header.Set("Authorization", "Bearer "+p.token)
    resp, err := http.DefaultClient.Do(httpReq)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var users []struct {
        ID, Email string
        MFA, Admin bool
    }
    if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
        return nil, err
    }

    out := make([]core.EvidenceRecord, 0, len(users))
    for _, u := range users {
        payload, _ := json.Marshal(map[string]any{
            "id":          u.ID,
            "email":       u.Email,
            "mfa_enabled": u.MFA,
            "is_admin":    u.Admin,
        })
        out = append(out, core.EvidenceRecord{
            Type:        "user_record",
            ID:          u.ID,
            IdentityKey: u.Email,           // cross-source dedup with aws.iam, okta
            SourceID:    SourceID,
            Payload:     payload,
        })
    }
    return out, nil
}

// init registers this plugin's factory with the global SourceRegistry.
// This is the same pattern every in-tree plugin uses. The factory is
// what the orchestrator calls (with the YAML-unmarshalled config block)
// to produce a configured plugin instance per run.
func init() {
    sources.RegisterFactory(SourceID, func(ctx context.Context, cfg map[string]any) (core.SourcePlugin, error) {
        p := &Plugin{}
        if err := p.Init(ctx, cfg); err != nil {
            return nil, err
        }
        return p, nil
    })
}
```

### Step 3 — Configure the project

```yaml
# .sigcomply.yaml (excerpt)
sources:
  acme.internal_iam:
    endpoint: "https://auth.acme-internal.com/api/v1"
    token_env: "ACME_IAM_TOKEN"

bindings:
  soc2.cc6.1.mfa_enforced:
    user_directory: [acme.internal_iam]
  soc2.cc6.1.admin_mfa_enforced:
    user_directory: [acme.internal_iam, aws.iam]    # mix and match
```

### Step 4 — Build and run

```bash
sigcomply build              # generates the wrapper, blank-imports
                             # acme.internal_iam, runs `go build`
./bin/sigcomply check
```

The `acme.internal_iam` plugin now satisfies any policy whose slots
have `accepts: [user_record]`. AcmeCorp can mix and match across the
same binding (`[acme.internal_iam, aws.iam]`) if they want. **No
policy changes happened — only configuration.**

---

### Path B — Coining a new evidence type

If AcmeCorp wants their custom policies to consume fields beyond what
`user_record` carries (department, security clearance, manager_id),
they register a new evidence type.

#### B1 — Author the schema

```json
// .sigcomply/evidence_types/acme_principal.v1.json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://schemas.acme.com/evidence_types/acme_principal/v1.json",
  "title": "acme_principal",
  "version": 1,
  "description": "An Acme Corp user with internal-only fields (department, security clearance, manager_id) not present in the shipped user_record type. Cross-source identity convention: populate EvidenceRecord.IdentityKey with the user's primary email.",
  "type": "object",
  "required": ["id", "mfa_enabled", "department"],
  "properties": {
    "id":                 { "type": "string" },
    "email":              { "type": "string", "format": "email" },
    "mfa_enabled":        { "type": "boolean" },
    "department":         { "type": "string" },
    "security_clearance": { "type": "string", "enum": ["public", "internal", "confidential", "secret"] },
    "manager_id":         { "type": "string" }
  },
  "additionalProperties": true
}
```

Cross-source identity convention is documented in the schema's
`description` (plugin authors read it to know what to populate
`EvidenceRecord.IdentityKey` with). The constraints `format: email`
and `enum: [...]` are honored by future, richer validators — today's
validator enforces only top-level `type: object`, `required`, and
per-property scalar `type` (see
[`04a-evidence-type-registry.md`](04a-evidence-type-registry.md)
§Current implementation status).

#### B2 — Plugin emits both types

```yaml
# .sigcomply/plugins/acme.internal_iam/plugin.yaml
emits: [user_record, acme_principal]
```

```go
// Inside Collect — emit two records per user, one of each type:
out = append(out, core.EvidenceRecord{
    Type:        "user_record",            // for shipped policies
    ID:          u.ID,
    IdentityKey: u.Email,
    SourceID:    SourceID,
    Payload:     userRecordPayload,
})
out = append(out, core.EvidenceRecord{
    Type:        "acme_principal",          // for AcmeCorp policies
    ID:          u.ID,
    IdentityKey: u.Email,
    SourceID:    SourceID,
    Payload:     acmePrincipalPayload,
})
```

The shipped policies bind to slots with `accepts: [user_record]` and
ignore the `acme_principal` records. AcmeCorp's custom policies bind
to slots with `accepts: [acme_principal]` and ignore the
`user_record` records.

#### B3 — Custom policy references the new type

```yaml
# .sigcomply/policies/acme.custom.cc6.1.confidential_clearance_review/policy.yaml
schema_version: policy.v1
id: acme.custom.cc6.1.confidential_clearance_review
control: SOC2.CC6.1
severity: high
category: access_control
description: |
  Every user with access to confidential data must have an active
  security clearance recorded in Acme's internal IAM.
slots:
  principals:
    accepts: [acme_principal]
    cardinality: one-or-more
    required: true
rule: rules.acme.confidential_clearance.v1
```

The custom rule reads `record.payload.security_clearance` and
`record.payload.department`, which `user_record` doesn't expose but
`acme_principal` guarantees.

---

## Contributing back upstream

Project-local extensions that have broader value (a new shipped
plugin, a new shipped policy, a new evidence type) can be contributed
to the SigComply CLI repo.

The contribution path:

1. **Fork** the public `sigcomply-cli` repo.
2. **Move** the project-local files into the in-tree locations:
   - `internal/sources/<id>/` for plugins
   - `internal/compliance_frameworks/<fw>/policies/<id>/` for policies
   - `internal/evidence_types/<id>.v<n>.yaml` for evidence types
3. **Adapt** import paths from the project-local package names to the
   in-tree ones (`internal/sources/...`).
4. **Add** in-tree tests under the same directory.
5. **Update** the relevant framework's `policies/` index if adding a
   shipped policy.
6. **Open a PR** with a clear description, test coverage, and a note
   on whether the contribution implies any aggregation-contract changes
   (almost always: no).
7. **Review**: at least one maintainer must approve. For changes touching
   the aggregation contract, security owner must also approve.

The contribution standards mirror the in-tree code's standards: TDD,
small atomic commits, conventional commit prefixes, all tests
passing, no breaking changes without a major version bump.

---

## Compatibility guarantees

A project-local extension authored against CLI version `1.x` is
guaranteed to keep working for the entire `1.x` series:

- `SourcePlugin`, `Rule`, `Vault`, and other L1 interfaces are
  append-only within a major.
- Evidence type schemas only add optional fields within a major.
- The aggregation contract is frozen within a major.
- Project config schema additions are optional and default-safe.

Bumping to a new major (`2.x`) is allowed to break extensions but
must:

- Provide a migration guide
- Coexist with `1.x` long enough for ecosystem migration
- Maintain vault-format backward-compatibility (auditors still read
  old vaults)

---

## What's deliberately *not* extensible

- **Framework specs themselves.** A customer cannot publish a custom
  "SOC 2" spec that disagrees with the canonical one. Customers adapt
  by adding custom policies (which the framework spec doesn't
  enumerate but the CLI runs anyway) or by deselecting framework
  policies (via exception with `state: na`).
- **The aggregation contract.** Customers cannot widen the cloud
  payload by registering a custom payload field. That's the privacy
  boundary; widening requires upstream code change.
- **Vault layout.** Schema is fixed within a major version. Customers
  cannot rearrange directory structure or change file names.
- **Run identity scheme.** Customers cannot inject custom run IDs or
  alter how `period_id` is derived. The fiscal calendar config tunes
  the derivation; the derivation algorithm itself is fixed.

These restrictions exist because they're the contracts external
parties (auditors, the cloud, the verification SPA) rely on. Customers
get extensibility everywhere it preserves those contracts.
