# 07 — Extensibility

The CLI ships with curated frameworks, policies, rules, and source
plugins. Customers extend the system *project-locally* under
`.sigcomply/` — their own policies, their own plugins, their own
evidence types.

This document specifies what can be customized, how to author each
artifact, the compilation/loading mechanism, and the path from a
project-local extension to an upstream contribution.

---

## Status — which routes are wired today

**Read this before following any worked example below.** The
data-driven routes are live and fork-free; the Go routes are not, and
the difference decides which one you should reach for.

**Wired, no fork needed — the data-driven routes.** Project-local **YAML
policies** (`.sigcomply/policies/<id>/policy.yaml`, `pass_when:` clause
included), **Rego rules** (`.sigcomply/policies/<id>/rule.rego`), and
**evidence-type JSON Schemas** (`.sigcomply/evidence_types/*.json`) are
discovered and registered at orchestrator bootstrap by
`registerProjectLocal` (`internal/orchestrator/project_local.go`) on every
`sigcomply check`. No recompile, no fork, no `sigcomply build`.
These three cover the overwhelming majority of what customers need, and
they are the routes this document recommends.

**Project-local *Go* code currently requires the extension package to
live inside the CLI module — i.e. a fork.** `sigcomply build` itself
genuinely works: it discovers Go packages under `.sigcomply/`, scans
their imports, runs `go vet`, generates a blank-import entrypoint, and
runs `go build` (see §Loading mechanism). What does not work is the
import. Every plugin API surface a Go extension must reach —
`core.SourcePlugin`, `sources.Env`, `sources.RegisterFactory`,
`vault.RegisterBackend`, `manual.Reader` / `manual.RegisterReader` —
lives under `internal/`. Go forbids importing a path containing an
`internal` element from outside the tree rooted at that element's
parent, and `sigcomply build` compiles the extension **inside the
customer's own module** (`readModulePath` reads the *project's* `go.mod`,
and `go build` runs from the project dir). So a project-local Go plugin
passes `sigcomply build`'s validation and *then* fails at `go build`
with `use of internal package … not allowed`.

What would lift this is a public (non-`internal`) API package exporting
those interfaces and registries. **It is not shipped**, and creating one
is its own piece of work, not something a customer can do from
`.sigcomply/`. Until it exists, treat the Go worked examples below as
**illustrations of the shape of each interface** — the method sets, the
`init()` registration pattern, the factory signatures — rather than a
walkthrough that compiles as-is from a customer repo. They are
followable verbatim only from inside the CLI module, which is the
[upstream-contribution path](#contributing-back-upstream).

**Go rules and Go evidence types have a second, independent gap.** Even
setting the `internal/` import problem aside, neither has a registration
hook at all. The rule registry is a per-evaluation `Set` populated
**only** from each framework's `Rules()` — there is no
`rule.Register(...)` an `init()` can call. Evidence types are registered
from JSON (embedded in-tree, or `.sigcomply/evidence_types/*.json`
project-locally), never from a Go `init()`. A `rules/` package or an
`evidence_types/<id>/` package under `.sigcomply/` is therefore
discovered and compiled and then silently never loaded; `sigcomply
build` prints a warning for both kinds so the discovery isn't mistaken
for wiring.

---

## What can be customized

| Artifact | Project-local | In-tree (upstream) |
|---|---|---|
| Framework spec | ❌ (frameworks are curated) | ✅ |
| Policy (YAML) | ✅ as `.sigcomply/policies/<id>/policy.yaml` (loaded at bootstrap, unioned into the plan) | ✅ Go `.policy()` builders in `internal/frameworks/<fw>/policies_*.go` |
| Rego rule | ✅ as `.sigcomply/policies/<id>/rule.rego` (loaded at bootstrap) | ✅ via `framework.Rules()` (no shipped policy uses one today) |
| Go rule | ⚠️ **not wired** — compiled by `sigcomply build`, but no registration hook feeds it into the per-`Set` rule registry | ✅ via `framework.Rules()` |
| Source plugin (Axis C) | ⚠️ **fork required** — the package shape is `init()` → `sources.RegisterFactory`, but `sources` is under `internal/` and is not importable from a customer module (see §Status) | ✅ in `internal/sources/` (same self-registration pattern) |
| Vault backend (Axis B) | ⚠️ **fork required** — `init()` → `vault.RegisterBackend`, same `internal/` import limitation | ✅ in `internal/vault/<id>/` (same self-registration pattern) |
| Manual-evidence backend (Axis A) | ⚠️ **fork required** — `init()` → `manual.RegisterReader`, same `internal/` import limitation | ✅ in `internal/sources/manual/<id>/` (same self-registration pattern) |
| Evidence type | ✅ JSON Schema file at `.sigcomply/evidence_types/<id>.v<n>.json`, loaded at bootstrap (a Go package under `.sigcomply/evidence_types/<id>/` has **no** registration hook and never loads) | ✅ in `internal/evidence_types/schemas/<id>.v<n>.json`, embedded via `go:embed` (see [`04a`](04a-evidence-type-registry.md)) |
| Project config (`.sigcomply.yaml`) | ✅ | n/a |
| Aggregation contract | ❌ (frozen schema) | ✅ (requires bump + security review) |

The three plugin axes (A, B, C) share one mechanical pattern —
self-registering factory plus blank-import bootstrap. See
[`00-three-plugin-axes.md`](00-three-plugin-axes.md) for the unified
design.

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
  go.mod                                   # required for Go extensions
  .sigcomply.yaml                          # project config
  .sigcomply/
    policies/
      acme.custom.cc6.1.contractor_review/
        policy.yaml                         # loaded at bootstrap
        rule.rego                           # optional Rego rule, loaded at bootstrap
        rules/                              # optional Go rule package (not yet wired)
          rule.go
    plugins/
      acme.internal_iam/
        plugin.go                           # Go source plugin (package name == dir)
        plugin_test.go
    evidence_types/
      acme_principal.v1.json                # plain JSON Schema, loaded at bootstrap
```

Data-driven artifacts (`policy.yaml`, `rule.rego`, and evidence-type
`*.json`) are discovered under `.sigcomply/` at orchestrator bootstrap
and unioned into the registries (L2) alongside in-binary artifacts. Go
artifacts (plugins, and — were they wired — rule and evidence-type
packages) are compiled into a tailored binary by `sigcomply build`,
subject to the `internal/` import limitation in §Status.

There is no in-tree `plugin.yaml` manifest for shipped plugins; a
`plugin.yaml` only applies to project-local plugins — and even there it
is **descriptive only**: `sigcomply build` never opens it. Discovery is
purely structural (a directory holding a `.go` file whose `package`
clause matches the directory name), and the authoritative declaration of
what a plugin emits is its `Emits()` method. `spec.LoadPluginManifest`
exists and parses the format, but nothing in the production path calls
it; the file is reserved for a future validation step.

---

## `.sigcomply/` is the only extension surface

There is no runtime plugin loading, no shared library, no IPC, no WASM.
Customers extend SigComply by dropping files in known directories under
`.sigcomply/` and (for Go code) running `sigcomply build`:

| What | Where | How it loads |
|---|---|---|
| **YAML policy** | `.sigcomply/policies/<id>/policy.yaml` | Orchestrator bootstrap — parsed and added to the plan. |
| **Rego rule** | `.sigcomply/policies/<id>/rule.rego` | Orchestrator bootstrap — registered into the per-`Set` rule registry (OPA-backed). |
| **Go rule** | `.sigcomply/policies/<id>/rules/` | ⚠️ Discovered + compiled by `sigcomply build`, but **not yet wired** into evaluation (no registration hook). |
| **Source plugin** | `.sigcomply/plugins/<id>/` | `sigcomply build` blank-imports it; its `init()` calls `sources.RegisterFactory`. |
| **Vault / manual backend** | `.sigcomply/plugins/<id>/` | `sigcomply build`; `init()` calls `vault.RegisterBackend` / `manual.RegisterReader`. |
| **Evidence type** | `.sigcomply/evidence_types/<id>.v<n>.json` | Orchestrator bootstrap — `loadProjectEvidenceTypes` reads every `*.json` file directly under `evidence_types/`, compiles the schema body, and registers it. Subdirectories are ignored: a **Go** package under `.sigcomply/evidence_types/<id>/` is compiled by `sigcomply build` but has no registration hook and never loads. |

## Loading mechanism for project-local Go code

The CLI does not load Go plugins at runtime — Go's `plugin` package is
fragile across versions and Linux-only. Instead, the CLI ships a
**build wrapper** that is fully wired today:

```bash
sigcomply build      # default output: ./bin/sigcomply
```

`runBuild` (`cmd/sigcomply/build.go`):

1. **Discovers** Go packages under `.sigcomply/plugins/<name>/`,
   `.sigcomply/policies/<name>/rules/`, and `.sigcomply/evidence_types/`
   (`DiscoverExtensions`). If none are found, the command is a graceful
   no-op — the shipped binary already covers Rego-only / YAML-only
   projects.
2. **Requires a project `go.mod`** (`readModulePath`). Project-local Go
   extensions are import-rooted at the project's module path; a project
   with Go extensions but no `go.mod` cannot compile, so this is an
   immediate configuration error (exit 3).
3. **Validates** each package (`ValidateExtensions`):
   - The declared `package X` name must match the directory basename
     (sanitized) — a mismatch is a configuration error.
   - An **import deny-list** rejects two specific stdlib reaches:
     `os/exec` (subprocess spawning) and anything under `net` / `net/*`
     (direct network access). It is a deny-list, not an allow-list —
     everything not named is permitted. In-tree plugins reach those APIs
     through curated `internal/` packages; project-local code gets no
     such escape hatch in v1.
4. **Runs `go vet`** against the discovered packages to surface errors
   before a slow compile.
5. **Generates an entrypoint** (`GenerateEntrypoint`) at
   `.sigcomply/.build/sigcomply-custom/main.go` that imports the shipped
   CLI command package (`github.com/sigcomply/sigcomply-cli/cmd/sigcomply`,
   for `cmd.Execute()`) plus a **blank-import block** of every discovered
   project-local package — so each package's `init()` runs and registers
   its factory.
6. **Runs `go build`** from the project dir (so imports resolve through the
   project `go.mod`, which must require `sigcomply-cli`), producing
   `./bin/sigcomply`.

From there, `./bin/sigcomply check` runs the project-tailored binary.
Projects with no Go extensions skip this entirely; the shipped binary
suffices.

CI integration: customers with Go extensions add a `sigcomply build` step
before `sigcomply check`. See the example workflows under
[`examples/`](../../examples/) and [`09-ci-execution-model.md`](09-ci-execution-model.md).

> **Go rules and Go evidence types are compiled but never loaded.** A
> `rules/` package under a policy dir, or a package under
> `evidence_types/<id>/`, is discovered and will compile, but neither has
> anything to register with: the rule registry is a per-evaluation `Set`
> populated **only** from `framework.Rules()` (there is no exported
> `rule.Register(...)` an `init()` can call), and evidence types are
> registered from JSON, never from Go. `sigcomply build` warns on both
> kinds rather than reporting them as built-and-working. Author custom
> rule logic as a `rule.rego` and custom evidence types as
> `.sigcomply/evidence_types/<id>.v<n>.json` — both load at bootstrap —
> or contribute the rule upstream via a framework's `Rules()`.

**Security implication — and how weak the import check really is.**
Project-local Go code runs in the same process as the CLI, with the same
access as an in-tree plugin: credentials, the vault backend, the
filesystem. The import check is **not a sandbox**, and it is important
not to read it as one:

- It scans only the **top-level** non-`_test.go` files of each
  discovered extension directory. Code in a nested subpackage is never
  looked at.
- It matches only **direct** import paths. A third-party module that
  itself does the networking — an HTTP client library, `go-ldap`, an
  SDK — passes untouched, because the extension imports the library, not
  `net/http`.

In other words it is a speed bump against a naive `import "net/http"`,
nothing more. A `.sigcomply/` directory deserves the same code-review
rigor as your core application code; the build wrapper will not catch a
hostile extension, and is not trying to.

---

## Authoring a custom policy

Every policy spec — shipped or project-local — carries a **required
first-class `evidence_mode`** field (`automated` | `manual`). The
evaluator branches on it and nothing else. The two modes have mutually
exclusive shapes:

- **`automated`** requires `slots` (each with `accepts: [<type>,…]` and a
  `cardinality`) and **exactly one of** `pass_when:` or `rule:`. It must
  not have a `catalog_entry`.
- **`manual`** requires a `catalog_entry` and **must not** have `slots`,
  `pass_when:`, or `rule:` — the manual PDF-presence check is universal.

`pass_when:` is the primary authoring path (no Go/Rego); `rule:` is the
escape hatch for what the DSL can't express. A spec that omits
`evidence_mode`, or mixes the two shapes, fails to load with exit 3.

### Example A — a manual policy

AcmeCorp requires a documented quarterly review of contractor access,
evidenced by a signed PDF. This is a **manual** policy: no slots, no rule.

```yaml
# .sigcomply/policies/acme.custom.cc6.1.contractor_review/policy.yaml
schema_version: policy.v1
id: acme.custom.cc6.1.contractor_review
evidence_mode: manual            # required; selects the PDF-presence path
control: SOC2.CC6.1
severity: high
category: access_control
description: |
  AcmeCorp requires a documented quarterly review of contractor access
  signed by the engineering manager. Evidence is a PDF uploaded to the
  project's manual-evidence bucket.
remediation: |
  Engineering manager performs and signs the contractor access review;
  upload the signed PDF to the configured manual-evidence bucket.
catalog_entry: contractor_review   # resolves the folder; NO slots/pass_when/rule
```

A manual policy takes **no binding** — it carries its own `catalog_entry`
(above), and the planner routes it through the `manual.pdf` singleton. A
project only needs a `policies:` entry to *override* the catalog entry (or
to flip an automated policy to manual):

```yaml
# .sigcomply.yaml (excerpt) — only needed to override the default
policies:
  acme.custom.cc6.1.contractor_review:
    evidence_mode: manual
    catalog_entry: contractor_review
```

> The previous version of this doc showed a manual policy declaring both
> a `slots:` block and `rule: rules.manual_presence.v1`. That shape is
> **rejected at load**: a manual policy must not carry slots or a rule.
> Manual evidence runs the universal PDF-presence check, not a named rule.

### Example B — an automated policy with `pass_when:`

The common case: a quantifier over a field condition on one slot — no Go,
no Rego.

```yaml
# .sigcomply/policies/acme.custom.cc6.1.mfa_enforced/policy.yaml
schema_version: policy.v1
id: acme.custom.cc6.1.mfa_enforced
evidence_mode: automated
control: SOC2.CC6.1
severity: high
category: access_control
description: Every user in the directory must have MFA enabled.
slots:
  evidence:
    accepts: [directory_user]
    cardinality: one-or-more
pass_when:
  slot: evidence
  quantifier: all
  # condition node is a {op, field, value} triple; field paths are
  # rooted at payload.* (a bare field name errors the policy).
  condition: { op: eq, field: payload.mfa_enabled, value: true }
```

The supported quantifiers are `all | none | any | count` (only `count`
takes `min_percentage`); ops are `eq, neq, lt, lte, gt, gte, in, not_in,
is_set, all_of, any_of`. Parameters are referenced on the value side as
the string `"$params.<name>"`. Full DSL reference:
[`03-policy-spec.md`](03-policy-spec.md).

**Scoping with `filter`, and the one rule to remember.** A clause may
carry a `filter` — a second condition tree that selects which records the
quantifier judges:

```yaml
pass_when:
  slot: keys
  quantifier: all
  filter:                      # only customer-managed keys are in scope
    op: all_of
    conditions:
      - { op: is_set, field: payload.is_customer_managed }
      - { op: eq, field: payload.is_customer_managed, value: true }
  condition: { op: eq, field: payload.rotation_enabled, value: true }
```

The `is_set` leg is not decoration. A filter that references a field the
record does not carry **errors the policy** — it has not decided whether
that record is in scope, and quietly excluding it would bias the result
toward passing, because `all` and `none` are true of the empty set. So if
your filter reads a field that is `required` in the evidence type's
schema, write it bare; if it reads an optional one, guard it with
`is_set` inside an `all_of`, which short-circuits before the comparison
is reached. (`any_of` does not guard — it keeps evaluating past a false.)

Check the schema — `sigcomply evidence catalog` and
[`04a-evidence-type-registry.md`](04a-evidence-type-registry.md) list
which fields each type guarantees.

### Run

```bash
sigcomply check     # the framework is fixed by config / SIGCOMPLY_FRAMEWORK
```

Project-local policies are unioned into the plan at bootstrap and appear in
run output and the cloud submission payload exactly like framework-shipped
ones. (There is no `--policies` filter flag; select the run set with
`--cadence` / `--on-push` as in [`09-ci-execution-model.md`](09-ci-execution-model.md).)

### When `pass_when:` isn't enough: the `rule:` escape hatch

For aggregations or joins the DSL can't express (a key lookup across
slots is `pass_when:`'s `matches_in` — see
[`03-policy-spec.md`](03-policy-spec.md) §Multi-slot policies), an automated
policy may instead carry `rule: <rule_id>` (mutually exclusive with
`pass_when:`). Today the only **wired** project-local rule mechanism is a
`rule.rego` alongside the policy:

```rego
# .sigcomply/policies/acme.custom.cc6.1.contractor_count/rule.rego
package sigcomply.acme.contractor_count

default allow := false
# … Rego expressing the cross-slot / threshold logic …
```

The Rego rule is registered into the per-`Set` rule registry at bootstrap,
and the policy references it via its `rule:` field.

**Project-local Go rules are not yet wired** (see the status note above):
a `rules/` Go package compiles under `sigcomply build` but has no
registration hook into the rule registry. Until that lands, express custom
rule logic as Rego, or contribute the rule upstream through a framework's
`Rules()`. The Go-rule authoring shape is therefore omitted here to avoid
documenting an uncompilable-into-evaluation path.

---

## Authoring a custom source plugin

Worked example: AcmeCorp has an internal IAM system
(`auth.acme-internal.com`) emitting user data over a private API. No
shipped plugin covers it. AcmeCorp authors one.

> **Illustrative, not yet copy-pasteable from a customer repo.** The Go
> below shows the *shape* of the plugin contract — the method set, the
> factory signature, the `init()` registration. It imports
> `internal/core` and `internal/sources`, which Go will not let a
> package outside the CLI module import, so today this compiles only
> from inside the CLI module (a fork / upstream contribution). See
> §Status. The YAML in Steps 1 and 3 is unaffected.

There are two paths depending on whether the data fits an existing
evidence type:

- **Path A (reuse `directory_user`).** AcmeCorp's internal IAM records
  are functionally identical to AWS IAM, Okta, and GitHub users — the
  shipped `directory_user` type already covers them (note: `aws.iam`
  emits `directory_user.v2`; `okta` and `github` emit `directory_user`).
  The plugin emits `directory_user` and becomes immediately consumable by
  every existing policy whose slot has `accepts: [directory_user]`. **No
  policy changes needed anywhere.** This is the substitutability property:
  one slot accepting `[directory_user]` can be fed by `aws.iam`, `okta`,
  `github`, and `acme.internal_iam` interchangeably.
- **Path B (coin a new `acme_principal` type).** AcmeCorp's records
  carry extra fields (department, security clearance, manager_id) that
  they want their custom policies to consume. They register a new evidence
  type and add it to the relevant slots' `accepts:` lists.

We show both.

### Step 1 — Plugin manifest (shared between A and B)

```yaml
# .sigcomply/plugins/acme.internal_iam/plugin.yaml
schema_version: plugin.v1
id: acme.internal_iam
display_name: "Acme Internal IAM"
version: "0.1.0"
description: "Reads user records from Acme's internal IAM service."
emits: [directory_user]               # Path A; Path B adds acme_principal
config_schema:
  endpoint:
    type: string
    required: true
  token_env:
    type: string
    default: "ACME_IAM_TOKEN"
```

(The `plugin.yaml` manifest applies to **project-local** plugins only.
In-tree plugins declare their emitted types in code via `Emits()`, with no
manifest file.)

> **`plugin.yaml` is not yet consumed by anything.** `sigcomply build`
> never opens it — discovery is structural (a directory holding a `.go`
> file whose `package` clause matches the directory name), and the
> authoritative statement of what the plugin emits is the `Emits()`
> method in Step 2. `spec.LoadPluginManifest` parses this format and is
> exercised by its own tests, but has no production caller. Write the
> manifest for your own documentation if you like; keep `Emits()` right
> regardless.

### Step 2 — Plugin implementation with a registered factory

The `SourcePlugin` interface (`internal/core/source.go`) is `ID()`,
`Emits() []string`, `Init(ctx, cfg map[string]any) error`, and
`Collect(ctx, req core.SlotRequest) ([]core.EvidenceRecord, error)`. The
factory registered in `init()` takes an **`sources.Env`** struct (not a
bare `map[string]any`): `Env{ Config map[string]any, FrameworkExtras
map[string]any }`. There is deliberately no `Vault` field — a plugin
that needs storage configures its own backend, the way `manual.pdf`
does, rather than borrowing the run's evidence vault.

```go
// .sigcomply/plugins/acme.internal_iam/plugin.go
package acme_internal_iam

import (
    "context"
    "encoding/json"
    "fmt"
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
func (p *Plugin) Emits() []string { return []string{"directory_user"} }

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
    // Fetch users from the internal IAM service and map each into a
    // directory_user payload. (In v1, `sigcomply build` rejects a
    // *direct* stdlib `net` / `net/*` import from a project-local
    // extension. The check is a deny-list over direct imports of the
    // extension dir's top-level files only, so a third-party HTTP or
    // LDAP client — or a nested subpackage — is not rejected; there is
    // no curated in-tree networking helper a project-local package
    // could reach, since every such helper is under internal/. The
    // supported route for a plugin that must talk to the network is to
    // contribute it upstream, where it lives inside the CLI module.)
    users := p.fetchUsers(ctx)

    out := make([]core.EvidenceRecord, 0, len(users))
    for _, u := range users {
        payload, _ := json.Marshal(map[string]any{
            "id":          u.ID,
            "email":       u.Email,
            "mfa_enabled": u.MFA,
            "is_admin":    u.Admin,
        })
        out = append(out, core.EvidenceRecord{
            Type:        "directory_user",
            ID:          u.ID,
            IdentityKey: u.Email,           // cross-source dedup with aws.iam, okta
            SourceID:    SourceID,
            Payload:     payload,
        })
    }
    return out, nil
}

// init registers this plugin's factory. The factory receives an
// sources.Env; pull the per-instance config from env.Config. This is
// the same pattern every in-tree plugin uses.
func init() {
    sources.RegisterFactory(SourceID, func(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
        p := &Plugin{}
        if err := p.Init(ctx, env.Config); err != nil {
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

policies:
  soc2.cc6.1.mfa_enforced_all_users:
    bindings:
      evidence: [acme.internal_iam]
  soc2.cc6.1.mfa_enforced_admins:
    bindings:
      evidence: [acme.internal_iam, aws.iam]   # mix and match
```

### Step 4 — Build and run

`sigcomply build` generates a `main.go` that imports *both* the shipped
CLI command package and your extension, then runs `go build` from the
project directory — so the project must be a Go module that requires
`sigcomply-cli`, or the generated entrypoint cannot resolve
`cmd.Execute()`:

```bash
go mod init example.com/acme-project        # if the repo has no go.mod yet
go get github.com/sigcomply/sigcomply-cli   # the generated entrypoint imports it

sigcomply build              # generates the wrapper, blank-imports
                             # acme.internal_iam, runs `go build`
./bin/sigcomply check
```

> Per §Status, `go build` will still fail here today with `use of
> internal package … not allowed`, because `plugin.go` imports
> `internal/core` and `internal/sources`. The dependency step above is
> necessary but not sufficient until a public API package ships.

The `acme.internal_iam` plugin now satisfies any policy whose slots
have `accepts: [directory_user]`. AcmeCorp can mix and match across the
same binding (`[acme.internal_iam, aws.iam]`) if they want. **No
policy changes happened — only configuration.**

---

### Path B — Coining a new evidence type

If AcmeCorp wants their custom policies to consume fields beyond what
`directory_user` carries (department, security clearance, manager_id),
they register a new evidence type.

#### B1 — Author the schema

Project-local evidence types are a **plain JSON file** dropped at
`.sigcomply/evidence_types/<id>.v<n>.json` — no Go, no `sigcomply build`.
`loadProjectEvidenceTypes` (`internal/orchestrator/project_local.go`)
reads every `*.json` file directly under that directory at bootstrap,
compiles the schema, and registers it into the same registry the embedded
in-tree types land in. The file name is not parsed; it is convention
only. The body is a JSON Schema **draft-07** document — the same form the
in-tree schemas at `internal/evidence_types/schemas/<id>.v<n>.json` use.
The type ID lives in the schema's `title`; the version in a `version`
field.

Subdirectories under `evidence_types/` are ignored by the loader. A Go
package at `.sigcomply/evidence_types/<id>/` is discovered and compiled
by `sigcomply build`, but nothing ever calls it — there is no
registration hook for a Go-authored evidence type. Use the JSON file.

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "acme_principal",
  "version": 1,
  "description": "An Acme Corp user with internal-only fields (department, security clearance, manager_id) not present in the shipped directory_user type. Cross-source identity convention: populate EvidenceRecord.IdentityKey with the user's primary email.",
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

The collector validates every record against the registered schema using
**full JSON Schema draft-07** (gojsonschema): `enum`, `format`, `pattern`,
`minimum`/`maximum`, and nested object/array constraints are all enforced
— not just `required`. The **first** non-conforming record fails the
binding and tags the policy `error` (exit 3); there is no
drop-and-continue and no ">5% threshold" (that permissive mode is design
intent only). Design custom schemas top-down from the semantic concept so
every field is satisfiable by all plausible sources without null sentinels
(see [`04a-evidence-type-registry.md`](04a-evidence-type-registry.md)).

#### B2 — Plugin emits both types

```yaml
# .sigcomply/plugins/acme.internal_iam/plugin.yaml
emits: [directory_user, acme_principal]
```

```go
// Inside Collect — emit two records per user, one of each type:
out = append(out, core.EvidenceRecord{
    Type:        "directory_user",         // for shipped policies
    ID:          u.ID,
    IdentityKey: u.Email,
    SourceID:    SourceID,
    Payload:     directoryUserPayload,
})
out = append(out, core.EvidenceRecord{
    Type:        "acme_principal",          // for AcmeCorp policies
    ID:          u.ID,
    IdentityKey: u.Email,
    SourceID:    SourceID,
    Payload:     acmePrincipalPayload,
})
```

The shipped policies bind to slots with `accepts: [directory_user]` and
ignore the `acme_principal` records. AcmeCorp's custom policies bind to
slots with `accepts: [acme_principal]` and ignore the `directory_user`
records.

#### B3 — Custom policy references the new type

```yaml
# .sigcomply/policies/acme.custom.cc6.1.confidential_clearance_review/policy.yaml
schema_version: policy.v1
id: acme.custom.cc6.1.confidential_clearance_review
evidence_mode: automated
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
pass_when:
  slot: principals
  quantifier: all
  condition: { op: in, field: payload.security_clearance,
               value: [internal, confidential, secret] }
```

The `pass_when:` reads `payload.security_clearance`, which
`directory_user` doesn't expose but `acme_principal` guarantees. (A
cross-slot or aggregate assertion the DSL can't express would use a
`rule.rego` instead — Go rules remain unwired, per the status note.)

---

## Custom vault backends

Worked example: AcmeCorp's vault must live on an internal NFS mount
fronted by an in-house metadata service. None of the shipped backends
(`local`, `s3`, `gcs`, `azure_blob`) match. AcmeCorp authors a custom
vault backend.

This is **Axis B** of the three plugin axes (see
[`00-three-plugin-axes.md`](00-three-plugin-axes.md) §Axis B). The
extension surface is `.sigcomply/plugins/` — the same one used for
custom source plugins. The mechanism is the same too: a Go package
with an `init()` that calls a registry function.

> **Illustrative, not yet copy-pasteable from a customer repo.** As with
> the source-plugin example, the Go below imports `internal/` packages
> that Go will not let a package outside the CLI module import — it shows
> the interface shape and the `init()` registration pattern, and compiles
> only from inside the CLI module. See §Status. The `.sigcomply.yaml` in
> Step 3 is unaffected.

### Step 1 — Implement `core.Vault`

```go
// .sigcomply/plugins/acme.nfs_vault/vault.go
package acme_nfs_vault

import (
    "context"

    "github.com/sigcomply/sigcomply-cli/internal/core"
)

type Vault struct {
    // … fields holding the NFS mount path, the metadata client, etc.
}

func (v *Vault) Init(ctx context.Context) error                                                { /* … */ return nil }
func (v *Vault) PutEnvelope(ctx context.Context, key string, e *core.Envelope) error           { /* … */ return nil }
func (v *Vault) PutJSON(ctx context.Context, key string, body any) error                       { /* … */ return nil }
func (v *Vault) PutBinary(ctx context.Context, key string, body []byte, meta map[string]string) error { /* … */ return nil }
func (v *Vault) GetBinary(ctx context.Context, key string) ([]byte, error)                     { /* … */ return nil, nil }
func (v *Vault) List(ctx context.Context, prefix string) ([]string, error)                     { /* … */ return nil, nil }

var _ core.Vault = (*Vault)(nil)
```

### Step 2 — Register the backend

```go
// .sigcomply/plugins/acme.nfs_vault/register.go
package acme_nfs_vault

import (
    "context"

    "github.com/sigcomply/sigcomply-cli/internal/core"
    "github.com/sigcomply/sigcomply-cli/internal/spec"
    "github.com/sigcomply/sigcomply-cli/internal/vault"
)

func init() {
    vault.RegisterBackend("acme.nfs", build)
}

func build(ctx context.Context, cfg *spec.VaultConfig) (core.Vault, error) {
    v := &Vault{ /* read fields from cfg */ }
    if err := v.Init(ctx); err != nil {
        return nil, err
    }
    return v, nil
}
```

### Step 3 — Configure the project

```yaml
# .sigcomply.yaml (excerpt)
vault:
  backend: acme.nfs        # the registered ID
  path: /mnt/sigcomply     # backend-specific fields read from VaultConfig
```

### Step 4 — Build and run

```bash
sigcomply build              # generates the wrapper, blank-imports
                             # acme.nfs_vault, runs `go build`
./bin/sigcomply check
```

`vault.FromConfig` looks up `"acme.nfs"` in the registry and calls
`build`. The collector, persistence, and submitter layers write to it
the same way they'd write to S3 or local — no other changes anywhere.

**The substitutability claim.** A SOC 2 customer and an ISO 27001
customer can both use `acme.nfs` with zero policy changes between
them. A customer can switch from `s3` to `acme.nfs` by editing two
lines in `.sigcomply.yaml`. The CLI's writing flow is identical
regardless.

---

## Custom manual-evidence backends

Worked example: AcmeCorp's manual evidence (signed access reviews,
training certificates) lives on a private SFTP server, not in S3.
AcmeCorp authors a custom manual-evidence backend.

This is **Axis A** of the three plugin axes (see
[`00-three-plugin-axes.md`](00-three-plugin-axes.md) §Axis A). The
mechanism mirrors Axes B and C exactly: implement an interface, call a
registry function from `init()`.

> **Illustrative, not yet copy-pasteable from a customer repo.** As with
> the source-plugin example, the Go below imports `internal/` packages
> that Go will not let a package outside the CLI module import — it shows
> the interface shape and the `init()` registration pattern, and compiles
> only from inside the CLI module. See §Status. The `.sigcomply.yaml` in
> Step 3 is unaffected.

### Step 1 — Implement `manual.Reader`

```go
// .sigcomply/plugins/acme.sftp_manual/reader.go
package acme_sftp_manual

import (
    "context"
    "time"

    "github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

type Reader struct {
    // … SFTP client, base path, credentials reference, etc.
}

// manual.Reader requires both Get and List.
func (r *Reader) Get(ctx context.Context, key string) ([]byte, time.Time, error) {
    // … fetch over SFTP. Return manual.ErrNotFound if the path
    //    does not exist; other errors are treated as transport
    //    failures by the manual.pdf plugin.
    return nil, time.Time{}, manual.ErrNotFound
}

func (r *Reader) List(ctx context.Context, prefix string) ([]manual.FileInfo, error) {
    // … list every file under prefix, sorted by key. An empty result
    //    is not an error — the caller decides how to handle it.
    return nil, nil
}
```

### Step 2 — Register the backend

```go
// .sigcomply/plugins/acme.sftp_manual/register.go
package acme_sftp_manual

import (
    "fmt"

    "github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

func init() {
    manual.RegisterReader("acme.sftp", build)
}

func build(raw map[string]any) (manual.Reader, string, string, string, error) {
    host, _ := raw["host"].(string)
    if host == "" {
        return nil, "", "", "", fmt.Errorf("manual.pdf.acme.sftp: \"host\" required")
    }
    bucket, _ := raw["bucket"].(string)
    prefix, _ := raw["prefix"].(string)
    if prefix == "" {
        prefix = "manual/"
    }
    return &Reader{ /* … */ }, "sftp", bucket, prefix, nil
}
```

### Step 3 — Configure the project

```yaml
# .sigcomply.yaml (excerpt)
sources:
  manual.pdf:
    backend: acme.sftp        # the registered ID
    host: sftp.acme.internal
    bucket: acme-manual-evidence
    prefix: manual/
```

### Step 4 — Build and run

```bash
sigcomply build
./bin/sigcomply check
```

The `manual.pdf` source resolves the per-evidence URI from the
catalog as before — only the `Reader.Get` call now traverses SFTP
instead of the filesystem. The evaluator, policies, and signing flow
are unchanged.

**The substitutability claim.** Every manual policy in every shipped
framework works with `acme.sftp` immediately. Adding a second
backend (Backblaze, an internal HTTP gateway, etc.) is one more
package — never an edit to the core.

---

## Contributing back upstream

Project-local extensions that have broader value (a new shipped
plugin, a new shipped policy, a new evidence type) can be contributed
to the SigComply CLI repo.

The contribution path:

1. **Fork** the public `sigcomply-cli` repo.
2. **Move** the project-local files into the in-tree locations:
   - `internal/sources/<vendor>/` for source plugins
   - `internal/frameworks/<fw>/policies_*.go` for policies (shipped
     policies are Go `.policy()` builders, not on-disk `policy.yaml`)
   - `internal/evidence_types/schemas/<id>.v<n>.json` for evidence types
     (JSON Schema, embedded via `//go:embed schemas/*.json` — the same
     document as the project-local `.sigcomply/evidence_types/*.json`,
     just embedded rather than read from disk)
3. **Adapt** import paths from the project-local package names to the
   in-tree ones (`internal/sources/...`).
4. **Add** in-tree tests under the same directory. A source plugin must
   ship the full **[testing checklist](04-source-plugins.md#testing-a-source-plugin-checklist)**:
   a `sourcetest` conformance test, sanitized cassettes, a `contracts/`
   spec snapshot with a fixture-vs-spec test, and redaction-clean
   fixtures. The GitHub plugin is the worked example to copy; see
   [`TESTING.md`](../../TESTING.md) and
   [`11-testing-strategy.md`](11-testing-strategy.md).
5. **Register** a new shipped policy through the framework's `.policy()`
   builder list (and, for a manual policy, its `manualSpecs()`).
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
  the derivation (and, for a manual entry's upload folder, the entry's
  cadence selects the window); the derivation algorithm itself is fixed.

These restrictions exist because they're the contracts external
parties (auditors, the cloud, the verification SPA) rely on. Customers
get extensibility everywhere it preserves those contracts.
