# Common Task Recipes

> **When to read**: First time doing a common task (adding sources,
> policies, evidence types, frameworks, storage backends).

> **Architecture note**: Policies are **Go-native**, not `.rego` files.
> There are no `.rego` policy files in the tree. The three coupling points
> are the **source plugin** (emits evidence types), the **evidence-type
> registry** (embedded JSON Schemas — the sole mediator), and the
> **policy** (accepts evidence types). Sources and policies never name
> each other. See [ARCHITECTURE.md](../../ARCHITECTURE.md) and
> [04a-evidence-type-registry.md](../architecture/04a-evidence-type-registry.md).

---

## Adding a New Source Plugin (automated collector)

A source plugin produces `core.EvidenceRecord`s for the evidence types it
declares via `Emits()`. It never references a policy. Live example:
`internal/sources/okta/`.

1. **Create the package** under `internal/sources/<service>/` (cloud
   providers nest by service, e.g. `internal/sources/aws/iam/`).

2. **Implement `core.SourcePlugin`** (`internal/core/source.go`):
   ```go
   ID() string                                                  // unique source id, e.g. "okta"
   Emits() []string                                             // evidence type IDs it can produce
   Init(ctx context.Context, cfg map[string]any) error
   Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error)
   ```
   In `Collect`, use `req.Accepts(typeID)` to decide which emitted types
   the slot actually wants, build one `core.EvidenceRecord` per resource,
   and **sort records by `ID` lexicographically** before returning (keeps
   envelope bytes stable across runs):
   ```go
   records = append(records, core.EvidenceRecord{
       Type:        EvidenceTypeDirectoryUser, // must be a registered evidence type
       ID:          u.ID,                      // unique within the source
       IdentityKey: u.Email,                   // set when the type has cross-source identity
       Payload:     body,                       // json.Marshal of the canonical payload shape
       SourceID:    SourceID,
       CollectedAt: now,
   })
   ```
   The payload must conform to the evidence type's JSON Schema — the
   collector validates every record (full draft-07: enum/format/min/
   nested all enforced) before signing; the first non-conforming record
   fails the binding and tags the policy `error` (exit 3). Do the full
   vendor→canonical translation here; **never** leave a field null
   expecting the policy to
   guard it (see the null-trap antipattern in the CLI CLAUDE.md).

3. **Register the factory** in a `factory.go` `init()`:
   ```go
   func init() { sources.RegisterFactory(SourceID, build) }

   func build(ctx context.Context, env sources.Env) (core.SourcePlugin, error) {
       // pull config via sources.StringOpt(env.Config, "..."), env vars, etc.
       return NewFromConfig(ctx, ...)
   }
   ```

4. **Blank-import it** in `internal/sources/builtin/builtin.go` (one
   line). `cmd/sigcomply` needs no other changes.

5. **Write the layered tests** — not just unit tests. A new plugin ships
   L0/L1 unit tests (fake API client, see `okta_test.go`) **plus** an L2
   `*_conformance_test.go` replaying a scrubbed go-vcr cassette through
   `sourcetest.RunConformance`, **plus** a `contracts/<provider>/…`
   snapshot for L3 drift. Follow the canonical **Testing a source plugin
   (checklist)** in
   [`docs/architecture/04-source-plugins.md`](../architecture/04-source-plugins.md);
   `CONTRIBUTING.md` gates it in review.

6. **No policy changes** are needed if the plugin emits an existing
   evidence type — every policy already accepting that type can now bind
   to this source (the substitutability property).

---

## Adding a New Evidence Type

Only needed when a source emits a shape no existing type covers. Design
the schema **top-down from the semantic concept**, not from one vendor's
API — every field must be satisfiable by all plausible sources without
null placeholders.

1. **Add a JSON Schema** at
   `internal/evidence_types/schemas/<type>.v<N>.json` (draft-07). Follow
   the existing files (e.g. `directory_user.v1.json`): set `title`,
   `version`, a cross-vendor `description`, and a minimal `required` list.
   Schemas are embedded via `go:embed schemas/*.json` and auto-registered
   by `evidence_types.Register` — no Go wiring needed.

2. **Version, don't mutate.** A breaking field change is a new
   `<type>.v<N+1>.json`; policies opt in by listing the new type ID in
   `accepts:`. v2-only fields stay out of v1 consumers.

3. Reference the new type ID from a source's `Emits()` and a policy
   slot's `accepts:`.

---

## Adding a New Automated Policy

Policies are Go values built with the compact builders in each
framework's `builders.go`. ~95% of checks fit the **`pass_when` DSL** —
reach for the `rule:` escape hatch only for logic the DSL can't express.

1. **Pick the file** by control family: append to the relevant
   `internal/frameworks/<fw>/policies_*.go` slice (e.g.
   `policies_cc6.go`).

2. **For a `pass_when` policy**, add an `autoPolicy{...}.policy()`:
   ```go
   autoPolicy{
       id: "soc2.cc6.1.mfa_enforced_all_users", control: "CC6.1",
       severity: core.SeverityCritical, category: "access", cadence: "daily",
       accepts: directoryUserTypes,           // evidence type IDs this slot consumes
       desc:    "All directory users have MFA enabled.",
       rem:     "Enable MFA for every user in each bound identity source.",
       clause:  all(leaf("payload.mfa_enabled", "eq", true),
                    "user {{.payload.display_name}} does not have MFA enabled"),
   }.policy(),
   ```
   Clause builders (in `builders.go`): `all` / `none` / `anyRec` (over
   every record), and `allWhere` / `noneWhere` / `anyWhere` (over records
   matching a filter). Conditions: `leaf(field, op, value)`, combined with
   `allOf` / `anyOf`. `evidence_mode` is set to `automated` by the
   builder. There is **no `source:` field** — a policy never names a
   plugin.

3. **For a `rule:` escape-hatch policy** (e.g. substring matching the DSL
   lacks), register a `core.Rule` (see `rules.go` `alarmRules()` using
   `evaluator.GoRule`, or an inline OPA module via
   `evaluator.NewRegoRule`) and reference it with
   `rulePolicy{... ruleRef: "rules.soc2.<name>.v1"}.policy()`. Add the
   rule to the framework's `Rules()`.

4. **Register happens automatically** — `Policies()` aggregates every
   slice, and `Register` walks it. Just make sure your new slice is
   appended in the framework's `Policies()` function.

5. The framework tests enforce: unique IDs, `soc2.`/`iso27001.` namespace,
   non-empty `evidence_mode`, every `accepts:` type is registered, every
   `ruleRef` resolves. Run `make test`.

---

## Adding a New Manual Evidence Policy

Manual policies check that customer-supplied files exist in the
catalog-resolved folder `{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/`
within the temporal window. The CLI converts images to PDF, merges, and
runs byte-level sanity checks — it never reads PDF *contents*.

1. **Add a `manualPolicy{...}` to `manualSpecs()`** in
   `internal/frameworks/<fw>/policies_manual.go` (the single authoring
   list — `manualPolicies()` and the catalog export both derive from it):
   ```go
   {
       id: "soc2.cc1.1.security_awareness_training", control: "CC1.1",
       cadence: "annual", catalog: "security_awareness_training",
       desc: "Employees complete security awareness training.",
       rem:  "Upload evidence of completed security awareness training.",
       tsc:  "security", // SOC 2 only
   },
   ```
   The builder sets `evidence_mode: manual` and `CatalogEntry` from
   `catalog`. There is no `pass_when`/`rule` — the universal PDF-presence
   check (`internal/evaluator/manual_check.go`) runs for all manual
   policies regardless of the presentation metadata below.

2. **Presentation metadata for the Evidence SPA (optional).** Each spec
   carries descriptive fields that feed `sigcomply evidence catalog`
   (consumed by the SPA) but that the evaluator **ignores**. They default:
   `etype` → `document_upload`, `name` → `TitleFromID(catalog)`,
   `severity` → `medium`. Set `etype: manualcatalog.TypeDeclaration` with a
   `declarationText`, or `etype: manualcatalog.TypeChecklist` with `items`,
   only for entries the SPA should render as a clickable form.
   `document_upload` entries are produced externally and the SPA filters
   them out. See `internal/manualcatalog` for the exported shape (it
   mirrors `sigcomply-evidence-spa/src/types/catalog.ts`).

3. **No separate catalog file.** Both `ManualCatalog()` (runtime path
   resolution → `manual.CatalogEntry`) and `ManualCatalogExport()`
   (SPA-facing → `manualcatalog.Catalog`) in `framework.go` derive from
   `manualSpecs()`. Adding the spec is enough — the framework test asserts
   every manual policy's `CatalogEntry` resolves, and the command test
   asserts the export satisfies the SPA contract. If you change the export
   shape, update `sigcomply-evidence-spa/src/types/catalog.ts` too.

---

## Adding a New Compliance Framework

Each framework is a self-contained package that self-registers via a
factory. Models: `internal/frameworks/soc2/` and `iso27001/`.

1. **Create `internal/frameworks/<fw>/`** with:
   - `framework.go` — the `core.Framework` impl (`ID`, `Version`,
     `Controls`, `Policies`), a `Policies()` aggregator, a `Register(set
     *registry.Set)` that registers the framework + rules + policies, and
     a `ManualCatalog()` if it has manual policies.
   - `controls.go` — the control catalog (`[]core.Control`).
   - `builders.go` — the `autoPolicy`/`rulePolicy`/`manualPolicy` shapes
     and clause helpers (copy from an existing framework; they're
     per-framework so control-ref wiring stays local).
   - `policies_*.go` — the policy slices.

2. **Self-register** in `framework.go` `init()`:
   ```go
   func init() {
       frameworks.RegisterFactory(FrameworkID, frameworks.Factory{
           Register:      Register,
           ManualCatalog: ManualCatalog, // omit if no manual policies
       })
   }
   ```

3. **Blank-import** the package in
   `internal/frameworks/builtin/builtin.go` (one line). Commands resolve
   frameworks by ID from the registry — no hardcoded switch.

4. **Update** `README.md` and `docs/configuration.md` framework lists.
   (Note: HIPAA remains a stub string only — do not add a `hipaa/`
   package until policies exist.)

---

## Adding a New Storage (Vault) Backend

Vault backends are symmetric with manual-evidence readers and use the
same self-registering-factory pattern. In-tree backends: `local`, `s3`,
`gcs`, `azureblob` under `internal/vault/`.

1. **Implement `core.Vault`** (`internal/core/vault.go`): `Init`,
   `PutEnvelope`, `PutJSON`, `PutBinary`, `GetBinary`, `List`.

2. **Register** in a `register.go` `init()`:
   ```go
   func init() { vault.RegisterBackend("<id>", build) }

   func build(ctx context.Context, cfg *spec.VaultConfig) (core.Vault, error) {
       v := New(cfg.Path /* or cfg.Bucket, cfg.Endpoint, … */)
       if err := v.Init(ctx); err != nil { return nil, err }
       return v, nil
   }
   ```

3. **Blank-import** the package in `internal/vault/builtin/builtin.go`.

4. **Write integration tests** (see `internal/vault/vaulttest/`). Write
   evidence using the period-first run layout — see the
   [storage layout in CLAUDE.md](../../CLAUDE.md) (`{framework}/{period_id}/
   run_{timestamp}_{run_id_short}/policies/{policy_id}/...`, basic ISO 8601
   timestamps, no colons).

---

## CI/CD Workflows

### `sigcomply init-ci` (wired) — the supported path
`init-ci` scaffolds **standalone, per-cadence** workflow files calibrated
to a framework's cadence distribution. For GitHub it writes
`.github/workflows/compliance-{daily,weekly,monthly,quarterly,annual,on-push}.yml`,
each of which downloads the CLI binary via `curl` from GitHub Releases and
runs `sigcomply check --cadence <X>` (or `--on-push`); it grants
`id-token: write` for OIDC. There is **no** reusable `workflow_call`
workflow and no composite action — each scaffolded file is self-contained.
For GitLab, `init-ci` uses the template at
`cmd/sigcomply/templates/gitlab/.gitlab-ci.yml`, which gates each cadence
with `rules: if $CI_PIPELINE_SOURCE == "schedule" && $CADENCE == ...`.

### Copy-paste examples
- GitHub: `examples/github-actions/{basic,multi-environment}.yml`
- GitLab: `examples/gitlab-ci.yml` (a first-class packaged GitLab CI
  component is not yet available). Use GitLab's OIDC token via the
  `id_tokens:` block; install the CLI; run `sigcomply check`; honor exit
  codes (0 pass / 1 violations / 2 error / 3 config).

### `sigcomply build` (wired)
`build` compiles a project-tailored binary that includes `.sigcomply/` Go
extensions (project-local sources, policies, evidence types, backends).
