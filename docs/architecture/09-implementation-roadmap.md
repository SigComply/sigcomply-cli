# 09 — Implementation Roadmap

The CLI is being rewritten from scratch against this architecture. The
existing tree under `internal/` will be replaced; nothing in the
current code is load-bearing for the v1 design. This document
specifies the order of work, the milestone deliverables, and the
verification steps for each.

This is **not** a migration plan — there is no production user base
yet, so no compatibility window to honor. The product is pre-live.
Work proceeds in dependency order, layer by layer, with verifiable
deliverables at each milestone.

---

## Milestone summary

| M | Name | Scope | Verification |
|---|---|---|---|
| **M0** | Repo reset | Remove old `internal/`, set up new package skeleton matching the layer model. | `go build ./...` succeeds; no symbols from old code remain. |
| **M1** | L1 + L2 — Core types and registries | Stable Go interfaces and the five registries; empty registrations. | Unit tests for each interface; reflection test for `SubmissionPayload`. |
| **M2** | L0 — Spec parsers and validators | YAML/JSON parsers for framework, policy, evidence type, plugin manifest, project config. | Round-trip tests; validation rejects malformed specs. |
| **M3** | L7 — Vault | All four backends (local, S3, GCS, Azure Blob) behind the `Vault` interface. | Integration tests against in-memory + real backends (localstack, fake-gcs-server). |
| **M4** | L3 — Planner | Plan production: bindings resolution, parameter merge, exception resolution, period derivation. | Golden-file tests over a curated set of project configs. |
| **M5** | Envelope + signing | `Envelope` write/read; Ed25519 signing; canonical JSON; verifier. | Sign/verify round-trip; cross-language verification (the SPA's WebCrypto verifier reads CLI-written envelopes). |
| **M6** | v1-alpha walking skeleton | The remaining layers wired end-to-end in a single milestone, narrowed to the minimum that demonstrates the architecture works: L4 collector + L5 evaluator (Rego + Go rule runners; YAML DSL deferred) + L6 aggregator (with privacy reflection test) + L8 submitter (OIDC + `POST /api/v1/runs`) + L9 orchestrator (`sigcomply check`, manifest emission with `file_hashes`); plus the two seed plugins `manual.pdf` and `aws.iam` (with an `API` interface for in-memory test fakes, matching the vault backend pattern); plus a SOC 2 framework skeleton (`framework.go` + `controls.go`) carrying 3 representative policies (one automated consuming `user_record`, one manual consuming a manual-catalog entry, one cross-source unioning multiple slots). | `make test && make lint` green; coverage ≥ 80% per new package; aggregator privacy reflection test passes; `sigcomply check --config testdata/fixture.yaml` runs to completion against a stubbed AWS + local vault, producing a signed `manifest.json` with `file_hashes` that `sign.VerifyManifest` accepts and per-policy `result.json` files matching the 3 sample policies. |

---

## Dependency graph

```
M0 (reset)
  └─ M1 (core types) ──┬─ M2 (specs)
                       ├─ M3 (vault) ──── M5 (envelopes)
                       └─ M4 (planner)

M2 + M3 + M4 + M5 → M6 (v1-alpha walking skeleton, single commit)
```

M6 closes the rewrite arc with the smallest end-to-end implementation
that demonstrates every layer works together. The earlier draft of
this roadmap had a finer-grained M6–M20 (one milestone per layer, one
per plugin, one per framework, plus reporting/init-ci/release
tooling). That finer breakdown is preserved below as the
[**post-M6 work plan**](#post-m6-work-plan); items there are not
required to land before M6 ships but are tracked so contributors
know what's intentionally deferred.

---

## Sequencing notes

### Start at the bottom

L0–L1 must be solid before anything else. Once the core types are
frozen, every higher layer can be built without breaking changes
rippling back. Resist the urge to start with the CLI command (L9) —
it's the easiest layer to write but the hardest to write *correctly*
without the lower layers stabilized.

### The vault before the planner

M3 before M4 because the planner needs to know how to format vault
paths and what the vault expects. Building the planner first risks
producing plans that the vault can't materialize.

### Envelope format frozen at M5

Once envelopes are signed and round-tripped, the format is contractual
with auditors. Subsequent milestones add data flowing through the
format but never modify it. If the format must change, a major
version bump is required.

### M6 is the end-to-end walking skeleton

M6 deliberately bundles every remaining layer (L4 collector, L5
evaluator, L6 aggregator, L8 submitter, L9 orchestrator), two seed
plugins (`manual.pdf` and `aws.iam`), and a tiny SOC 2 policy sample
into a single milestone. The reason: layers below L4 are now stable,
so the *only* risk left is at the seams between layers — and that
risk is best discovered by wiring all of them together against one
real end-to-end fixture rather than landing each layer alone behind
mocks.

Implementation order inside M6 (each step builds on the previous):

1. **L4 collector** with stub plugin emitting canned records.
2. **L5 evaluator** running one trivial Rego rule against those
   records.
3. **L6 aggregator** producing a `SubmissionPayload` from a
   `CheckResult`; privacy reflection test goes live here and must
   pass before M6 can ship.
4. **manual.pdf plugin** with full catalog + path + PDF-mirroring
   flow.
5. **aws.iam plugin** with an `API` interface for in-memory fakes,
   matching the vault backend pattern.
6. **SOC 2 framework skeleton** with `framework.go` + `controls.go`
   + 3 representative policies (one automated, one manual, one
   cross-source).
7. **L8 submitter** with OIDC + `POST /api/v1/runs`; check Rails
   strong params at `../sigcomply/app/controllers/api/v1/runs_controller.rb`.
8. **L9 orchestrator** (`sigcomply check`) wiring it all together,
   including manifest emission (filling `file_hashes` after the run
   completes, signing the manifest, writing it to the vault).
9. **End-to-end test**: `sigcomply check --config testdata/fixture.yaml`
   against a stubbed AWS + local vault produces a signed
   `manifest.json` that `sign.VerifyManifest` accepts and per-policy
   `result.json` files matching the sample policies.

Don't ship in pieces. The single-commit constraint forces an honest
assessment of whether the whole thing actually works — and is how
this rewrite arc ends.

---

## What's in v1-alpha (the artifact at M6)

The closing milestone of this rewrite arc ships a **walking
skeleton**, not a feature-complete v1. The point is to prove every
layer is wired correctly end-to-end against one real fixture; volume
(more policies, more plugins, more frameworks) is additive after that.

In v1-alpha:

- **One framework, demonstration scope: SOC 2 Type II**
  - 3 representative policies (one automated `aws.iam`-consuming,
    one manual catalog entry, one cross-source unioning multiple
    slots)
  - Framework skeleton (`framework.go` + `controls.go`) ready to
    absorb the full policy catalog later
- **Two source plugins**: `manual.pdf` and `aws.iam`
- **All four vault backends** (shipped at M3)
- **Cloud submission** to SigComply Cloud via `POST /api/v1/runs`
- **Reference Go verifier** (the `sign.VerifyEnvelope` /
  `sign.VerifyManifest` primitives shipped at M5)
- **OIDC auth** for GitHub Actions + GitLab CI

What is **explicitly not** in v1-alpha (tracked in the
[post-M6 work plan](#post-m6-work-plan) below):

- The ~300-policy SOC 2 catalog
- ISO 27001 framework
- Plugins beyond `manual.pdf` + `aws.iam`
- `sigcomply build`, `sigcomply report`, `sigcomply init-ci`
- SPA `/verify` rewrite to envelope.v1
- Release automation, install docs, auditor FAQ

v1.0 (feature-complete) is a multi-milestone release stream that
begins after v1-alpha. Patch and minor releases — driven by the
post-M6 work plan — converge on the original v1 vision over time.

---

## Post-M6 work plan

These items were the originally planned M7–M20 of this roadmap.
They are **not** required to land before M6 ships, but they are the
backlog that takes v1-alpha to feature-complete v1. Pull from this
list in priority order driven by user demand and policy coverage
needs; they parallelize once M6's walking skeleton is in place.

| Item | Scope | Verification |
|---|---|---|
| **Full SOC 2 policy catalog** | Port the curated SOC 2 policy set against the new types. ~300 automated policies + ~50 manual catalog entries. | All policies have rules and tests; tests pass. End-to-end run against a fixture vault. |
| **Plugin set v1** | `aws.s3`, `aws.cloudtrail`, `aws.kms`, `aws.rds`, `aws.ec2`, `aws.cloudwatch`, `aws.guardduty`, `aws.config`, `aws.eks`, `gcp.iam`, `gcp.storage`, `gcp.compute`, `gcp.sql`, `github`, `okta`. | Each plugin has manifest, tests, at least one shipped policy consuming it. |
| **YAML DSL transpiler** | The third rule runner alongside Rego and Go. | Round-trip tests; one policy authored in YAML DSL evaluates correctly. |
| **`sigcomply build`** | Project-local Go-extension build wrapper. | Fixture project's custom plugin compiles and runs end-to-end. |
| **ISO 27001 framework skeleton** | Framework spec + control catalog + representative ~30 policies. | One audit period's worth of policies pass tests. |
| **Auditor verification tooling** | Reference verifier (Go + SPA — this is where the SPA's `/verify` finally moves to envelope.v1); `sigcomply report` command (see §`sigcomply report` below) for snapshot views of the vault: latest-wins period roll-up, exception register, integrity verification, audit-ready PDF/CSV exports. **Time-series analytics (drift detection, deviation timelines, continuous-monitoring alerts) are explicitly out of scope for the free CLI — they live in the paid SigComply Cloud / Rails app.** | Fresh checkout + only the vault + the verifier can reproduce a policy's result. `sigcomply report --period 2026-Q1 --format pdf` produces a deterministic audit-ready snapshot. |
| **CI integration & scaffolding** | `sigcomply init-ci --framework <fw> --ci <github\|gitlab>` scaffolds the cadence-aligned workflow set (`compliance-on-push.yml`, `compliance-daily.yml`, `compliance-weekly.yml`, `compliance-monthly.yml`, `compliance-quarterly.yml`, `compliance-annual.yml`). Reusable composite action (`SigComply/sigcomply-cli/.github/actions/check@v1`). GitLab CI include template. The `--cadence` and `--on-push` filter flags on `sigcomply check`. | E2E test repos: one GitHub-Actions project + one GitLab-CI project each scaffolded via `init-ci`; nightly + on-push workflows produce expected vault contents. |
| **v1 release** | Tagged release; release notes; install docs; auditor-facing FAQ. | Public install + first community contribution merged. |

The dependency edges that mattered in the finer-grained plan still
apply: plugins block their consuming policies; the SPA verifier
rewrite blocks public-facing auditor messaging; `sigcomply build`
unblocks community-contributed custom plugins. They just don't all
need to land before M6 ships.

---

## What's deferred to v2

- **HIPAA framework.** The control catalog exists in public regulation
  but the policy set is non-trivial; defer to v2 with proper
  privacy-rule expertise involvement.
- **Multi-scope** (first-class `scope_id` on evidence records,
  multi-account runs in one invocation). v1 customers achieve this by
  running multiple CLI invocations or using bracketed plugin instances.
- **Continuous-monitoring rollup analytics.** Period roll-up is
  derivable from vault contents; v1 leaves this to dashboards.
  Built-in roll-up analytics in `sigcomply report` are a v2
  feature.
- **WASM plugin support.** All v1 plugins compile in. WASM plugins
  (sandboxed, language-agnostic) are evaluated for v2 if there's
  demand.
- **Cross-source joins beyond unioning into one slot.** The slot
  union model handles most cross-source cases; explicit join
  primitives (e.g. "match records in slot A to records in slot B by a
  key") may be added in v2.

---

## Open architectural questions to revisit

These were settled provisionally for v1. Worth revisiting at the v1 →
v2 transition based on real-world use.

| Question | v1 answer | Re-evaluate when |
|---|---|---|
| Per-policy collection (no shared fetches) | Yes (KISS) | First report of cost or rate-limit pain. |
| In-tree plugins only | Yes (security) | First credible request for hot-pluggable plugins from a customer with security review capacity. |
| Single-scope per invocation | Yes | First customer with >5 accounts to scan. |
| Materialized period state cache | No (always derived) | First measurable dashboard latency issue. |
| Rego as the default rule language | Yes | First survey of community contributors showing Rego friction outweighs auditability gains. |
| Schema validation drops malformed records silently | Drops <5%; errors >5% | First incident of legitimate records being dropped due to plugin bug. |

---

## Verification at each milestone

A milestone is complete when:

1. **All unit tests pass.** Coverage for new code ≥ 80% lines.
2. **Integration tests pass.** Each new component has at least one
   integration test against a real backend or stub.
3. **The privacy reflection test passes** (after M6, when the aggregator goes live).
4. **The verifier round-trip works** (after M5).
5. **Documentation is updated.** Specifically: `ARCHITECTURE.md` map,
   the relevant doc in `docs/architecture/`, and any user-facing
   docs that change behavior.
6. **Linter passes.** No untracked TODOs, no dead code, no commented-
   out blocks.

A milestone is **not** complete just because the code compiles or one
hand-run command produces the expected output.

---

## `sigcomply report` (post-M6 design detail)

The `report` subcommand produces **snapshot views** of the vault. It
reads only — no collection, no evaluation, no cloud submission, no
time-series analytics. It is the free CLI's auditor-facing tool.

**Inputs**

```
sigcomply report \
  --vault s3://acme-evidence/sigcomply/ \
  --framework soc2 \
  --period 2026-Q1 \
  --format pdf|csv|json|text \
  --view latest|exceptions|integrity \
  --out ./reports/soc2-q1-2026.pdf
```

**Views (free CLI)**

| `--view` | Content | Primary auditor question answered |
|---|---|---|
| `latest` (default) | Per-control + per-policy roll-up (latest-wins) for the period. Status, severity, last-evaluated, exception reference if waived. | "What was the compliance state at period close?" |
| `exceptions` | Centralized register of every waiver / NA declaration active during the period. Approver, approval date, expiration, scope, reason. Pulled from each run's `manifest.exceptions_applied`. | "What was waived, by whom, and why?" |
| `integrity` | Run-by-run integrity verification: each run's manifest signature checked, each `file_hashes` entry recomputed and compared. | "Has any evidence been modified since written?" |

**Not provided by the free CLI**

Time-series analytics — deviation timelines, drift detection,
continuous-monitoring narratives, alerting on emerging failures,
cross-period comparison — are **paid features** delivered by the
SigComply Cloud / Rails app. The vault preserves all the raw data
needed to compute them; the analytical layer is the paid product's
value-add. See [`06-aggregation.md`](06-aggregation.md) §What the
paid Rails app does with the submitted data.

A customer who needs these views and chooses not to subscribe can
either self-host the Rails app (if offered) or query the vault
directly with custom tooling.

**Formats**

- `pdf` — deterministic, paginated, includes the report header (project,
  framework, period, generation time, CLI version) and the chosen view.
- `csv` — one row per policy (latest-state view) or one row per
  exception (exceptions view); plays well with auditor spreadsheets.
- `json` — structured for downstream tooling; matches the dashboard's
  internal schema.
- `text` — plain stdout, for terminal use.

**Determinism**

`sigcomply report` is fully deterministic given the same vault state.
A PDF generated today and a PDF generated next year (against the same
period folder) produce byte-identical output modulo the
`generated_at` timestamp in the header.

**No cloud dependency**

`report` runs entirely against the customer's vault. It does not call
the SigComply cloud, requires no OIDC, and works offline. This is the
auditor's primary tool when SigComply Cloud is unavailable or unused.

---

## Release cadence after v1

- **Patch releases (1.x.y)**: bug fixes, additional plugins, additional
  policies. Aggregation contract frozen.
- **Minor releases (1.x)**: new evidence types (additive),
  new framework features (additive), new commands. Aggregation
  contract frozen.
- **Major releases (2.0, 3.0, ...)**: aggregation contract changes,
  vault layout changes, interface breaks. Always with a long
  coexistence window and a written migration guide.

Vault backwards-compatibility is a 5-year minimum: any 1.x or 2.x CLI
must read a vault written by any 1.x CLI. Auditors keep evidence for
the duration of their audit retention windows (typically 7 years for
SOC 2 / ISO 27001); the CLI honors that.
