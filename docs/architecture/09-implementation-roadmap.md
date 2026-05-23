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
| **M1** | L1 + L2 — Core types and registries | Stable Go interfaces and the four registries; empty registrations. | Unit tests for each interface; reflection test for `SubmissionPayload`. |
| **M2** | L0 — Spec parsers and validators | YAML/JSON parsers for framework, policy, evidence type, plugin manifest, project config. | Round-trip tests; validation rejects malformed specs. |
| **M3** | L7 — Vault | All four backends (local, S3, GCS, Azure Blob) behind the `Vault` interface. | Integration tests against in-memory + real backends (localstack, fake-gcs-server). |
| **M4** | L3 — Planner | Plan production: bindings resolution, parameter merge, exception resolution, period derivation. | Golden-file tests over a curated set of project configs. |
| **M5** | Envelope + signing | `Envelope` write/read; Ed25519 signing; canonical JSON; verifier. | Sign/verify round-trip; cross-language verification (the SPA's WebCrypto verifier reads CLI-written envelopes). |
| **M6** | L4 — Collector skeleton | Per-policy fetch loop; envelope assembly; schema validation; error routing. | Tests with a stub plugin that emits canned records. |
| **M7** | First plugin: `manual.pdf` | Full implementation including catalog reading, path resolution, PDF mirroring, manifest emission. | Integration test with files in a local backend; manifest verifies. |
| **M8** | First plugin: `aws.iam` | Full IAM coverage (users, roles, policies, access keys); `user_record` emission. | Live test against an AWS test account; records pass schema validation. |
| **M9** | L5 — Evaluator | Rule registry; Rego runner; Go rule runner; YAML DSL transpiler. | One end-to-end policy (`soc2.cc6.1.mfa_enforced`) evaluates correctly. |
| **M10** | L6 — Aggregator | `SubmissionPayload` construction; message generation; structural privacy test. | Reflection-based privacy test passes; payload diff vs vault summary shows correct information loss. |
| **M11** | L8 — Submitter | OIDC token acquisition (GitHub + GitLab); HTTP POST; failure handling. | Live test against a stub cloud receiver. |
| **M12** | L9 — Orchestrator | The `sigcomply check` command; flag parsing; CI auto-detection; output formatters. | `sigcomply check --dry-run` works end-to-end against a fixture project. |
| **M13** | SOC 2 framework — automated policies | Port the curated SOC 2 policy set against the new types. ~300 policies. | All policies have rules and tests; tests pass. |
| **M14** | SOC 2 framework — manual catalog | Manual catalog entries; bindings; tests for the `manual.pdf` integration with each entry. | End-to-end run against a fixture vault. |
| **M15** | Plugin set v1 | Remaining plugins for v1 launch: `aws.s3`, `aws.cloudtrail`, `aws.kms`, `aws.rds`, `aws.ec2`, `aws.cloudwatch`, `aws.guardduty`, `aws.config`, `aws.eks`, `gcp.iam`, `gcp.storage`, `gcp.compute`, `gcp.sql`, `github`, `okta`. | Each plugin has manifest, tests, at least one shipped policy consuming it. |
| **M16** | `sigcomply build` for project-local Go extensions | The build wrapper; smoke test with a custom plugin + custom policy. | A fixture project's custom plugin compiles and runs end-to-end. |
| **M17** | ISO 27001 framework skeleton | Framework spec + control catalog + a representative ~30 policies. | One full audit period's worth of policies pass tests. |
| **M18** | Auditor verification tooling | Reference verifier (Go and SPA); `sigcomply report` command (see §sigcomply report below) for snapshot views of the vault: latest-wins period roll-up, exception register, integrity verification, audit-ready PDF/CSV exports of those snapshots. **Time-series analytics (drift detection, deviation timelines, continuous-monitoring alerts) are explicitly out of scope for the free CLI — they live in the paid SigComply Cloud / Rails app.** | Fresh checkout + only the vault + the verifier can reproduce a policy's result. `sigcomply report --period 2026-Q1 --format pdf` produces a deterministic audit-ready snapshot. |
| **M19** | CI integration & scaffolding | `sigcomply init-ci --framework <fw> --ci <github|gitlab>` scaffolds the cadence-aligned workflow set (`compliance-on-push.yml`, `compliance-daily.yml`, `compliance-weekly.yml`, `compliance-monthly.yml`, `compliance-quarterly.yml`, `compliance-annual.yml`). Reusable composite action (`SigComply/sigcomply-cli/.github/actions/check@v1`). GitLab CI include template. The `--cadence` and `--on-push` filter flags on `sigcomply check`. | E2E test repos: one GitHub-Actions project + one GitLab-CI project each scaffolded via `init-ci`; nightly + on-push workflows produce expected vault contents. |
| **M20** | v1 release | Tagged release; release notes; install docs; auditor-facing FAQ. | Public install + first community contribution merged. |

---

## Dependency graph

```
M0 (reset)
  └─ M1 (core types) ──┬─ M2 (specs)
                       ├─ M3 (vault) ──── M5 (envelopes)
                       └─ M4 (planner)

M2 + M3 + M4 + M5 → M6 (collector)
M6 → M7 (manual.pdf) → M14 (SOC 2 manual)
M6 → M8 (aws.iam)   → M13 (SOC 2 automated)
M6 → M15 (other plugins)

M2 → M9 (evaluator) ────┐
                        ├─ depends on M6 + M9
                        ▼
M10 (aggregator) ─→ M11 (submitter) ─→ M12 (orchestrator)
                                          ▼
                                    M16 (build wrapper)
                                          ▼
                                    M17 (ISO 27001)
                                          ▼
                                    M18 (verifier)
                                          ▼
                                    M19 (CI integration)
                                          ▼
                                    M20 (release)
```

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

### Aggregation last among the core layers

L6 (M10) is the most consequential boundary and should be implemented
when L5 (M9) produces real `PolicyResult`s. Implementing the
aggregator early risks shaping the privacy contract around toy inputs.

### Plugins parallelize after M6

Once the collector skeleton (M6) is done, plugins can be built in
parallel. Manual evidence and AWS IAM go first because the SOC 2
framework's most foundational policies depend on them; remaining
plugins arrive in priority order driven by shipped policy coverage.

### Don't ship the framework before the engine

M13 (SOC 2 policies) cannot ship before M9 (evaluator) is solid. Each
policy needs its rule tested end-to-end. Shipping policies that depend
on yet-unbuilt rule features creates phantom coverage.

### Auditor tooling late but before release

M18 must be done before M20. Selling "evidence without access" without
the verifier is selling a half-finished promise. The verifier is part
of the product, not an afterthought.

---

## What's in v1 (the release at M20)

- One framework production-ready: **SOC 2 Type II**
  - ~300 automated policies across AWS, GCP, GitHub
  - ~50 manual catalog entries
  - Full control coverage
- One framework as proof of concept: **ISO 27001**
  - ~30 policies (a representative subset)
- 14 shipped source plugins
- All four vault backends
- GitHub Actions and GitLab CI integrations
- Reference verifier (Go + browser)
- Project-local extensions (custom policies, plugins, evidence types)
- Cloud submission to SigComply Cloud
- Self-hosted dashboard support (via `cloud.base_url` override)

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
3. **The privacy reflection test passes** (after M10).
4. **The verifier round-trip works** (after M5).
5. **Documentation is updated.** Specifically: `ARCHITECTURE.md` map,
   the relevant doc in `docs/architecture/`, and any user-facing
   docs that change behavior.
6. **Linter passes.** No untracked TODOs, no dead code, no commented-
   out blocks.

A milestone is **not** complete just because the code compiles or one
hand-run command produces the expected output.

---

## `sigcomply report` (M18 detail)

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
