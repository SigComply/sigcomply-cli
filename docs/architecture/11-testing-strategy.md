# 11 — Testing Strategy

This document is the canonical reference for **how SigComply tests its
evidence-source API integrations**. The CLI integrates many vendor APIs
(GitHub, GitLab, AWS, GCP, Azure, Okta, and later others), and two
requirements pull against each other:

- **Robustness** — when a vendor API changes shape or behavior, *a test
  must fail* and tell us the CLI is broken.
- **Cost** — we cannot afford to spin up paid cloud resources on every
  CI run.

The answer is a **layered strategy** with a clear **repo split**: the
per-PR path is fast, free, and deterministic, and the "did the vendor
change?" question is answered by a separate, mostly-free, scheduled
path.

> **Status:** target architecture. The layers below are being rolled out
> per-plugin; not every source has every layer yet. The
> [add-a-source-plugin testing checklist](04-source-plugins.md) and
> [extensibility doc](07-extensibility.md) state what a *new* plugin must
> ship today.

---

## 1. The one model: regression tests vs. drift detectors

Every test in this codebase is exactly one of two things, and you must
never confuse them:

- A **regression test** checks *your code against a frozen contract*. It
  is fast and free, but **blind to API changes** — if the vendor moves,
  the frozen contract moves with your code and the test stays green.
- A **drift detector** checks *the contract against reality*. It is the
  **only** thing that catches an upstream API change.

**Golden rule:** never let a test give *false confidence*. A green
per-PR suite must be backed by a drift detector that is *allowed to fail
loudly* when an upstream API changes.

---

## 2. The six layers

| Layer | What it checks | Catches an API change? | Cost | Cadence | Repo |
|------|----------------|------------------------|------|---------|------|
| **L0 — Invariants** | structural/privacy guarantees (e.g. no freeform field on the cloud wire type) | n/a (guards *us*) | $0 | per-PR | **CLI** |
| **L1 — Mapping unit** | fake API response → mapped `EvidenceRecord`; every schema field populated; deterministic | No (by design) | $0 | per-PR | **CLI** |
| **L2 — Contract/fixture** | recorded cassette replayed **through the real SDK deserializer**; cassette validated against the **vendor's published spec** | Partially (on re-record / spec-snapshot update) | $0 | per-PR | **CLI** |
| **L3 — Spec-diff drift** | diff the vendor's own machine-readable API model on a schedule | **Yes — shape/contract changes**, for $0 | $0 | scheduled (weekly) | **CLI** |
| **L4a — SaaS/Entra live** | real calls to **free** accounts (GitHub/GitLab/Okta/Entra) | **Yes — incl. behavioral** | ~$0 | scheduled (nightly) | **CLI** (`//go:build live`) |
| **L4b — Cloud + pipeline E2E** | provision minimal real cloud infra, run the released binary end-to-end, **assert expected per-policy outcomes** | **Yes — incl. behavioral + integration** | bounded (~$1–5/run) | scheduled / manual | **E2E repos** |

**Why L3 is the centerpiece.** AWS (Smithy models), Azure
(`azure-rest-api-specs` OpenAPI), GCP (Discovery Documents), GitHub
(`github/rest-api-description`), and Okta (OpenAPI) all publish the
machine-readable model their own SDK is generated from. Diffing it on a
schedule catches contract changes with **zero accounts and zero live
calls**. GitLab's published spec is thin → for GitLab we lean on L4a
cassette re-record diffs instead.

---

## 3. Repo split — which tests go where, and why

**`sigcomply-cli/` owns L0, L1, L2, L3, L4a.** These are Go tests (or
scheduled Go tooling) that live next to the plugin code, need no
infrastructure provisioning, and gate every CLI change. L4a (SaaS/Entra)
lives here because those vendors are *free* and need only a token — no
Terraform, no teardown.

**The E2E repos own L4b only.** L4b needs real provisioned cloud
infrastructure (apply → read → assert → destroy), credential/OIDC
plumbing per CI platform, and a sweeper to garbage-collect leaks. That
machinery already lives in the E2E repos. L4b validates the **released
binary end-to-end**, which is a different purpose than CLI unit/contract
tests.

```
                      ┌─────────────────────────── sigcomply-cli/ ───────────────────────────┐
   per-PR  ──────────▶│ L0 invariants · L1 mapping · L2 cassette+spec-conformance             │
   scheduled (weekly) │ L3 spec-diff drift  → alert-only (opens issue)                        │
   scheduled (nightly)│ L4a SaaS/Entra live (free accounts, //go:build live) + cassette re-rec│
                      └───────────────────────────────────────────────────────────────────────┘
                                                   │ releases binary
                                                   ▼
                      ┌──────── E2E repos (github / gitlab) ────────┐
   scheduled / manual │ L4b provision minimal cloud → run binary →  │
                      │     ASSERT expected outcomes → destroy →    │
                      │     sweep leaks                             │
                      └─────────────────────────────────────────────┘
```

**Boundary rules:**

- Cloud per-plugin *contract* verification (AWS/GCP/Azure) is done via
  **L2 cassettes** in the CLI repo; the cassettes are **recorded** during
  an L4b run (or a one-off maintainer record) so the two layers share
  fixtures.
- The CLI repo never provisions cloud resources in CI. The E2E repos
  never contain Go unit tests of mappers.

---

## 4. Cross-cutting conventions

Decided once; obeyed everywhere.

1. **Cassette location.**
   `internal/sources/<provider>/<service>/testdata/cassettes/*.yaml`
   (go-vcr v4). One cassette per scenario — e.g.
   `list_buckets_encrypted.yaml`, `list_buckets_unencrypted.yaml`.
2. **Vendor spec snapshots ("contracts").**
   `contracts/<provider>/<service>@<api-version>.json`. Serves **both**
   L2 (validate cassettes against the spec) and L3 (diff over time). Pin
   only the services we actually use.
3. **Redaction (mandatory — privacy invariant).** The go-vcr
   `BeforeSaveHook` scrubs `Authorization`, tokens, ARNs, account IDs,
   emails, and usernames to stable placeholders. A CI gate greps
   `testdata/` + `contracts/` for `AKIA…`, 12-digit account IDs,
   `@`-emails, and bearer tokens, and fails the build on a hit. A fixture
   that leaks identity violates the non-custodial architecture, not just
   a style rule.
4. **Build tags.** Live tests are `//go:build live` and additionally
   skip if the required env (token) is absent (`TF_ACC`-style). They are
   excluded from the per-PR suite and from the coverage gate.
5. **Coverage.** Keep the existing **80% floor** (`test.yml`). L2
   cassette replay *raises* coverage (the real deserialize paths run).
   Live/build-tagged code is excluded from the gate.
6. **Shared harness.** All source-plugin tests run through
   `internal/sources/sourcetest/` — schema conformance + field
   completeness + determinism + metadata checks. Adding a plugin must not
   require re-inventing test scaffolding.
7. **Naming for live/E2E resources.** Fixed prefix `sigcomply-e2e-` so
   sweepers can find and delete leaks safely.
8. **Drift jobs are alert-only.** They open/update a GitHub issue; they
   do **not** block PRs (they run on a schedule, not on PRs).

---

## 5. Tooling reference

| Concern | Tool | Notes |
|--------|------|-------|
| HTTP record/replay | `dnaeon/go-vcr` v4 | transport seam for L1/L2 |
| AWS test seam | fake `HTTPClient` via `config.WithHTTPClient` (runs the real deserializer); interface stubs for pure logic | per-protocol matcher needed for query/json APIs (IAM/EC2/STS) |
| GCP test seam | `option.WithHTTPClient` + `option.WithoutAuthentication` → httptest / go-vcr | REST/JSON clients |
| Azure test seam | `arm.ClientOptions{Transport: ...}`; fake `azcore.TokenCredential` | swap the transport |
| Spec-diff (OpenAPI) | `oasdiff` | GitHub, GitLab (partial), Okta, Azure |
| Spec-diff (AWS) | `smithy diff` / track `botocore` `.changes` | models in `aws/aws-sdk-go-v2` `codegen/sdk-codegen/aws-models/` |
| Spec-diff (GCP) | snapshot Discovery Doc + JSON / `oasdiff` (via converter) | `https://<api>.googleapis.com/$discovery/rest?version=<v>` |
| Sweeper | `cloud-nuke` / `aws-nuke` | name-prefix scoped; dedicated test account |
| Free identity tenant | Microsoft 365 Developer Program | Entra ID P2 + seeded users (for L4a Entra) |
| Schema validation in tests | existing `internal/evidence_types` (`gojsonschema`) | reuse `Validate()` |

---

## 6. Where each layer lives (current pointers)

- **L0** — `internal/core/cloud_test.go` (reflection test: no freeform
  field on the cloud wire type).
- **L1** — per-operation `fakeAPI` stubs + field assertions in each
  `internal/sources/<provider>/<service>/*_test.go`.
- **L2/L4a harness** — `internal/sources/sourcetest/` (shared
  conformance harness + go-vcr wiring + live-gating helpers).
- **L3** — `contracts/` snapshots + a scheduled `contract-drift`
  workflow (mirrors the cron in `.github/workflows/security.yml`).
- **L4b** — the E2E repos (see root [`TESTING.md`](../../TESTING.md)).

For the per-plugin requirements when adding a new source, see
[`04-source-plugins.md`](04-source-plugins.md) and
[`07-extensibility.md`](07-extensibility.md).
