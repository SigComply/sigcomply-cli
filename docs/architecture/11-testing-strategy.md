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
| **L4a — SaaS/Entra live** | real calls to **free** accounts (GitHub/GitLab/Okta/Entra†) | **Yes — incl. behavioral** | ~$0 | scheduled (nightly) | **CLI** (`//go:build live`) |
| **L4b — Cloud + pipeline E2E** | provision minimal real cloud infra, run the released binary end-to-end, **assert expected per-policy outcomes** | **Yes — incl. behavioral + integration** | bounded (~$1–5/run) | scheduled / manual | **E2E repos** |

**Why L3 is the centerpiece.** AWS (Smithy models), Azure
(`azure-rest-api-specs` OpenAPI), GCP (Discovery Documents), GitHub
(`github/rest-api-description`), and Okta (OpenAPI) all publish the
machine-readable model their own SDK is generated from. Diffing it on a
schedule catches contract changes with **zero accounts and zero live
calls**. GitLab's published spec is thin → for GitLab we lean on L4a
cassette re-record diffs instead.

† **Entra is partially live.** Non-premium Entra surfaces (users,
`authorizationPolicy`) run as L4a live on a free Azure-account tenant; the
**P2-gated MFA registration report** is not free to host, so it is covered
by a spec-validated L2 cassette instead — see the Entra exception under §3
boundary rules.

---

## 3. Repo split — which tests go where, and why

**`sigcomply-cli/` owns L0, L1, L2, L3, L4a.** These are Go tests (or
scheduled Go tooling) that live next to the plugin code, need no
infrastructure provisioning, and gate every CLI change. L4a (SaaS/Entra)
lives here because those vendors are *free* and need only a token — no
Terraform, no teardown.

**L4a convention (WU-4.1).** A live test carries the `//go:build live` tag
(so the default `go test ./...`, the coverage gate, and CI's unit job never
compile it) and calls `sourcetest.RequireEnv(t, "GITHUB_TEST_TOKEN", …)` as
its first line — which returns the values when every named var is set, or
`t.Skip`s when any is absent. So `make test-live` (`go test -tags live ./...`)
runs every live test that has credentials configured and cleanly skips the
rest; with no secrets set (PRs, most contributors) the whole set no-ops. Live
tests never count toward the coverage number.

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
- **Entra's P2-gated surfaces are the one L4a exception.** Most Entra
  surfaces (users, `authorizationPolicy`) are L4a-live-capable on a free
  Azure-account tenant. But the **MFA registration report**
  (`reports/authenticationMethods/userRegistrationDetails`) the plugin
  reads requires an Entra ID **P2** license, which is **not free** — the
  Microsoft 365 Developer Program is no longer self-serve, and a P2 trial
  is time-boxed (30 days) and may require a payment method. So that single
  surface is covered by a **hand-authored, spec-validated L2 cassette**
  (validated against the `azure-rest-api-specs` OpenAPI like any other
  cassette — see `mfa_registration_*.yaml`), not an L4a live call. This is
  a deliberate, scoped fallback: the P2-gated report gets contract
  coverage for $0; only its *nightly behavioral* live confirmation is
  forgone. A maintainer with a live P2 tenant can record the real cassette
  to refresh it; the per-PR gate never depends on either.
- **GCP cassettes are hand-authored until a usable credential exists.**
  The contract path for GCP is the same L2 cassette + L3 Discovery-Doc
  drift as any cloud, but **live recording is currently blocked**: the test
  GCP org enforces `iam.disableServiceAccountKeyCreation` (no downloadable
  JSON keys) *and* an org-level IAM deny on `iam.serviceAccounts.*` (so
  impersonation also fails, even for a project Owner), and its billing
  account is closed (so `compute`/`container` won't enable). Until an org
  admin lifts those (or a no-org project is used), GCP cassettes are
  **hand-authored and validated against the published Discovery Doc /
  OpenAPI**, exactly like the Entra P2 fallback above. Same contract
  coverage for $0; only live (L4a smoke / L4b behavioral) GCP is deferred.

---

## 4. Cross-cutting conventions

Decided once; obeyed everywhere.

1. **Cassette location** (go-vcr v4). The path mirrors the package that
   owns the mapper, so cassettes sit next to the code they test:
   - **Multi-service providers** (one Go package per service —
     `aws`, `gcp`, `azure`):
     `internal/sources/<provider>/<service>/testdata/cassettes/*.yaml`
     (e.g. `internal/sources/aws/s3/testdata/cassettes/`).
   - **Single-service providers** (one flat package —
     `github`, `gitlab`, `okta`, `manual`):
     `internal/sources/<provider>/testdata/cassettes/*.yaml`
     (e.g. `internal/sources/github/testdata/cassettes/`).

   One cassette **per scenario**, named for the behavior it captures —
   e.g. `list_buckets_encrypted.yaml`, `list_buckets_unencrypted.yaml`,
   `branch_protection_present.yaml`, `branch_protection_absent.yaml`.
   `testdata/` is ignored by the Go toolchain, so cassettes never affect
   the build.
2. **Vendor spec snapshots ("contracts").**
   `contracts/<provider>/<service>@<api-version>.json`. Serves **both**
   L2 (validate cassettes against the spec) and L3 (diff over time). Pin
   only the services we actually use.
3. **Redaction (mandatory — privacy invariant).** The go-vcr
   `BeforeSaveHook` scrubs secrets and identity to **stable
   placeholders** as a cassette is recorded, so re-recording is
   deterministic. The agreed placeholders:

   | Real value | Placeholder |
   |---|---|
   | `Authorization` / bearer token / API key headers | `REDACTED` |
   | AWS access key (`AKIA…`) | `AKIAEXAMPLE0000000000` |
   | AWS account ID (12 digits) | `000000000000` |
   | ARN | `arn:aws:<svc>:<region>:000000000000:<resource>` |
   | email address | `user@example.com` |
   | username / login | `example-user` |

   A CI gate (`scripts/check-fixtures.sh`) greps every `testdata/` dir +
   `contracts/` for `AKIA[0-9A-Z]{16}`, bare 12-digit account IDs, ARNs
   carrying a real (non-zero) account ID, `@`-emails (other than the
   reserved `example.{com,org,net}` domains), and bearer tokens, and
   **fails the build on a hit**. Tokens matching the placeholders above
   are ignored, and `*.md` docs are skipped (a README documenting the
   `service@version.json` contract path scheme is not a fixture). It runs
   as a first step in `test.yml`, in `make check-fixtures`, and in
   `make pre-commit`; `internal/fixturehygiene` drives it over synthetic
   fixtures so `go test ./...` proves it catches planted secrets and
   passes a clean tree. A fixture that leaks identity violates the
   non-custodial architecture, not just a style rule.
4. **Build tags.** Live tests carry `//go:build live` as the first line
   and additionally skip if the required env (token) is absent
   (`TF_ACC`-style — call `sourcetest.RequireEnv(t, "GITHUB_TEST_TOKEN")`
   at the top of the test). Because the default build (`go test ./...`,
   no `-tags live`) never compiles a `live`-tagged file, live tests run
   in neither the per-PR suite nor the coverage run — no extra exclusion
   config is needed. **Corollary:** a `live` file must never be the
   *only* test for a production mapper, or that mapper would show 0%
   under the default build. Every mapper is covered by non-tagged L1/L2
   tests; live is *additional* confidence.
5. **Coverage.** Keep the existing **80% floor**. It is enforced in
   `.github/workflows/test.yml`: CI runs
   `go test -race -coverprofile=coverage.out -covermode=atomic ./...`
   then fails if `go tool cover -func` `total` `< COVERAGE_THRESHOLD`
   (currently `80`). L2 cassette replay *raises* coverage because the
   real deserialize paths execute. Raise the floor as coverage improves;
   never lower it silently.
   **`live` and E2E are excluded from the gate by construction** (WU-7.4):
   the coverage run carries no `-tags live`, so `//go:build live` tests are
   never compiled into it (they neither raise nor dilute the number), and the
   L4b E2E suites live in separate repos entirely. `make ci` and `make
   pre-commit` likewise omit `-tags live`. So the floor measures exactly the
   L0–L3 in-repo tests, which is what gates every CLI change.
6. **Shared harness.** All source-plugin tests run through
   `internal/sources/sourcetest/` — schema conformance + field
   completeness + determinism + metadata checks. Adding a plugin must not
   require re-inventing test scaffolding.
7. **Naming for live/E2E resources.** Fixed prefix `sigcomply-e2e-` so
   sweepers can find and delete leaks safely.
8. **Drift jobs are alert-only.** They open/update a GitHub issue; they
   do **not** block PRs (they run on a schedule, not on PRs).

### Where a new plugin's test artifacts go (worked layout)

A contributor adding the (illustrative) AWS S3 plugin and the GitHub
plugin places artifacts exactly here:

```
sigcomply-cli/
├── contracts/
│   ├── aws/
│   │   └── s3@2006-03-01.json            # vendor spec snapshot  (L2 + L3)
│   └── github/
│       └── api.github.com@2026-06-18.json
└── internal/
    └── sources/
        ├── aws/s3/                        # multi-service provider → per-service pkg
        │   ├── s3.go                      # the mapper (production)
        │   ├── s3_test.go                 # L1 fakeAPI unit + L2 conformance (RunConformance)
        │   ├── s3_live_test.go            # //go:build live   (L4a, if applicable)
        │   └── testdata/cassettes/
        │       ├── list_buckets_encrypted.yaml
        │       └── list_buckets_unencrypted.yaml
        └── github/                        # single-service provider → flat pkg
            ├── github.go
            ├── github_test.go
            └── testdata/cassettes/
                ├── branch_protection_present.yaml
                └── branch_protection_absent.yaml
```

Rule of thumb: **mapper, its `*_test.go`, and its `testdata/cassettes/`
are siblings**; the matching `contracts/<provider>/<service>@<ver>.json`
spec snapshot is the only artifact that lives outside the plugin package
(it is shared by L2 validation and L3 drift). See
[`contracts/README.md`](../../contracts/README.md) and
[`internal/sources/sourcetest/README.md`](../../internal/sources/sourcetest/README.md).

---

## 5. Tooling reference

| Concern | Tool | Notes |
|--------|------|-------|
| HTTP record/replay | `dnaeon/go-vcr` v4 | transport seam for L1/L2 |
| AWS test seam | fake `HTTPClient` via `config.WithHTTPClient` (runs the real deserializer); interface stubs for pure logic | per-protocol matcher needed for query/json APIs (IAM/EC2/STS) |
| GCP test seam | `option.WithHTTPClient` + `option.WithoutAuthentication` → httptest / go-vcr | REST/JSON clients |
| Azure test seam | `arm.ClientOptions{Transport: ...}`; fake `azcore.TokenCredential` | swap the transport |
| Spec-diff (all providers) | `scripts/contracts/diff_contracts.py` (dependency-free structural JSON diff over our committed slices) | Implemented in WU-3.2; run via `make contracts-diff`. Classifies *removed/changed* (op·shape·field·enum we read) as **breaking**, *added* as non-breaking. Chosen over `oasdiff`/`smithy diff` to keep the toolchain to python3 only (no Go-binary or Java gate); the slices are deterministic JSON we control. Upgrade to `oasdiff` later if richer OpenAPI rules are wanted. |
| Spec snapshots | `scripts/contracts-fetch.sh` (`make contracts-fetch`) | OpenAPI sliced by `slice_openapi.py` (GitHub/Okta); AWS Smithy by `slice_smithy.py`; models in `aws/aws-sdk-go-v2` `codegen/sdk-codegen/aws-models/`. |
| Sweeper | `cloud-nuke` / `aws-nuke` | name-prefix scoped; dedicated test account |
| Free identity tenant | Free Azure-account tenant (`*.onmicrosoft.com`) + seeded users | Covers non-premium L4a Entra (users, policies). The Microsoft 365 Developer Program is no longer self-serve free. **Entra ID P2 is not free** (time-boxed trial only) → the P2-gated MFA registration report falls back to a spec-validated L2 cassette, not L4a. |
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

---

## 7. Drift triage runbook (L3 alert response)

The weekly `contract-drift` workflow re-fetches every pinned vendor spec
slice and diffs it against the committed snapshot in `contracts/`. A
change opens (or comments on) a GitHub issue labelled `contract-drift`
with the diff report. The alert is **never** on the per-PR path — it's a
heads-up that an upstream API moved. Triage:

1. **Reproduce locally:** `make contracts-diff`. It prints, per snapshot,
   `BREAKING …` lines (a removed/changed operation, shape, field, or enum
   value our mapper reads) and an additions count. A clean tree exits 0.
2. **Classify each change.**
   - *Additions only* (new fields/operations upstream): non-breaking — we
     ignore unknown fields. Skip to step 5 (just re-baseline the snapshot).
   - *Breaking* (something we read was removed or changed type): continue.
3. **Assess mapper impact.** For each breaking change, find the consuming
   plugin (the `contracts/<provider>/<service>` path maps to
   `internal/sources/<provider>/<service>`). Does its mapper or
   evidence-type schema read the changed field? If not, it's breaking for
   the vendor but inert for us — note it and proceed.
4. **Fix what broke.** Update the mapper (and, if the canonical shape
   changed, the evidence-type schema in `internal/evidence_types/schemas/`
   — new version, never a mutation). Re-record the affected cassette so it
   reflects the new response shape (re-run the plugin's `//go:build record`
   recorder against a live/test account, or hand-author from the real
   response). Re-run the plugin's conformance + spec test.
5. **Re-baseline the snapshot:** `make contracts-fetch` re-slices in place;
   commit the updated `contracts/<…>.json`. This clears the alert on the
   next scheduled run.
6. **Close the issue** once the snapshot (and any mapper/cassette/schema
   changes) are committed and CI is green.

Rule of thumb: a `contract-drift` issue is *informational until proven
breaking* — most vendor changes are additive. Never silence it by editing
the differ; re-baseline via `make contracts-fetch` so the next genuine
drift still fires.

## 8. L4a live-test setup (free-account guide)

The L4a live tests (`//go:build live`, run by `make test-live` locally and the
nightly **Live SaaS Drift** workflow, `.github/workflows/live-saas.yml`) hit
real provider APIs. Each calls `sourcetest.RequireEnv` first, so it **skips**
unless its credentials are present — configure only the providers you have free
accounts for. In CI the credentials are repository **secrets**; the workflow maps
them onto the env the tests read (GitHub's are stored as `GH_TEST_*` because
secret names can't begin with `GITHUB_`).

| Provider | Env the test reads | CI secret | How to get a free credential |
|----------|--------------------|-----------|------------------------------|
| GitHub  | `GITHUB_TEST_TOKEN`, `GITHUB_TEST_ORG` | `GH_TEST_TOKEN`, `GH_TEST_ORG` | A free org; a classic PAT with `read:org` + `admin:org` (org policy + member 2FA) + `repo`. The org must enforce 2FA (the test asserts `two_factor_required`). |
| GitLab  | `GITLAB_TEST_TOKEN`, `GITLAB_TEST_GROUP`, `GITLAB_TEST_BASE_URL` (optional) | same names | gitlab.com free group; a **classic** `read_api` PAT (fine-grained tokens 403 on `/user`). Base URL blank = gitlab.com. |
| Okta    | `OKTA_TEST_TOKEN`, `OKTA_TEST_ORG_URL` | same names | Okta Integrator Free Plan org; an API token (Security → API → Tokens), SSWS scheme; org URL e.g. `https://trial-xxximes.okta.com`. |
| Entra   | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | same names | Free Azure tenant; an app registration with **application** Graph permissions `User.Read.All` + `AuditLog.Read.All` (admin-consented) + a client secret. The MFA registration report needs Entra **P1/P2**; without it the test skips after proving auth (`Authentication_RequestFromNonPremiumTenantOrB2CTenant`). |

**Drift signal & remediation.** A live test failing on the nightly run opens a
`live-drift` issue (alert-only; PRs never run it). Cassette **re-record is
manual** by design — the recorders are throwaway `//go:build record` drivers, not
committed — so triage is: reproduce with `make test-live`, fix the mapper/schema,
re-record the affected cassette with a throwaway driver, and (if the upstream
shape moved) re-baseline the L3 snapshot via `make contracts-fetch`. The two
drift jobs are complementary: **Contract Drift** (L3) catches spec-shape changes
with zero accounts; **Live SaaS Drift** (L4a) catches behavioral changes a spec
diff can't see (and GitLab, whose published spec is too thin for L3, relies on it
entirely).
