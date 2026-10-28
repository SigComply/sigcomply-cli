# 11. Testing strategy

How the CLI tests itself, and in particular its vendor API integrations. This doc owns the test
layer table; `TESTING.md` and `CONTRIBUTING.md` link here. How tests fit into a task (tests first,
the gate, exercising the built binary) is in
[../claude/development-workflow.md](../claude/development-workflow.md).

## 1. Regression tests and drift detectors

Every test is one of two kinds:

- A **regression test** checks the code against a frozen contract (a fake, a cassette, a spec
  snapshot). It is fast and free, and blind to vendor API changes: if the vendor moves, the frozen
  contract does not.
- A **drift detector** checks the frozen contract against reality. Only drift detectors catch an
  upstream change.

Rule: a green per-change suite must be backed by a scheduled drift detector that is allowed to
fail loudly.

## 2. Test layers

| Layer | Checks | Catches a vendor change? | Runs | Where | Command |
|---|---|---|---|---|---|
| L0 invariants | structural and privacy guarantees, such as no freeform field on the cloud wire type (`internal/core/cloud_test.go`) | n/a | every push | CLI | `make test` |
| L1 mapping unit | fake API response to `EvidenceRecord`; fields populated; deterministic | No | every push | CLI | `make test` |
| L2 contract | cassette replayed through the real SDK deserializer; cassette and fixtures validated against the vendor's published spec | Only on re-record or snapshot refresh | every push | CLI | `make test-contract` |
| L3 spec-diff drift | the vendor's machine-readable API model, diffed against `contracts/` | Yes, shape changes | weekly (`contract-drift.yml`, Monday 00:00 UTC) | CLI | `make contracts-diff` |
| L4a live SaaS | real calls to free accounts, `//go:build live` | Yes, including behaviour | nightly (`live-saas.yml`, 03:00 UTC) | CLI | `make test-live` |
| Binary E2E | the built binary as a process: exact exit codes 0/1/2/3, vault tree, manifest and envelope signatures, the cloud submission (fake OIDC endpoint and cloud), `evidence due`, `evidence catalog`, `init-ci` (`cmd/sigcomply/e2e_test.go`). Manual-evidence configs only: real sources need vendor APIs | No | every push | CLI | `make test` |
| Policy outcomes | every shipped policy of every framework, run through the real evaluator against one committed evidence fixture in three scenarios (compliant, noncompliant, sparse); the status, resource counts and flagged resource IDs per policy are pinned in a golden (`internal/frameworks/policy_outcomes_test.go`). A policy with no golden entry fails. A companion static check fails when a clause reads a field that no evidence type its slot accepts declares (`clause_fields_test.go`) | n/a | every push | CLI | `make test` |
| Cross-repo goldens | committed fixtures the other repos copy byte for byte: the run payload (Rails), envelope vectors, the period and folder table, the manual catalogs (Evidence SPA). Regenerated with `-update`; a stale golden fails the test | n/a | every push | CLI | `make test` |
| L4b cloud and pipeline E2E | provision minimal cloud infra, run the released binary, assert per-policy outcomes, tear down | Yes, including integration | per release candidate (gate) and scheduled | E2E repos | see the E2E repos |

How these layers group into per-push, post-deploy, release and scheduled tiers, and what each
costs: [§8](#8-system-tiers).

L3 covers AWS (Smithy models), Azure (`azure-rest-api-specs` Swagger), GCP (Discovery documents),
GitHub (`github/rest-api-description`) and Okta (OpenAPI). GitLab's published spec is too thin;
GitLab relies on L4a.

To list which sources have live tests: `grep -rl 'go:build live' internal/sources`. AWS, GCP
(except `gcp.cloud_identity`) and Azure ARM sources have no live layer; they rely on recorded L2
cassettes and L4b.

## 3. Repo split

- `sigcomply-cli` owns L0 to L4a, the binary E2E tests and the goldens. These need no
  provisioning; L4a needs only a free account and a token.
- The E2E repos own L4b: provisioning, OIDC plumbing per CI platform, setup/teardown scripts and
  a leak sweeper. L4b tests the released binary, including the prerelease the release gate
  checks. In
  `sigcomply-cli-testing-project-github`, see `scripts/assert_outcomes.py`, `scripts/setup-*.sh`,
  `scripts/teardown-*.sh` and `scripts/sweep-aws.sh` (a custom AWS-only sweeper that deletes
  resources named with the `sigcomply-e2e-` prefix).
- The CLI repo never provisions cloud resources in CI. The E2E repos contain no Go unit tests of
  mappers.

## 4. Conventions

1. **Package layout.** A source package holds the mapper, its tests and its `testdata/` as
   siblings. A typical package: `factory.go`, `<service>.go`, `<service>_test.go` (L1),
   `<service>_conformance_test.go` (L2 replay via `sourcetest.RunConformance`), sometimes
   `<service>_spec_conformance_test.go`, `<service>_record_test.go` (recorder) or
   `<service>_live_test.go` (L4a), and `testdata/cassettes/`. Multi-service providers (`aws`,
   `gcp`, `azure`) use one package per service (`internal/sources/aws/s3/`); single-service
   providers are flat (`internal/sources/github/`). List a real package to confirm.
2. **Cassettes.** go-vcr v4 YAML under `testdata/cassettes/`. Most sources have one cassette
   covering their whole collect call (`aws/s3/testdata/cassettes/buckets.yaml`,
   `github/testdata/cassettes/org_collect.yaml`). Scenario variety (encrypted vs unencrypted,
   present vs absent) lives in L1 fakes, not in extra cassettes.
3. **Spec snapshots.** `contracts/<provider>/<service>@<api-version>.json`, sliced to the
   operations and fields the mapper reads. They serve L2 (validate cassettes) and L3 (diff over
   time). See [`contracts/README.md`](../../contracts/README.md).
4. **Redaction.** The recorder's go-vcr `BeforeSaveHook` replaces secrets and identity with stable
   placeholders so re-recording is deterministic:

   | Real value | Placeholder |
   |---|---|
   | `Authorization`, bearer token, API key headers | `REDACTED` |
   | AWS access key (`AKIA…`) | `AKIAEXAMPLE0000000000` |
   | AWS account ID, quoted or in an ARN | `000000000000` |
   | 12-digit bare JSON number | `0` (leading zeros are invalid JSON) |
   | ARN | `arn:aws:<svc>:<region>:000000000000:<resource>` |
   | email address | `user-<hash>@example.com`, distinct per address so identity-bearing sources do not alias members |
   | username or login | `example-user` |

   `scripts/check-fixtures.sh` scans every `testdata/` directory and `contracts/` for AWS keys,
   bare account IDs, ARNs with a real account, non-`example.*` emails and bearer tokens, and fails
   on a hit. It runs in `test.yml`, `make check-fixtures` and `make pre-commit`;
   `internal/fixturehygiene` proves it catches planted secrets. A fixture that leaks identity
   breaks the non-custodial architecture.
5. **Build tags.**
   - `live`: L4a. The test's first call is `sourcetest.RequireEnv(t, ...)`, which skips when any
     named variable is unset. The nightly workflow runs `go test -tags live -count=1 -run Live
     ./...`, so name every live test `Test*Live*` or it never runs nightly.
   - `record`: committed recorders (`<service>_record_test.go`) for GCP and Azure ARM packages,
     using `gcptest.RecordLiveOptions` / `gcptest.RecordLiveClient` and
     `azuretest.RecordLiveOptions`. Run with live credentials:
     `go test -tags record -run <Test> ./internal/sources/<provider>/<service>/`.
   - `cassette`: `internal/sources/aws/identitycenter/identitycenter_cassette_test.go` constructs
     a cassette that could not be recorded (no Identity Center tenant): real SDK-serialized
     requests paired with response bodies transcribed from the Smithy models. Regenerate with
     `go test -tags cassette -run TestConstructCassette ./internal/sources/aws/identitycenter/`,
     then paste back the provenance header that go-vcr drops. It stays a shape test until
     re-recorded against a real tenant.
   - A tagged file must never be the only test for a production mapper: the default build does
     not compile it, so the mapper would show 0% coverage.
6. **Coverage.** `test.yml` runs the full suite with `-coverprofile` and fails below
   `COVERAGE_THRESHOLD` (read the value there). Locally, `make test` runs the `-short` unit suite;
   `make test-full` matches CI. Tagged tests and E2E never count. Raise the floor as coverage
   improves; never lower it silently.
7. **Shared harness.** All source tests use `internal/sources/sourcetest/` (schema conformance,
   field completeness, determinism, metadata, go-vcr wiring, live gating). See
   [`internal/sources/sourcetest/README.md`](../../internal/sources/sourcetest/README.md).
8. **Resource names.** Live and E2E resources use the `sigcomply-e2e-` prefix so sweepers can
   find leaks.
9. **Drift jobs are alert-only.** They open or update a GitHub issue and never run on pull
   requests or block a push.
10. **Non-HTTP sources.** `active_directory` (LDAP) cannot use cassettes or L3. Its L2 layer is an
    in-process protocol responder behind a package-private dial seam
    (`internal/sources/activedirectory/fakedc_test.go`): it decodes real client requests and
    replays canned responses, with `sourcetest.RunConformance` over it. Drift is caught by its
    live test against a disposable Samba AD DC container. See
    [04-source-plugins.md](04-source-plugins.md).

### Recorded and hand-authored cassettes

- GCP and Azure ARM cassettes are recorded from seeded test projects/subscriptions through the
  committed `record` drivers. The setup and teardown scripts in the E2E repo
  (`setup-gcp.sh`, `setup-azure.sh`, `teardown-gcp.sh`, `teardown-azure.sh`) provision the posture and document
  provider quirks. To see which packages have a recorder: `grep -rl 'go:build record'
  internal/sources`.
- Some cassettes stay hand-authored because the posture cannot be produced cheaply: GCP `scc`
  and `directory`, Azure `defender` and `certs`, and the Entra MFA registration report
  (`reports/authenticationMethods/userRegistrationDetails`, in
  `internal/sources/azure/entra/testdata/cassettes/directory.yaml`), which needs an Entra ID P1/P2
  licence. Hand-authored cassettes are still validated against the vendor spec.
- `gcp.cloud_identity` has no cassette on purpose. Google publishes no sample response for
  `settings/security.password`, so a hand-written fixture would only re-assert the mapper's own
  guesses. Its decoders accept every shape the unverified details could take and turn anything
  else into an error, not a zero. `cloudidentity_live_test.go` logs the raw bodies; recording a
  cassette from a real Workspace tenant retires the exemption. Do not hand-author one.

## 5. Tooling

| Concern | Tool |
|---|---|
| HTTP record/replay | `dnaeon/go-vcr` v4 |
| AWS test seam | fake `HTTPClient` via `config.WithHTTPClient` (runs the real deserializer); interface stubs for pure logic |
| GCP test seam | `option.WithHTTPClient` + `option.WithoutAuthentication` |
| Azure test seam | `arm.ClientOptions{Transport: ...}` and a fake `azcore.TokenCredential` |
| Storage SDK seam (vault backends, manual-evidence readers) | `internal/storagetest`: in-memory GCS, Azure Blob and S3 servers that speak each wire protocol, so the real SDK client runs: pagination, response decoding, not-found mapping |
| Spec snapshots | `scripts/contracts-fetch.sh` (`make contracts-fetch`), slicing with `scripts/contracts/slice_smithy.py` (AWS), `slice_swagger.py` (Azure), `slice_discovery.py` (GCP), `slice_openapi.py` (GitHub, Okta) |
| Spec diff | `scripts/contracts-diff.sh` (`make contracts-diff`) running `scripts/contracts/diff_contracts.py`: removed or changed operations, shapes, fields and enums the mapper reads are breaking; additions are not |
| Spec toolchain | `curl`, `python3`, and `ruby` (Okta YAML to JSON) |
| Schema validation | `internal/evidence_types` (`gojsonschema`) |
| Leak sweeper | `scripts/sweep-aws.sh` in the GitHub E2E repo |

## 6. L3 drift triage

`contract-drift.yml` re-fetches every pinned spec slice and diffs it against `contracts/`. A change
opens or comments on an issue labelled `contract-drift`. The script exits 1 on breaking drift and 2
on a tooling failure; both comment on the issue, and the workflow run itself stays green. So read
the issue, not the run's colour. A tooling failure means no spec was compared that week: the
fetch names the URL that failed (`contracts-fetch: GET <url> failed`), usually a vendor moving a
spec file.

1. Reproduce: `make contracts-diff`. It prints `BREAKING …` lines and an additions count; a clean
   tree exits 0.
2. Additions only: go to step 5.
3. For each breaking change, find the consumer: `contracts/<provider>/<service>` maps to
   `internal/sources/<provider>/<service>`. If the mapper and schema do not read the changed
   field, note it and go to step 5.
4. Fix the mapper. If the canonical shape changed, add a new evidence-type schema version in
   `internal/evidence_types/schemas/` (never mutate one). Re-record the affected cassette with the
   package's `record` driver, or hand-edit it from a real response. Re-run its conformance tests.
5. Re-baseline: `make contracts-fetch`, commit the updated `contracts/` files.
6. Close the issue once CI is green.

The differ skips what never describes a shape a mapper reads: Smithy endpoint-routing rules
(`smithy.rules#endpointBdd` and its relatives), documentation strings, and how many `../` a
relative `$ref` starts with (`scripts/contracts_diff_test.go` pins both what is skipped and what
still counts). Never silence real drift by editing the differ.

## 7. L4a live setup

Each live test skips unless its variables are set. In CI they come from repository secrets mapped
in `live-saas.yml` (GitHub secrets are stored as `GH_TEST_*` because secret names cannot start with
`GITHUB_`). The `live-saas.yml` run stays green even when tests fail; a failure opens or comments
on a GitHub issue labelled `live-drift`. Read the issue, not the run's colour.

| Provider | Env the test reads | CI secret | Free credential |
|---|---|---|---|
| GitHub | `GITHUB_TEST_TOKEN`, `GITHUB_TEST_ORG` | `GH_TEST_TOKEN`, `GH_TEST_ORG` | A free org that enforces 2FA (the test asserts `two_factor_required`); classic PAT with `read:org`, `admin:org`, `repo` |
| GitLab | `GITLAB_TEST_TOKEN`, `GITLAB_TEST_GROUP`, optional `GITLAB_TEST_BASE_URL` | same names | gitlab.com free group; classic `read_api` PAT (fine-grained tokens get 403 on `/user`) |
| Okta | `OKTA_TEST_TOKEN`, `OKTA_TEST_ORG_URL` | same names | Okta Integrator Free Plan org; SSWS API token whose owner can read policies and roles (the test expects at least one `password_policy`, so zero means missing permission) |
| Entra | `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET` | same names | Free Azure tenant; app registration with admin-consented application permissions `User.Read.All`, `AuditLog.Read.All`, `Domain.Read.All`. Without P1/P2 the MFA report test skips after proving auth; the password-policy test skips on `Authorization_RequestDenied` |
| Active Directory | `SIGCOMPLY_AD_TEST_URL`, `SIGCOMPLY_AD_TEST_BIND_DN`, `SIGCOMPLY_AD_TEST_PASSWORD`, optional `SIGCOMPLY_AD_TEST_*` | none (not in the nightly workflow) | Local `diegogslomp/samba-ad-dc` container; see the header of `activedirectory_live_test.go` |
| GCP Cloud Identity | `GCP_TEST_TARGET_SERVICE_ACCOUNT`, `GCP_TEST_IMPERSONATE_SUBJECT` | none (not in the nightly workflow) | A Workspace or Cloud Identity tenant; see `cloudidentity_live_test.go` |

Remediating a live failure: reproduce with `make test-live`, fix the mapper or schema, re-record
the affected cassette, and re-baseline the L3 snapshot if the upstream shape moved. L3 catches
spec-shape changes with no accounts; L4a catches behaviour a spec diff cannot see.

## 8. System tiers

The layers above sit in four tiers across the SigComply repos. Each tier runs at a different
moment and costs a different amount.

| Tier | When | What runs | Cost |
|---|---|---|---|
| T1 per-push gate | every push, in each repo | unit, integration, cross-repo goldens and the repo's own E2E layer. Here: L0 to L2 and the binary E2E tests in `test.yml`, which a release waits for | $0 |
| T2 post-deploy smoke | after the dashboard or the Evidence SPA deploys | a check that the deployed site answers; owned by those repos | $0 |
| T3 release gate | every CLI release candidate, when `RELEASE_GATE` is `on` | `release-gate.yml` in the GitHub E2E repo runs the prerelease against a small real AWS set, the GitHub source and manual evidence, asserts the exit code and every policy outcome, verifies the vault with the SPA's verifier, submits counts to SigComply Cloud and reads them back. The release becomes latest only if it passes | about $0.05 of AWS per run; SaaS accounts are free tiers |
| T4 scheduled | daily, nightly, weekly | the release gate on `latest` daily (account and vendor drift), L4a nightly, L3 weekly, the AWS leak sweeper | about $1 a month |

The daily release-gate run on `latest` lives in the GitHub E2E repo, which is private. A failure shows
as a red run in that repo, not as an issue here.

The full AWS, GCP and Azure tiers in the E2E repo cost far more per run and are dispatched by
hand, never on a gate or a schedule.
