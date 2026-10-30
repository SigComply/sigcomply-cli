# 06: Aggregation contract (the privacy boundary)

This page owns what crosses from the customer's environment to SigComply Cloud, how the CLI
sends it, and how the contract is versioned. The boundary sits between L6 (aggregator) and L8
(submitter): `aggregator.Build` reduces `[]core.PolicyResult` to a `core.SubmissionPayload`, and
`submitter.Submit` sends it. Everything before L6 stays in the customer's vault.

Rule: no resource identifier (ARN, email, user ID, account number, file hash, resource name)
reaches the payload. A change that could carry one is a stop-and-ask (AGENTS.md Invariant #1).

## The payload

The wire types are in `internal/core/cloud.go` (`SubmissionPayload`, `Repository`,
`CIEnvironment`, `RunSummary`, `AggregatedPolicy`) and `internal/core/framework.go`
(`ControlRef`). Read them there; don't copy them into docs. The schema string is
`aggregator.SchemaVersion`.

What each field carries and why it is allowed:

| Field | Content | Why it may cross |
|---|---|---|
| `schema`, `run_id`, `framework`, `period_id` | Run identity | No customer data. |
| `commit_sha`, `commit_time`, `branch` | Git metadata | Visible to anyone with repo access. A branch name can contain a username. |
| `repository.{provider,name_slug,url}` | Where the code is hosted | Public via the remote URL. |
| `environment.{provider,workflow,run_url,worker_image}` | CI metadata | CI artefacts, not evidence. |
| `cli_version`, `started_at`, `completed_at` | Run metadata | No customer data. |
| `summary.*` | Per-status counts and `compliance_score` | Counts. |
| `policies[].policy_id`, `category` | Policy metadata | Framework taxonomy for shipped policies. A project-local policy sends its customer-chosen ID and category. |
| `policies[].controls[]` (`framework`, `framework_version`, `control_id`, `relationship`) | Control mapping | Public framework taxonomy. `framework_version` exists only here. |
| `policies[].status`, `severity`, `rule_version` | Enums and versions | No identity. |
| `policies[].resources_evaluated`, `resources_failed` | Counts | Counts. |
| `policies[].message` | Sentence regenerated from counts by `generateMessage` | Never copied from violation text. |
| `policies[].configured_cadence`, `last_evaluated_at`, `next_due_at`, `is_carried_forward`, `policy_content_hash` | Cadence scalars ([`10-cadence-model.md`](10-cadence-model.md)) | Scalars about the policy. |
| `policies[].evidence_mode`, `evidence_mode_overridden` | Which flow produced the result | Lets the dashboard tell an inspected estate from documents on file. |
| `policies[].vacuous` | A pass whose clauses filtered every record away | Boolean. |

`compliance_score = (passed + waived + carried_forward) / (total - skipped - na)`. Carry-forward
only follows a pass, so it counts as passed.

### What never crosses

| Data | Where it stays |
|---|---|
| Violations (resource ID, reason text) | `result.json`, `summary.json` |
| Evidence record payloads | Envelopes |
| Effective parameters, diagnostics (`Diag`) | `result.json`, `summary.json` |
| Uploaded manual evidence | The customer's upload bucket. Its hashes are in the envelope. |
| Signatures and public keys | Envelopes, `manifest.json` |
| Exception detail (scopes, approvers, reasons) | `manifest.json` |
| `RecordScope`, the run's `scope` report | Vault only |

Layout of those files: [`05-vault-layout.md`](05-vault-layout.md).

### Messages and vacuity

`generateMessage` (`internal/aggregator/aggregator.go`) builds `message` from the status and the
two counts only. `resources_evaluated` counts records before clause filters run, and `all` and
`none` are true of the empty set, so a policy that filtered 500 records to zero would otherwise
send "All 500 resources passed." `vacuousPass` detects that case. Both the `vacuous` flag and the
vacuous-pass message come from it, so they always agree, and both apply only to `pass`. The slot
names behind it stay in the CLI. See [`03-policy-spec.md`](03-policy-spec.md) §Empty-set
semantics.

## How the boundary is enforced

1. Types. `SubmissionPayload` has no `Violations` field, no `map[string]any`, no
   `json.RawMessage` and no interface. `TestSubmissionPayload_StructurallyCountsOnly`
   (`internal/core/cloud_test.go`) walks the type graph with `reflect` and fails on interfaces,
   `json.RawMessage`, non-string map keys and non-scalar kinds.
2. Human review. The reflection test allows any `string` and `[]string`, so a field such as
   `FailedResources []string` would pass it. Every new field needs a review that it cannot carry
   identity, plus a schema bump. The checklist is in the `SubmissionPayload` doc comment.
3. What fills the strings. String fields are filled only from CI metadata, policy metadata and
   count-generated messages.
4. The dashboard's runs API is a second allow-list. It silently drops unknown fields.
5. Golden contract. `TestCloud_GoldenWireContract` (`internal/aggregator/golden_contract_test.go`)
   locks the wire bytes in `internal/aggregator/testdata/cloud_golden.json`. The Rails repo
   keeps a byte-identical copy (path in the test's `railsFixtureRelPath`). Regenerate with
   `-update` and copy the file to Rails in the same task.
6. Payload capture. `sigcomply check --capture-cloud-payload <file>` writes the exact payload
   and does not POST. Use it to grep a real payload for identifiers.

## Sending

### Decision matrix

The CLI decides per run (`submitter.Decide`, called from
`handleSubmission` in `internal/orchestrator/orchestrator.go`).

Every submitted run is a full snapshot. Rails reads a project's latest run as its current state
(score, status, point-in-time reports), so a run over a subset of policies would swap the
headline between unrelated subsets. Only an unfiltered `check` and a `--scheduled` run submit;
under `--scheduled` the policies that are not due carry forward, so the payload still lists every
policy. A filtered run (`--cadence`, `--cadences`, `--on-push`, `--pr`; `planner.Filter`
`IsExplicit()` after `resolveMode`) never POSTs. When a submission or capture was in play it
prints `cloud submission skipped: this run evaluates a subset of policies (use `sigcomply check`
or `--scheduled`)` to stdout; with no cloud configured it stays quiet.

A run in a pull-request or merge-request pipeline never POSTs either, whatever its flags
(`isPullRequestRun`: `--pr`, or `InPullRequestPipeline`: a GitHub `pull_request*` or
`merge_group` event, or GitLab's `CI_MERGE_REQUEST_IID` / `CI_EXTERNAL_PULL_REQUEST_IID` set; the same helper stops it advancing cadence state). The branch's code
and config produced it, so it is not the project's result. It prints `cloud submission skipped:
this run is in a pull request or merge request pipeline; ...` under the same condition as the
filtered notice. Rails enforces the same rule from the verified token claims (it accepts only
push, schedule and manual events), so the CLI skip saves a rejected request and says why.

| Input | Effect |
|---|---|
| Filtered run | Skip, with the stdout notice above. `--capture-cloud-payload` still writes. |
| Pull-request or merge-request pipeline | Skip, with its notice, whatever the flags (`--cloud` too). `--capture-cloud-payload` still writes. |
| `--capture-cloud-payload` | Writes the file. Nothing is sent. |
| `--no-cloud` | Skip. |
| `--cloud`, no base URL | Skip with a warning naming `cloud.base_url` and `--cloud-url`. |
| `--cloud`, base URL, no OIDC token | Skip with a warning. |
| `--cloud`, base URL, OIDC token | Submit, in or out of CI. |
| No flag, no base URL | Skip silently. |
| No flag, base URL, not in CI or no OIDC token | Skip silently. |
| No flag, base URL, in CI, OIDC token | Submit. |

- Base URL: `cloud.base_url` in config, overridden by `--cloud-url`. There is no default and no
  environment variable. The SigComply Cloud value is `https://sigcomply.com`.
- In CI: `CI`, `GITHUB_ACTIONS` or `GITLAB_CI` is set (`submitter.InCI`).
- OIDC token: GitHub Actions via `ACTIONS_ID_TOKEN_REQUEST_URL` + `ACTIONS_ID_TOKEN_REQUEST_TOKEN`;
  GitLab CI via `SIGCOMPLY_ID_TOKEN` only (`submitter.HasOIDC`). `Submit` refuses a token whose
  `aud` does not include `DefaultAudience` ([auth.md](../claude/auth.md)).
- Audience: always `submitter.DefaultAudience` (`https://api.sigcomply.com`), whatever the base
  URL. It is an identifier, not a host. The dashboard's OIDC validator checks it.
- There is no `cloud.enabled` switch; `cloud.base_url` and `--no-cloud` decide. Setting the
  removed key is a config error.
- Project ID: `cloud.project_id` does not change the decision. It is sent as a header when set.
  A malformed value fails config load (exit 3). When a cloud URL is resolved, `--no-cloud` is not
  set, no payload capture replaces the POST, the run is not filtered (the same rule as the
  filtered-run skip, so `--scheduled` counts) and the key is empty, `check` exits 3 before
  collection, in or out of CI and with or without `--cloud` (`missingProjectIDError`). It has no
  flag and no environment variable: the committed file is what ties the repository to the project.

The request:

```
POST {base_url}/api/v1/runs
Content-Type: application/json
Authorization: Bearer <oidc_jwt>
X-OIDC-Provider: github | gitlab
X-Sigcomply-CLI-Version: <version>
X-SigComply-Project: <cloud.project_id>
```

Rails validates the token signature and the audience, then picks the project: with
`X-SigComply-Project`, the active project with that public ID whose repository matches the
token's claims (else `403 project_mismatch`); without it (an older CLI), `403
project_id_required`. The
project ID is in a header, not the payload, so the counts-only payload and `cloud_golden.json`
are unchanged. OIDC setup for customers is in the CI and cloud dashboard guides under
`docs/guides/`; agent-side detail is in [`docs/claude/auth.md`](../claude/auth.md).

Rails answers 201 with `{"run": {"id", "policy_evaluation_id", "status": "accepted"}}`. The CLI
does not parse the body; it logs `submission accepted (HTTP <code>)`.

### Failures

`submitter.Submit` makes one attempt with a 30-second HTTP timeout. There is no retry. Any
failure (token, network, HTTP status 400 or above) is logged as a warning
(`submit: <error>`, which includes the response body for an HTTP error) and the run continues.
Submission never changes the exit code. The vault already holds everything.

### Other receivers

`cloud.base_url` can point at any receiver that accepts the same payload and the same OIDC
audience. SigComply does not ship or support another receiver.

## What the dashboard does with it

Rails stores run data from the payload only, and builds its reports and history from those
stored counts. It cannot drill down to a resource: that would need read access to the customer's
vault, which the architecture rules out. Reading the violations behind a count happens where they
are, with `sigcomply report` against the vault. Dashboard features are documented in the Rails
repo and in the customer guide `docs/guides/cloud-dashboard.md`; don't track them here.

## Versioning the contract

`aggregator.SchemaVersion` is stamped into every payload. History:

| Version | Change |
|---|---|
| v2 | Added the five cadence scalars. |
| v3 | Replaced the scalar `control_id` with `controls []ControlRef`, so one policy maps to controls in several frameworks. |
| v4 | Added `evidence_mode` and `evidence_mode_overridden`. Without them a document on file and an inspected estate both look like `pass`. |
| v5 | Added `vacuous`, so vacuous passes can be filtered and counted, not only read in `message`. |

Rules:

- Bump the version for any added, renamed or re-meant field.
- Rails is shape-driven, not version-gated. It stores `schema` verbatim and accepts v1 to v5. A
  policy with a non-empty `controls[]` is read as v3+; one with only a scalar `control_id` becomes
  a one-element list (`Cli::RunSubmissionService#normalize_controls`).
- Deploy the Rails side first. Strong params silently drop a field Rails does not know, the
  request still returns 201, and the new field is lost without an error.
