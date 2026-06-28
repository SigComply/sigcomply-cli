# `contracts/` — vendor API spec snapshots

This directory holds **pinned snapshots of the machine-readable API
models** published by the vendors whose APIs our source plugins call.
Each snapshot is the vendor's *own* spec (the one their SDK is generated
from), captured at a point in time and committed to the repo.

These snapshots serve **two test layers** (see
[`docs/architecture/11-testing-strategy.md`](../docs/architecture/11-testing-strategy.md)):

- **L2 — Contract/fixture (per-PR):** recorded cassettes are validated
  against the snapshot, so a cassette that drifts away from the real
  response shape fails CI.
- **L3 — Spec-diff drift (scheduled, $0):** a weekly job re-fetches each
  vendor spec and diffs it against the committed snapshot. A breaking
  shape change opens a GitHub issue — this is the cheapest mechanism we
  have for catching upstream API changes, needing zero accounts and zero
  live calls.

## Path scheme

```
contracts/<provider>/<service>@<api-version>.json
```

- `<provider>` — `aws`, `azure`, `gcp`, `github`, `gitlab`, `okta`.
- `<service>` — the specific service/API surface we use (pin **only**
  what our plugins actually call; do not snapshot whole catalogs).
- `<api-version>` — the vendor's version string, or an ISO date
  (`YYYY-MM-DD`) when the vendor has no stable version (e.g. GitHub).

Examples:

```
contracts/aws/s3@2006-03-01.json
contracts/azure/storage@2023-01-01.json
contracts/gcp/compute@v1.json
contracts/github/api.github.com@2026-06-18.json
contracts/okta/management@2024-07-01.json
```

## Where each provider's spec comes from

| Provider | Source of truth | Diff tool (L3) |
|----------|-----------------|----------------|
| AWS | Smithy models in `aws/aws-sdk-go-v2` (`codegen/sdk-codegen/aws-models/`) / `botocore` `.changes` | `smithy diff` |
| Azure | `Azure/azure-rest-api-specs` (OpenAPI) | `oasdiff` |
| GCP | Discovery Document `https://<api>.googleapis.com/$discovery/rest?version=<v>` | JSON diff / `oasdiff` via converter |
| GitHub | `github/rest-api-description` (OpenAPI) | `oasdiff` |
| GitLab | GitLab OpenAPI (partial — lean on L4a re-record diffs where thin) | `oasdiff` (partial) |
| Okta | Okta management OpenAPI | `oasdiff` |

## Refreshing snapshots

A snapshot is refreshed (and re-committed) when a plugin's mapper or
cassettes are intentionally updated to a new API shape, or when the L3
drift job flags a change you've triaged.

- `make contracts-fetch` → `scripts/contracts-fetch.sh` (WU-3.1): pulls the
  current upstream spec for every used service and re-slices it in place
  (OpenAPI via `scripts/contracts/slice_openapi.py`; AWS Smithy via
  `slice_smithy.py`). Re-running overwrites each committed snapshot, so
  `git diff contracts/` after a fetch is the raw drift signal. Pin only
  services with a plugin + cassette; GitLab is omitted (thin spec → L4a
  re-record), GCP/Azure added when their plugins land.
- `make contracts-diff` → diff committed snapshots vs. freshly fetched
  (WU-3.2, pending).

See the drift-triage runbook in
[`docs/architecture/11-testing-strategy.md`](../docs/architecture/11-testing-strategy.md).

## Hygiene

Vendor specs are public, but the **secret/PII fixture gate**
(`scripts/check-fixtures.sh`) still scans this directory — never paste a
real account ID, ARN, token, or email into a snapshot. Keep snapshots to
the schema/shape only.
