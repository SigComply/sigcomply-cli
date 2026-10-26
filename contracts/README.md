# `contracts/`: vendor API spec snapshots

Pinned slices of the machine-readable API models that vendors publish for the APIs our source
plugins call. Each snapshot is the vendor's own spec (the one their SDK is generated from), cut
down to the operations and shapes we use.

They serve two test layers (see
[`docs/architecture/11-testing-strategy.md`](../docs/architecture/11-testing-strategy.md)):

- L2, per change: recorded cassettes are validated against the snapshot, for GitHub and Okta only
  (`internal/sources/github/github_spec_conformance_test.go`,
  `internal/sources/okta/okta_spec_conformance_test.go`). The AWS, Azure and GCP snapshots are
  used by L3 alone.
- L3, weekly: `contract-drift.yml` runs `make contracts-diff`, which fetches every spec fresh and
  diffs it against the committed snapshot. A breaking change (exit 1) or a fetch failure (exit 2)
  opens or updates a GitHub issue labelled `contract-drift`.

## Path scheme

```
contracts/<provider>/<service>@<api-version>.json
```

- `<provider>`: `aws`, `azure`, `gcp`, `github`, `okta`. GitLab has no snapshot; its published
  spec is too thin, so GitLab drift is caught by live tests.
- `<service>`: the API surface a plugin calls. Snapshot only what plugins use.
- `<api-version>`: the vendor's version string, or an ISO date (`YYYY-MM-DD`) when the vendor has
  no stable version (GitHub, Okta).

Examples: `aws/s3@2006-03-01.json`, `gcp/compute@v1.json`, `azure/storage@2026-04-01.json`,
`github/api.github.com@2026-06-28.json`.

## Where each spec comes from

| Provider | Upstream source | Slicer (`scripts/contracts/`) |
|---|---|---|
| AWS | Smithy models in `aws/aws-sdk-go-v2` | `slice_smithy.py` |
| Azure | `Azure/azure-rest-api-specs` (Swagger) | `slice_swagger.py` |
| GCP | Discovery documents | `slice_discovery.py` |
| GitHub | `github/rest-api-description` (OpenAPI) | `slice_openapi.py` |
| Okta | Okta management OpenAPI | `slice_openapi.py` |

The diff for every provider is `scripts/contracts/diff_contracts.py`, which classifies changes as
breaking or not. The scripts need `curl`, `python3` and `ruby`.

## Refreshing snapshots

- `make contracts-fetch` (`scripts/contracts-fetch.sh`) re-fetches and re-slices every snapshot
  in place. `git diff contracts/` afterwards is the raw drift. Do this when you update a plugin to
  a new API shape, or after triaging a drift issue.
- `make contracts-diff` (`scripts/contracts-diff.sh`) fetches into a temporary directory and
  reports breaking differences without touching the committed files.
- A new plugin adds its service to `scripts/contracts-fetch.sh` in the same change.

Triage steps: "L3 drift triage" in `11-testing-strategy.md`.

## Hygiene

The specs are public, but `make check-fixtures` (`scripts/check-fixtures.sh`) still scans this
directory. Never paste a real account ID, ARN, token or email into a snapshot. Keep snapshots to
schema and shape only.
