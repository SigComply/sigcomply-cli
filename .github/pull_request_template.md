<!--
For outside contributors. Maintainers push straight to main (see CONTRIBUTING.md).
-->

## Summary

<!-- What and why. Link any issue. -->

## Checklist

- [ ] `make test && make lint` pass locally; CI is green.
- [ ] I built the binary and ran the affected `sigcomply` command (output, exit code, vault files).
- [ ] Commits are small, with `<type>: <description>` subjects. The type sets the release (`feat` minor, others patch); no "breaking change" in a subject unless it is one.
- [ ] Docs the change makes wrong are updated in this PR (see the routing table in `docs/claude/development-workflow.md`).
- [ ] User-visible change: an entry under `[Unreleased]` in `CHANGELOG.md`.
- [ ] Published counts changed: `go test ./internal/manualcatalog/ -run TestDocFiguresMatchCode` passes.

### If this PR adds or changes a source plugin (`internal/sources/**`)

- [ ] Unit tests for the mapper and `Collect` (fake API, fixed clock).
- [ ] A conformance test with a scrubbed cassette (`*_conformance_test.go` via `sourcetest.RunConformance`); `make check-fixtures` passes.
- [ ] A `contracts/<provider>/<service>` snapshot, added to `scripts/contracts-fetch.sh`.
- [ ] If applicable, a `//go:build live` test gated with `sourcetest.RequireEnv`.

### If this PR changes the cloud submission (`internal/core/cloud*`, `internal/aggregator/`, `internal/submitter/`)

- [ ] `TestSubmissionPayload_StructurallyCountsOnly` and `TestCloudV3_GoldenWireContract` pass.
- [ ] No field can carry a resource identifier, email or file hash.
- [ ] A regenerated golden payload is noted, so maintainers can update the dashboard's copy.

### If this PR changes the manual-evidence catalog or folder scheme

- [ ] `sigcomply evidence catalog -o json` output still matches the Evidence SPA's `src/types/catalog.ts`, or the PR says what the SPA must change.

### If this PR changes `cmd/sigcomply/templates/` or `examples/`

- [ ] Actions are pinned to commit SHAs, `permissions` are least-privilege, and no `${{ github.event.* }}` value is interpolated into a `run:` step.

<!-- See CONTRIBUTING.md and docs/architecture/11-testing-strategy.md. -->
