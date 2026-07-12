<!--
This template is for EXTERNAL / post-launch pull requests. Internal
pre-launch work commits directly to `main` after `make test && make lint`
are green + CI green (see CONTRIBUTING.md → "Two contribution flows").
-->

## Summary

<!-- What and why. Link any issue. -->

## Checklist

- [ ] `make test && make lint` pass locally; CI is green.
- [ ] Manually ran the affected `sigcomply` subcommand and confirmed behavior (there's no web UI).
- [ ] Commits are small + atomic, `<type>: <description>` format.
- [ ] Docs updated — the focused doc the change touches (recipe / `configuration.md` / `architecture/`) is part of "done".

### If this PR adds or changes a source plugin (`internal/sources/**`)

- [ ] L0/L1 **unit tests** for the mapper/`Collect` (fake `API`, deterministic clock).
- [ ] L2 **conformance test + cassette** added (`*_conformance_test.go` via `sourcetest.RunConformance`; cassette scrubbed of secrets/PII).
- [ ] **`contracts/<provider>/<service>` spec snapshot** added + wired into `scripts/contracts-fetch.sh` (L3 drift coverage).
- [ ] (If applicable) a `//go:build live` L4a test gated with `sourcetest.RequireEnv`.

### If this PR changes the cloud-submission contract (`internal/core/cloud*`)

- [ ] The counts-only reflection test (`internal/core/cloud_test.go`) still passes; the matching Rails strong-params were checked.

<!-- See CONTRIBUTING.md and docs/architecture/11-testing-strategy.md. -->
