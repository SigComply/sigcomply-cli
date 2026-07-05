# Contributing to SigComply CLI

Thanks for contributing! This file covers the **non-negotiable testing
requirements**; the broader engineering rules, architecture, and invariants live
in [`CLAUDE.md`](./CLAUDE.md) and [`docs/architecture/`](./docs/architecture/).

## Development rules (summary)

- **TDD + small atomic commits**, all tests passing per commit. Format
  `<type>: <description>` (`feat`/`fix`/`refactor`/`test`/`docs`/`chore`).
- **`make test && make lint` green before every commit; never break `main`.**
- Full rules: [`CLAUDE.md` → Development Rules](./CLAUDE.md#development-rules).

## Testing layers

The testing strategy is layered **L0–L4b** — see
[`docs/architecture/11-testing-strategy.md`](./docs/architecture/11-testing-strategy.md).
What runs where:

| Make target | Layer | When |
|-------------|-------|------|
| `make test` / `test-full` | L0/L1 unit + integration | every change (CI gate, 80% floor) |
| `make test-contract` | L2 cassette + fixture-vs-spec conformance | every change |
| `make contracts-diff` | L3 spec drift (scheduled) | `contract-drift.yml` |
| `make test-live` | L4a live (`//go:build live`) | nightly `live-saas.yml`; skips without creds |
| (E2E repos) | L4b released-binary E2E | the `sigcomply-cli-testing-project-*` repos |

`live` and E2E are **excluded from the coverage gate** (build-tagged / separate
repos); see §Coverage in the strategy doc.

## Adding a new source plugin — required tests

A PR that adds (or materially changes) a `internal/sources/<vendor>/<service>`
plugin **MUST** include, in the same PR:

1. **L0/L1 unit tests** — the mapper/`Collect` against an in-memory fake `API`
   (field mapping, edge cases, deterministic clock via the `Now` seam).
2. **L2 conformance** — a `*_conformance_test.go` that replays a **sanitized
   go-vcr cassette** through `sourcetest.RunConformance` (schema-validates every
   record + completeness). Cassettes are recorded with a throwaway
   `//go:build record` driver and **scrubbed of secrets/PII** (the
   `check-fixtures` gate enforces this).
3. **A `contracts/<provider>/<service>` snapshot** wired into
   `scripts/contracts-fetch.sh`, so L3 drift detection covers the new surface.
   (Where the vendor publishes an OpenAPI/Smithy/Discovery/Swagger spec — see the
   existing slicers in `scripts/contracts/`.)

The canonical step-by-step is the **Testing a source plugin (checklist)**
section of [`docs/architecture/04-source-plugins.md`](./docs/architecture/04-source-plugins.md).
Policies and sources never reference each other —
mediate via the evidence-type registry (Invariant #4 in `CLAUDE.md`).
