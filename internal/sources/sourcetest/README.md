# `internal/sources/sourcetest` — shared source-plugin test harness

This package is the **one place** every source plugin's tests run
through. It exists so that adding a plugin never means re-inventing test
scaffolding: a plugin author feeds canned API responses in and gets
schema-conformance, completeness, determinism, and metadata checks for
free.

It backs test layers **L1, L2, and L4a** described in
[`docs/architecture/11-testing-strategy.md`](../../../docs/architecture/11-testing-strategy.md).

> **Status:** the harness code is built across WU-1.1 (conformance) and
> WU-1.2 (go-vcr wiring); WU-4.1 adds the live-gating helper. This README
> ratifies the intended API so plugin authors and those WUs share one
> contract. Until then, plugins keep their existing `fakeAPI` unit tests.

## What it provides

- **`RunConformance(t, plugin, opts)`** — given a plugin and a way to
  feed it canned responses, asserts:
  - **Schema conformance** — every emitted `EvidenceRecord` validates
    against its evidence-type JSON Schema (reuses
    `internal/evidence_types`).
  - **Completeness** — no schema-defined field is left zero/empty
    (CloudQuery-style), so a mapper that silently drops a field fails.
  - **Determinism** — two runs produce identical, ID-sorted output.
  - **Metadata** — `Type`, `SourceID`, and `CollectedAt` are set on
    every record.
- **Cassette wiring** — load a go-vcr v4 cassette, wrap it as an
  `http.RoundTripper`, and install the redaction `BeforeSaveHook` so
  recordings are scrubbed to the stable placeholders defined in the
  strategy doc §4.
- **Live gating** — `RequireEnv(t, "GITHUB_TEST_TOKEN")` skips a
  `//go:build live` test when its token env var is absent (`TF_ACC`-style).

## How a plugin uses it

A plugin's `*_test.go` (sibling to the mapper) typically:

1. Builds the plugin with a transport seam pointed at a cassette under
   `testdata/cassettes/` (per-provider seam: AWS `config.WithHTTPClient`,
   GCP `option.WithHTTPClient`, Azure `arm.ClientOptions{Transport:…}`).
2. Calls `sourcetest.RunConformance(t, plugin, opts)` to replay each
   scenario cassette through the **real SDK deserializer** and assert the
   emitted records.

Cassette and contract locations, the redaction placeholder table, and a
full worked directory layout live in
[`docs/architecture/11-testing-strategy.md`](../../../docs/architecture/11-testing-strategy.md)
(§4). The add-a-plugin checklist is in
[`docs/architecture/04-source-plugins.md`](../../../docs/architecture/04-source-plugins.md).

## Rules

- The harness must have **no network access** of its own; it only
  replays cassettes or runs against an in-package fake plugin.
- Keep it dependency-light — it is imported by every source test, so a
  heavy import here taxes the whole suite.
