# `internal/sources/sourcetest`: source-plugin test harness

Shared helpers for source-plugin tests: conformance checks on emitted records, go-vcr cassette
record and replay with redaction, vendor-spec validation of recorded responses, and live-test
gating. It backs test layers L2 and L4a in
[`docs/architecture/11-testing-strategy.md`](../../../docs/architecture/11-testing-strategy.md).
The add-a-plugin checklist is in
[`docs/architecture/04-source-plugins.md`](../../../docs/architecture/04-source-plugins.md).

## Conformance (`conformance.go`)

```go
records := sourcetest.RunConformance(t, &sourcetest.Options{
    Plugin:        plugin,                              // built with its cassette transport
    EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),  // embedded production schemas
})
```

`RunConformance(t *testing.T, opts *Options) []core.EvidenceRecord` calls `Collect` twice and
reports through `t`:

- Determinism: both calls return identical output. A plugin that stamps `time.Now()` instead of
  an injected clock fails here.
- Non-empty: zero records fail unless `AllowEmpty` is set.
- Ordering: records are sorted by `ID`.
- Metadata: every record has `Type` (one of `Plugin.Emits()`), `ID`, `SourceID` and a non-zero
  `CollectedAt`.
- Schema: every payload validates against its evidence type's JSON Schema.
- Completeness: every key in the schema's top-level `properties` is present in the payload,
  optional fields included. Presence is checked, not value: a zero value passes.

It returns the first call's records for scenario-specific assertions.

`Options` fields:

| Field | Meaning |
|---|---|
| `Plugin` | The plugin under test, already wired to its cassette or fake. Required. |
| `Request` | The `SlotRequest` passed to `Collect`. Empty `AcceptedTypes` defaults to `Plugin.Emits()`. |
| `EvidenceTypes` | Schema registry. Pass `BuiltinEvidenceTypes(t)`. Required. |
| `OptionalFields` | Fields exempt from the completeness check, as `field` or `type.field`. |
| `AllowEmpty` | Permit a scenario that emits no records. |
| `WantScope` | When set, every record must carry exactly this `core.RecordScope`. Set it when the plugin knows which account, subscription or project it queried; the scope is signed into the envelope. |

## Cassettes (`cassette.go`)

Cassette names are paths without the `.yaml` suffix, for example
`testdata/cassettes/list_repos`.

| Function | Use |
|---|---|
| `ReplayClient(t, name)` | Offline replay, matching on method and URL. An unrecorded request fails. |
| `ReplayClientWithMatcher(t, name, matcher)` | Replay with a custom matcher. |
| `RecordClient(t, name, transport)` | Record through a real transport; used in `//go:build record` drivers. |
| `RecordClientWithMatcher(t, name, transport, matcher)` | Record with a custom matcher. |
| `MethodURLMatcher` | The default matcher. |
| `AWSMatcher` | Also compares request bodies, for AWS query, JSON and CBOR protocols where operations share a URL. |
| `RedactInteraction` | The save hook every recording uses. Scrubs credential headers, bearer tokens, emails, AWS access key IDs and 12-digit account IDs in URLs, forms and bodies. Plugin-specific fields (usernames that are not emails) need an extra hook in the plugin's driver. |

Point the plugin's HTTP client at the returned `*http.Client` through its SDK seam: AWS
`config.WithHTTPClient`, GCP `option.WithHTTPClient`, Azure `arm.ClientOptions{Transport: ...}`.

## Vendor-spec validation (`spec.go`)

`NewSpecValidator(t, specPath)` loads an OpenAPI slice from `contracts/`;
`(*SpecValidator).Check` and `CheckArray` validate decoded JSON against a named component schema.
`LoadCassetteInteractions` and `DecodeJSONBody` read recorded responses for it. GitHub and Okta
use this (`*_spec_conformance_test.go`); other providers rely on the weekly drift job alone.

## Live tests (`live.go`)

```go
//go:build live

env := sourcetest.RequireEnv(t, "GITHUB_TEST_TOKEN", "GITHUB_TEST_ORG")
```

`RequireEnv(t, keys...)` skips the test unless every variable is set, and returns their values.
Run live tests with `make test-live`.

## Rules

- The harness makes no network calls of its own. It replays cassettes, or the caller passes a
  real transport while recording.
- Keep it light on dependencies. Every source test imports it.
- Never commit an unscrubbed cassette. `make check-fixtures` scans `testdata/`.
