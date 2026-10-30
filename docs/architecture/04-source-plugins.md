# 04: Source plugins

A source plugin reads one external system (an AWS service, Okta, GitHub, an LDAP directory, a
bucket of uploaded documents) and emits evidence records of declared types. Plugins are the only
code that calls external systems during collection. Read this before adding or changing a plugin;
step-by-step recipe: [`docs/claude/recipes.md`](../claude/recipes.md).

## The plugin contract

A plugin implements `core.SourcePlugin` (`internal/core/source.go`):

```go
type SourcePlugin interface {
    ID() string                 // "aws.iam", or an instance key "aws.iam[staging]"
    Emits() []string            // evidence-type IDs this plugin can produce
    Init(ctx context.Context, cfg map[string]any) error   // never called; see below
    Collect(ctx context.Context, req SlotRequest) ([]EvidenceRecord, error)
}

type SlotRequest struct {
    PolicyID      string          // logging only; never branch on it
    AcceptedTypes []string        // slot.Accepts ∩ plugin.Emits()
    SlotName      string
    Params        map[string]any  // planner-stamped keys, plus binding slot_params
}
```

Lifecycle within a run:

1. `cmd/sigcomply/check.go` (`registerProductionSources`) builds every configured source through
   its factory before planning. The factory parses config and resolves credentials.
2. The collector calls `Collect` once per (policy, slot, source) binding.
3. Instances are discarded at run end.

`Init` is vestigial: no production code calls it, and every in-tree implementation is a no-op.
Put setup in the factory.

**KISS-no-DRY axiom.** Each policy fetches its own data: ten policies bound to `aws.iam` mean ten
`Collect` calls. A plugin must return live state on each call and stay correct with no cache.

The plugin sees only the narrowed `AcceptedTypes`, never the policy's full `accepts:`. Return
records whose `Type` is in that set.

### Declaring config keys

`sources.RegisterFactory` takes the config keys the factory reads as a variadic tail:

```go
func init() { sources.RegisterFactory(SourceID, build, awscfg.ConfigKeys...) }
```

The `sources:` entry is a free `map[string]any`, so the strict YAML decoder cannot catch a typo
inside it. The declared keys let the planner warn about an unknown key or a key of the wrong YAML
type. The type check assumes a string (`sources.StringOpt` reads any other type as unset). A key
the factory parses as a bool, number or list must also be passed to
`sources.RegisterTypedConfigKeys`, or the planner tells the operator to quote a value whose
quoting breaks the source; that factory must reject a wrong type itself. Shared sets live beside their parser (`awscfg.ConfigKeys`, `azcommon.ConfigKeys`).
`TestEverySourceDeclaresItsConfigKeys` (`internal/sources/builtin/coverage_test.go`) fails the
build for an in-tree plugin that declares none; a project-local plugin that declares none is
never warned about.

### Optional: `core.CaveatedSource`

A plugin that emits a field it cannot observe implements `Caveats() []core.SourceCaveat`
(`EvidenceType`, `Field` without `payload.`, `Detail`). The planner warns when the source is
bound, the binding accepts that type, and the policy's `pass_when` reads that field. The warning
changes no status, count or wire field.

Add a caveat only when both hold: the value is a safe default rather than a measurement, and a
shipped policy reads the field. Don't caveat:

- a platform constant that is true by definition (`gcp.firestore` `encryption_enabled`);
- a field the plugin omits where the schema allows it (`azure.compute` and `gcp.compute` leave
  `monitoring_enabled` unset; policies scope them out with `is_set`);
- a conservative but correct value (`aws.identity_center` `has_condition` is `false` because an
  assignment has no condition).

Anything that wraps a `SourcePlugin` must forward `Caveats()`; `asInstance`
(`internal/sources/instance.go`) does. List the caveated plugins live with
`grep -rln "func (.*) Caveats()" internal/sources`. Operator-facing list:
[configuration.md §Source caveats](../configuration.md#source-caveats).

## The factory contract

This is the one explanation of the registry pattern. Sources, vault backends and manual-evidence
readers all use it ([00](00-three-plugin-axes.md)).

- Each plugin package calls a registry function from `init()`. No switch on IDs exists anywhere.
- A `builtin` package blank-imports every in-tree plugin package (`internal/sources/builtin`,
  `internal/vault/builtin`, `internal/sources/manual/builtin`); `cmd/sigcomply` blank-imports the
  `builtin` packages. Adding an in-tree plugin is one new package plus one import line.
- The host looks a factory up by the configured ID (`sources.Build`, `vault.FromConfig`,
  `manual.buildReader`) and lists IDs for error messages (`sources.IDs()`).
- Project-local plugins register through the public façade in `plugin/plugin.go`
  (`plugin.RegisterSource`, `plugin.RegisterVaultBackend`, `plugin.RegisterManualReader`),
  because `internal/` is not importable from the customer's module. `sigcomply build` compiles
  them in. There is no runtime plugin loading.

The source factory signature (`internal/sources/factory.go`):

```go
type Factory func(ctx context.Context, env Env) (core.SourcePlugin, error)

type Env struct {
    Config          map[string]any // this source's block from .sigcomply.yaml
    FrameworkExtras map[string]any // framework data, e.g. the manual catalog
}

func RegisterFactory(id string, f Factory, keys ...string)
```

Each factory parses its own `Config` map (`sources.StringOpt`, `awscfg`, `azcommon`). `Env` has
no `Vault` field; a plugin that needs storage configures its own backend, as `manual.pdf` does. A
factory error stops the run with exit 3.

### Resolve credentials in the factory

`sources:` declares what the project audits, so a listed source with missing credentials is a
config error (exit 3) before collection, not a collection outcome.

| Family | Where the check happens |
|---|---|
| `github`, `gitlab`, `okta`, `active_directory` | `sources.ResolveToken` |
| `gcp.*` | `NewService`/`NewClient` resolve Application Default Credentials |
| `aws.*` | `awscfg.Load` retrieves credentials from the resolved provider |
| `azure.*` | `azcommon.NewCredential(ctx, scope)` mints one token |

Neither cloud SDK fails on its own: `awsconfig.LoadDefaultConfig` builds a lazy chain, and
`azidentity.NewDefaultAzureCredential` wraps failed sub-credentials instead of returning an
error. Both eager checks memoize (per `awscfg.Options`, per Azure scope), never cache a failure,
and time out after 60s. A backend that builds its own client owes the same check: the `s3` and
`azure_blob` manual readers and vault backends each carry one.

### plugin.yaml

In-tree plugins have no manifest: `ID()`, `Emits()` and the factory are the declaration. A
project-local `.sigcomply/plugins/<id>/plugin.yaml` is descriptive only. `sigcomply build` never
reads it, and `spec.LoadPluginManifest` has no production caller.

## Evidence types

Emit records whose `Type` is a registered evidence-type ID. The collector validates every payload
against the full draft-07 schema before signing. The first non-conforming record fails the
binding: the policy becomes `error` and the run exits 2. Fix the plugin or the schema; don't add
local validation. Schema design, versioning and project-local types:
[04a](04a-evidence-type-registry.md).

## Built-in plugins

Plugins live under `internal/sources/<vendor>/<service>/` (single-plugin vendors at
`internal/sources/<vendor>/`). The authority on what each emits is its `Emits()` method. Count
live, from the repo root:

| Figure | Command |
|---|---|
| Plugins per provider directory | `grep -rl --include='*.go' "sources.RegisterFactory(" internal/sources \| grep -v _test \| sed 's#internal/sources/##' \| cut -d/ -f1 \| sort \| uniq -c` |
| Evidence-type families | `ls internal/evidence_types/schemas \| sed 's/\.v[0-9]*\.json$//' \| sort -u \| wc -l` |
| Schema files (versioned IDs) | `ls internal/evidence_types/schemas/*.json \| wc -l` |
| Every accepted type has an emitter | `go test ./internal/sources/builtin/ -run TestEmitterCoverage` |

Don't copy these numbers into docs; customer-facing published counts are pinned by
`TestDocFiguresMatchCode`.

### Provider × evidence-type matrix

A ✓ means at least one plugin for that provider emits the type. Policies bind to types, so any ✓
in a row can stand in for any other.

| Evidence type | AWS | Azure | GCP | GitHub | GitLab | Okta | Active Directory | Manual |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `directory_user` | ✓¹ | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| `roster_entry` | ✓² | ✓ | ✓ | | | ✓ | ✓ | |
| `iam_access_key` | ✓ | | | | | | | |
| `iam_binding` | ✓³ | | ✓ | | | | | |
| `password_policy` (v2) | ✓ | ✓⁴ | ✓⁵ | | | ✓ | | |
| `okta_app` | | | | | | ✓ | | |
| `compute_instance` | ✓ | ✓ | ✓ | | | | | |
| `serverless_function` | ✓ | | | | | | | |
| `kubernetes_cluster` | ✓ | ✓ | ✓ | | | | | |
| `container_registry` | ✓ | ✓ | ✓ | | | | | |
| `object_storage_bucket` | ✓ | ✓ | ✓ | | | | | |
| `managed_database_instance` | ✓ | ✓ | ✓ | | | | | |
| `nosql_table` | ✓ | ✓ | ✓ | | | | | |
| `backup_plan` | ✓ | ✓ | ✓ | | | | | |
| `network` | ✓ | ✓ | ✓ | | | | | |
| `firewall_rule` | ✓ | ✓ | ✓ | | | | | |
| `kms_key` | ✓ | ✓ | ✓ | | | | | |
| `secret` | ✓ | ✓ | ✓ | | | | | |
| `tls_certificate` | ✓ | ✓ | ✓ | | | | | |
| `log_group` | ✓ | ✓ | ✓ | | | | | |
| `audit_log_trail` | ✓ | ✓ | ✓ | | | | | |
| `config_change_tracking` | ✓ | ✓ | ✓ | | | | | |
| `threat_detection_service` | ✓ | ✓ | ✓ | | | | | |
| `security_service` | ✓ | ✓ | ✓ | | | | | |
| `vulnerability_finding` | ✓ | ✓ | ✓ | ✓ | | | | |
| `security_alert` | ✓ | | | | | | | |
| `git_repository` | | | | ✓ | ✓ | | | |
| `source_control_org_policy` | | | | ✓ | | | | |
| `pull_request` | | | | ✓ | ✓ | | | |
| `deployment` | | | | ✓ | ✓ | | | |
| `signed_document` | | | | | | | | ✓ |

¹ `aws.iam` emits `directory_user.v2`; every other emitter, including `aws.identity_center`,
emits `directory_user`. v2's required `is_root` and access fields describe an IAM account and
have no analog for an SSO identity. Slots accept both versions.

² `aws.identity_center` is the only AWS emitter of `roster_entry`. When an upstream IdP
SCIM-syncs into Identity Center, designate the IdP as the roster and use Identity Center as an
account source. Identity Center exposes no per-user MFA, so its `mfa_enabled` is `false` and
caveated; bind `soc2.cc6.1.mfa_enforced_all_users` to the real IdP.

³ `aws.identity_center` emits one `iam_binding` per permission-set assignment, as made: a group
assignment stays a `group` principal, so the least-privilege policies (which recommend granting
admin through groups) don't flag the recommended pattern. `directory_user.is_admin` asks a
different question and does resolve group membership. `is_broad_admin_role` reads AWS-managed
policies and the permission-set name only, so admin reached through an inline or
customer-managed policy under a neutral name is missed.

⁴ `azure.entra` emits one `password_policy.v2` per verified domain with only `max_age_days` set.
Minimum length, reuse and complexity are listed in `not_configurable` and left absent, because
they are not tenant settings; policies reading them report vacuous for Entra records. A federated
domain carries no `max_age_days`.

⁵ `gcp.cloud_identity` reads the Cloud Identity Policy API. Complexity is `strength_enum`, never
per-class booleans. The plugin reduces policies by Google's precedence itself (admin policies
above the system baseline) and lists fields that fell back to Google's documented default in
`defaulted`. It needs super-admin domain-wide delegation, paces itself to the 1 QPS quota, and
has no cassette ([12](12-multicloud-sources.md)).

### Plugins that emit more than one type

Every other plugin emits one type; read its `Emits()`.

| Plugin | Emits |
|---|---|
| `aws.identity_center` | `directory_user`, `roster_entry`, `iam_binding` (a roster-only slot skips the permission-set traversal) |
| `gcp.directory` | `directory_user`, `roster_entry` |
| `gcp.scc` | `threat_detection_service`, `security_service`, `vulnerability_finding` (org-scoped: `organization_id`) |
| `azure.entra` | `directory_user`, `roster_entry`, `password_policy.v2` |
| `azure.network` | `firewall_rule` (NSG Allow rules only), `network` |
| `azure.keyvault` | `kms_key`, `secret` (management plane only) |
| `azure.monitor` | `log_group`, `audit_log_trail` |
| `azure.defender` | `threat_detection_service`, `security_service`, `vulnerability_finding` |
| `github` | `git_repository`, `directory_user`, `source_control_org_policy`, `vulnerability_finding`, `pull_request`, `deployment` |
| `gitlab` | `git_repository`, `directory_user`, `pull_request`, `deployment` |
| `okta` | `directory_user`, `okta_app`, `roster_entry`, `password_policy.v2` |

`active_directory` emits only `roster_entry` (AD has no MFA signal). `manual.pdf` emits only
`signed_document`. Per-field vendor mappings are documented in each plugin's package comment and
code; customer-facing credentials and permissions are in
[docs/reference/sources.md](../reference/sources.md).

## The manual.pdf plugin

`manual.pdf` reads uploaded documents for `evidence_mode: manual` policies. It is a
project-level singleton: one instance, one bucket, configured under `sources.manual.pdf`;
`"manual.pdf[secondary]"` fails config validation (exit 3). The contract (folder scheme, cadence
window, file checks, failure codes, fan-out, what is never checked) is owned by
[14-manual-evidence.md](14-manual-evidence.md).

Plugin-side facts:

- Code: `internal/sources/manual/` (`manual.go`: `scanFolder`, `validatePDF`; `factory.go`:
  `build`, `buildReader`; `fileconv`, `pdfmerge`). Default `prefix` is `manual/`.
- Reader backends: `local` (registered in `factory.go`), `s3`, `gcs`, `azure_blob` (packages
  blank-imported by `manual/builtin`). `s3` with `endpoint` and `force_path_style` serves
  S3-compatible stores.
- The catalog is generated in Go from each framework's `manualSpecs()`; the runtime catalog
  reaches the factory through `Env.FrameworkExtras`. Fan-out members are added by
  `internal/vendorfanout` before that.
- The plugin computes the temporal window (with the entry's `GracePeriod`) and the prior-period
  comparison; the evaluator only reads the resulting booleans.
- Validation failures are in the signed record's `validation_failures` and in `result.json`, not
  in `manifest.json`. The record carries `file_hash` and a `sha256` per source file. The merged
  PDF rides on the record as a `core.Attachment` (never serialized) and the collector writes it
  to `policies/{policy_id}/attachments/` (see `14-manual-evidence.md`).
- Missing evidence fails with `manual evidence not found; expected files in: <uri>`
  (`internal/evaluator/manual_check.go`).

## Multiple plugin instances (API plugins only)

Configure a plugin again under a bracketed key to add an instance:

```yaml
sources:
  aws.iam:
    region: us-east-1
  "aws.iam[staging]":
    region: us-east-1
    role_arn: arn:aws:iam::210987654321:role/SigComplyAudit
```

- Instances auto-bind like any source; a `one-or-more` slot gets the union. An `exactly-one` slot
  (such as `roster`) with two candidates is a plan error: name the instance in `bindings:`.
- The instance key is the plugin's ID for the run: registry key, binding name, record
  `source_id`, and part of the envelope filename. An unknown instance key is an error, never a
  fallback to the default instance.
- `asInstance` prefixes the record `id` with the instance key, because many IDs repeat across
  accounts (`aws.password_policy` emits `account`; GCP's `default` network). Without it, two
  accounts' violations would dedupe into one. `IdentityKey` is not prefixed: it is the
  cross-source join key. Unbracketed sources are unchanged.
- A second account needs a second identity. `aws.*` instances take `role_arn` (plus
  `external_id`, `role_session_name`); there is no `profile` key, because environment credentials
  outrank a profile on CI runners. `github`, `gitlab` and `okta` take their own token or
  `token_env`. `gcp.*` and `azure.*` instances vary `project_id`/`subscription_id` but share one
  ambient identity. Not built: per-instance GCP impersonation and Azure per-tenant credentials.
- Credential routing: a source reads a credential from the environment only through
  `sources.ResolveToken`, which refuses a `token_env` naming a CI or cloud credential (`AWS_*`,
  `ACTIONS_*`, `GOOGLE_*`, `AZURE_*`, `ARM_*`, `CLOUDSDK_*`, `CI_JOB_*`, `*ID_TOKEN*`, GitLab's
  predefined passwords, `CI_REPOSITORY_URL`, `VAULT_TOKEN`).
  A URL the credential is sent to goes through `sources.ResolveEndpoint` (or, for a vault
  backend, `endpoint.ValidateHTTPS`): `https://`, or `http://` only to a loopback host
  (`localhost`, `127.0.0.1`, `::1`). The config file is repository content anyone with push
  access edits, so without both a branch could point a source at its own host with the job's
  AWS keys as the "token". Active Directory keeps its own `ldaps://` or StartTLS rule. An Azure
  storage `account` becomes a host name, so it must match Azure's 3 to 24 lowercase letters and
  digits (`endpoint.ValidateAzureStorageAccount`). A pagination link the server returns (GitHub
  and Okta `Link` headers, Graph `@odata.nextLink`) goes through `sources.FollowableLink`: same
  scheme and host as the API base, no user info, under its path. Guards: the `forbidigo` linter
  (`os.Getenv` in `internal/sources`), the registry-wide endpoint and host-key tests in
  `internal/sources/builtin` and `internal/vault/builtin`, and
  `TestPaginationLinksGoThroughFollowableLink`.
- A second region uses the same mechanism: regional `aws.*` plugins read only `region`
  (`awscfg.Load`), so per-region instances (`"aws.ec2[eu]"`) are how an estate with several
  regions is covered. There is no `regions:` list; `aws.s3` alone routes each bucket to its own
  region inside one Collect. Customer guidance: `docs/reference/sources.md` §Regions.
- Source keys and catalog IDs become part of vault object keys, so both are restricted to
  letters, digits, dot, dash and underscore (plus `[instance]`). Only the local vault rejects path
  escapes; the grammar protects the cloud backends.

## Record scope: provenance, not configuration

`core.EvidenceRecord.Scope` (`*core.RecordScope`: `Account`, `Region`, `Project`, all
`omitempty`) records where an observation was read from.

- It is inside the envelope signature, so one envelope proves its own origin.
- Stamp only what the API call was addressed to, or what the API returned. `azure.entra` resolves
  the tenant from the credential (`GET /organization`) and refuses to run if a declared
  `tenant_id` disagrees. `gcp.directory` leaves it unset for the `my_customer` alias.
- It never crosses the aggregation boundary, and nothing evaluates or aggregates by it.

Stamped by project-scoped `gcp.*` plugins (`Project`), `gcp.scc` (organization),
`gcp.directory` and `gcp.cloud_identity` (customer), ARM-plane `azure.*` plugins (subscription),
`azure.entra` (tenant) and `aws.identity_center` (identity store on identity records, target
account on `iam_binding`). List live with `grep -rln "RecordScope{" internal/sources`. Assert it
in conformance tests with `sourcetest.Options.WantScope` (not usable by `aws.identity_center`,
which stamps two kinds of boundary).

## Slot params

`policies.<id>.bindings.<slot>[].slot_params` is parsed and forwarded in `SlotRequest.Params`,
but no in-tree plugin reads a user-supplied key. Plugins read only planner-stamped keys:
`period_start`, `period_end`, `prior_period_id`, `catalog_id`, `period_id`, `now`. Not built:
plugin-side filtering through `slot_params`.

## How third parties contribute a source

1. Create `.sigcomply/plugins/<id>/` with a Go package whose name matches the directory.
2. Implement `plugin.SourcePlugin` and call `plugin.RegisterSource(id, factory, keys...)` in
   `init()`.
3. If no shipped type fits, add `.sigcomply/evidence_types/<id>.v<n>.json`. JSON schemas there
   load at startup without a rebuild (`loadProjectEvidenceTypes`).
4. Run `sigcomply build` to produce `./bin/sigcomply` with the plugin compiled in.

Walkthrough: [07-extensibility.md](07-extensibility.md). Upstream contributions are in-tree
plugins (§The factory contract).

## Plugin invariants (checklist)

- Return the same records for the same external state and config. The collector sorts by `ID`.
- Set `IdentityKey` when the type has a cross-source identity
  ([03 §Cross-source dedup](03-policy-spec.md#cross-source-dedup-clause-level-identity_key)).
- Use `CollectedAt` for fetch time; don't add synthetic timestamps to payloads.
- Own the whole vendor-to-canonical mapping. Never put a placeholder (`null`, `""`, `0`, `false`)
  in a required field; if a vendor lacks the concept, fix the schema
  ([04a §The null trap](04a-evidence-type-registry.md#the-null-trap)).
- Return every error from `Collect`; the collector decides the policy effect. No partial results.
- Never log, serialize or persist credentials. Return errors rather than printing.
- Read only. The CLI never changes the systems it audits.
- Respect vendor rate limits: create any limiter in the factory, apply it in `Collect`.
- Classify errors: return `*sources.APIError` or implement `Retryable() bool`
  (`internal/sources/errors.go`). 429, 5xx and timeouts retry; 401, 403, 404 and schema failures
  stop the binding. Unclassified errors are retried.

## Testing a source plugin (checklist)

Every in-tree plugin ships these, using `internal/sources/sourcetest`. The `github` plugin is the
worked example. Layer model and conventions: [11-testing-strategy.md](11-testing-strategy.md).

1. Conformance: `sourcetest.RunConformance`, once per emitted type when there are several
   (schema-valid, complete, deterministic with an injected clock).
2. Cassettes: recorded with `sourcetest.RecordClient`, replayed with `sourcetest.ReplayClient`,
   under the plugin's `testdata/cassettes/`.
3. Contract snapshot: `contracts/<provider>/<service>@<version>.json`, checked with
   `sourcetest.NewSpecValidator` ([`contracts/README.md`](../../contracts/README.md)).
4. Clean fixtures: no real credentials or identities; `make check-fixtures` enforces it.

`active_directory` (LDAP, not HTTP) replaces 2 and 3 with a scripted BER responder
(`internal/sources/activedirectory/fakedc_test.go`).
