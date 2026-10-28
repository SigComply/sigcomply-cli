# 12. Multi-cloud and multi-instance sources

Rules every provider plugin follows (naming, layout, registration, authentication, instances,
dependencies) and the cross-vendor identity contract. The factory contract and the provider ×
evidence-type matrix are owned by [04-source-plugins.md](04-source-plugins.md); schemas and
versioning by [04a-evidence-type-registry.md](04a-evidence-type-registry.md). Per-source config
keys and permissions for customers: [`../reference/sources.md`](../reference/sources.md).

## Why a new provider is mostly mechanical

A policy accepts an evidence type, never a vendor. The schemas are cloud-neutral
(`object_storage_bucket`, `managed_database_instance`, `directory_user`, `firewall_rule`), so a new
provider almost always emits into existing types and needs no policy change. One "object storage
encrypted at rest" policy covers S3, GCS and Azure Blob because all three emit
`object_storage_bucket`.

To count plugins or types live: the blank imports in `internal/sources/builtin/builtin.go`, and
the files in `internal/evidence_types/schemas/`.

## Source IDs

- Single-service providers use `<provider>`: `github`, `gitlab`, `okta`, `active_directory`.
- Multi-service providers use `<provider>.<service>`: `aws.s3`, `gcp.storage`, `azure.entra`.
- `<service>` names the cloud service, not the evidence type. One plugin may emit several types
  (`azure.keyvault` emits `kms_key` and `secret`). Keep a plugin to one underlying service.
- `gcp.cloud_identity` is named for the API, not for `password_policy`: the Cloud Identity Policy
  API serves many setting types through one endpoint, credential and quota.

## Package layout and conventions

- Multi-service providers nest one Go package per service: `internal/sources/<provider>/<service>/`.
- Single-plugin providers are flat: `internal/sources/<provider>/`. The package drops underscores
  (`activedirectory/`); the source ID keeps them.
- `factory.go` holds `const SourceID`, an `init()` calling `sources.RegisterFactory(SourceID,
  build, <config keys>...)`, and `build(ctx, env)`.
- `<service>.go` holds the `Plugin`, `Options`, `New`, the `ID`/`Emits`/`Init`/`Collect` methods,
  a small `API` interface that tests fake and the real SDK adapter.
- Test files and `testdata/` follow [11-testing-strategy.md](11-testing-strategy.md#4-conventions).

Every plugin:

1. Injects `Now()`; never calls `time.Now()` directly in mapping code.
2. Sorts records by `ID`.
3. Sets `IdentityKey` for identity types.
4. Wraps errors with context and handles pagination.
5. Populates every `required` field of each emitted schema.

### Registration

A plugin registers in `init()`, so it must be blank-imported in
`internal/sources/builtin/builtin.go`. `internal/sources/builtin/coverage_test.go` discovers
factories and fails if any accepted evidence type has no emitter. Plugins that cannot be built
without credentials (`gcp.iam`, `azure.entra`) use the hard-coded `Emits()` fallback in that test.
AWS plugins build there under static dummy credentials with no network call.

## Authentication per provider

Auth is read-only. In CI, prefer keyless federation (OIDC, workload identity) over long-lived
secrets. A factory must resolve credentials, not only build a client: a listed source with no
credentials is a config error (exit 3) before collection.

- **AWS**: SDK default chain, resolved eagerly by `awscfg.Load`. Optional `role_arn`,
  `external_id`, `role_session_name` assume a role from the ambient identity
  (`awscfg.ConfigKeys`). The cache is keyed by the whole `Options` value.
- **GCP**: Application Default Credentials (Workload Identity Federation in CI); config key
  `project_id`. `gcp.directory` and `gcp.cloud_identity` use domain-wide delegation; each scope
  must be allow-listed verbatim (a broader scope fails with `unauthorized_client`).
- **Azure**: `DefaultAzureCredential` (workload identity in CI, else `AZURE_TENANT_ID`,
  `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`). `azcommon.NewCredential(ctx, scope)` mints one token
  before returning a plugin and memoizes the verified credential per scope (ARM, Graph). The key
  is the scope alone because the process has one ambient identity; per-tenant credentials would
  need a tenant component in the key. ARM clients are scoped by `subscription_id`; Entra uses the
  Graph v1.0 REST API over `net/http` with the same credential. Config keys:
  `azcommon.ConfigKeys`.
- **GitHub, GitLab, Okta, Active Directory**: `sources.ResolveToken` resolves the secret in this
  order: config key, the variable named by `token_env`, then a shared fallback variable.
  GitHub: key `token`, fallback `GITHUB_TOKEN`, plus `org` and `base_url` (GitHub Enterprise
  Server). GitLab: key `token`, fallback `GITLAB_TOKEN`, plus `group` and `base_url`
  (self-managed). Okta: key `api_token`, fallback `OKTA_API_TOKEN`, plus `org_url`. Active
  Directory: bind DN and password over LDAPS or StartTLS. Each factory's `RegisterFactory` call
  lists its keys.

## Multiple instances of one source

A `sources:` key may carry a bracketed instance name: `aws.iam[staging]`, `github[labs]`. Each
instance is a second, independently configured copy of the plugin (another account, project,
subscription or org). Worked config:
[`examples/multi-account.sigcomply.yaml`](examples/multi-account.sigcomply.yaml).

Rules (`internal/sources/instance.go`, `internal/sources/factory.go`):

1. Grammar: `sources.IDPattern`, a base ID plus optional `[name]` of letters, digits, `.`, `_`,
   `-`. The key becomes part of an envelope path in the vault, so `/` and `..` are rejected.
2. Factories register under the base ID only. An instance key builds from the base factory.
3. `asInstance` wraps a bracketed plugin. The wrapper reports the instance key as its ID and
   rewrites each record's `SourceID` to the key and `ID` to `<key>/<id>`. Without this, record IDs
   that are unique only within one account (`aws.password_policy` emits `account`) collide, the
   evaluator dedups two accounts' violations into one, and one `resource_id` exception waives
   both.
4. `IdentityKey` is not namespaced: it is the cross-source join key (one email in Okta and AWS
   IAM).
5. Plain keys are not wrapped; their records are unchanged.
6. The wrapper forwards every optional interface the inner plugin implements
   (`core.CaveatedSource` today). A missed forward fails silently.
7. Lookups are exact (`lookupSourcePlugin` in `internal/planner/bindings.go`). A typo such as
   `aws.iam[bakcup]` is an error, never a fallback to another instance.
8. Region is not an account boundary. Two AWS instances that differ only by `region` collect the
   same account twice. Give each instance its own identity: `role_arn` for AWS, `token_env` for
   token-based sources, `project_id` or `subscription_id` for GCP and Azure.
9. `manual.pdf` is a project singleton and rejects instance keys (`spec` validation).
10. `experimental.scope.required_sources` lists each instance key separately; `aws.iam` does not
    assert `aws.iam[staging]`.

## Dependency policy

Add a vendor SDK module in the change that first imports it; `go mod tidy` removes anything added
ahead of use. Entra calls Microsoft Graph over `net/http` with no SDK. GitLab uses
`gitlab.com/gitlab-org/api/client-go`. Check `go.mod` for what is present.

## Cross-vendor identity contract (`directory_user`)

Every account-bearing identity source emits `directory_user`. Active Directory emits only
`roster_entry`. `aws.identity_center` emits `directory_user`, `roster_entry` and `iam_binding`.
The roster policies' subject slot accepts the `directory_user` family plus `iam_binding`
(`rosterSubjectTypes`), so a cloud grant is joined to the roster on its principal.

Rules:

1. **Decision 1: only AWS IAM emits `directory_user.v2`.** v2 adds required `is_root`, `has_console_access`,
   `has_programmatic_access`, which describe an IAM account. Every other source, including
   `aws.identity_center`, emits v1 and never fabricates them. If an SSO source emitted v2, the
   v2-only policies (`soc2.cc6.1.root_mfa_enabled`, `soc2.cc6.1.no_root_access_keys`,
   `soc2.cc6.1.no_direct_iam_policies` and their ISO 5.15 counterparts) would pass on it trivially.
2. **Decision 2: populate `is_admin` and `is_active`** although the schema marks them optional. The admin-MFA
   policies (`soc2.cc6.1.mfa_enforced_admins`, `iso27001.8.2.privileged_mfa_enforced`) read
   `is_admin`. A referenced field the record lacks gives status `error` (`evalCondition` in
   `internal/evaluator/pass_when.go`), and the run exits 2. Derive `is_admin` from the vendor's
   admin signal (org owner, super admin, privileged role); derive `is_active` from account status,
   or `true` when the API lists only active identities. The `is_active` schema text "Absent means
   assume active" is not applied by the evaluator.
3. **The grant record mirrors the assignment as made; the person record answers about the
   person.** `iam_binding.principal_type` stays `group` for a group grant, because the
   least-privilege policies flag direct user grants and recommend groups. `is_admin` on the user
   does resolve group membership (`aws.identity_center` walks permission sets, account
   assignments and `identitystore:ListGroupMemberships`).
4. **Conservative is not fabricated.** A value computed in the failing direction is acceptable
   (`is_broad_admin_role` over-reports; `has_condition` is `false`). Inventing a value the source
   cannot observe is not.
5. **Optional fields** (`email`, `is_external`, `is_service_account`, `mfa_factor_count`,
   `last_login_at`) may be omitted. A policy that reads them must `is_set`-guard them, in the
   condition or the filter.

Known limits:

- `aws.identity_center` cannot read per-user MFA (no public API), so it emits `mfa_enabled: false`.
  This can only fail a policy. An estate that needs a real verdict binds the IdP (`okta`,
  `azure.entra`, `gcp.directory`) to the MFA policies' slot with a `bindings:` override
  ([pin a policy to one source](../guides/configure-sources.md#pin-a-policy-to-one-source)).
- `gitlab` gets a member's `two_factor_enabled` only with an instance-admin token, which no
  gitlab.com customer has, so on gitlab.com it emits `mfa_enabled: false` for every member. The
  remedy is the same `bindings:` override. It lists members of the configured group only (direct,
  inherited from ancestors, invited), not people who are members only of a subgroup or project.
- `okta` counts a factor towards `mfa_enabled` unless it is a security question or email
  (knowledge factor; no device possession, NIST SP 800-63B 5.1.3.1).
- A permission set that grants admin through an inline or customer-managed policy with an
  unremarkable name reads as not broad. Closing it means parsing IAM policy documents.

## `password_policy` emitters

Schema shape, versions and emitter rules: [04a, password_policy
versions](04a-evidence-type-registry.md#password_policy-versions). Per-emitter behaviour:

- `aws.password_policy` and `okta` emit v2 with `complexity_model: per_class`. An AWS account
  with no password policy gets one record with `complexity_model: none` and zero length and age
  (AWS answered "no policy"), so the consuming policies flag it.
- `azure.entra` emits one record per verified domain from `GET /domains` (`Domain.Read.All`, no
  P1/P2). `max_age_days` comes from `passwordValidityPeriodInDays`, with Microsoft's never-expires
  sentinel `2147483647` mapped to `0`; it is omitted for federated domains. `not_configurable`
  lists `min_length`, `reuse`, `complexity`. It does not emit `complexity_model: fixed`.
- `gcp.cloud_identity` emits one record per `settings/security.password` policy, with
  `complexity_model: strength_enum`. Omitted fields carry Google's documented default and are
  listed in `defaulted`. The API has no effective-policy endpoint: the plugin ranks `ADMIN`
  policies above `SYSTEM`, orders by `sortOrder`, and fills gaps down the customer-wide order (an
  approximation across disjoint org-unit branches, since the API returns no OU tree). The quota is
  1 QPS per customer, so the plugin never parallelizes. Access needs a super admin through
  domain-wide delegation with `cloud-identity.policies.readonly`. It has no L2 cassette by design
  ([11](11-testing-strategy.md#recorded-and-hand-authored-cassettes)).

A control no configured source can answer can be marked `na` with a reason under
`policies.<id>.exceptions` ([`../configuration.md`](../configuration.md)). `na` leaves the score
denominator like `skip` does, but the exclusion is recorded in the config.
