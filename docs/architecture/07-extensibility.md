# 07: Extensibility

Customers extend the CLI project-locally, under `.sigcomply/` in their repo. This page owns what
can be extended, how each kind loads, and the path from a project-local extension to an
upstream contribution. Every example below was loaded by a real `sigcomply check` (or
`sigcomply build`) run.

## What loads, and how

| Kind | Where | How it loads |
|---|---|---|
| Policy | `.sigcomply/policies/<id>/policy.yaml` | Data. Read at bootstrap by `registerProjectLocal` (`internal/orchestrator/project_local.go`) on every `sigcomply check`. |
| Rego rule | `.sigcomply/policies/<id>/rule.rego` | Code, compiled at bootstrap against a restricted builtin set: no network, environment, clock or randomness (below). |
| Evidence type | `.sigcomply/evidence_types/*.json` | Data. Read at bootstrap; see [`04a-evidence-type-registry.md`](04a-evidence-type-registry.md). |
| Source plugin | `.sigcomply/plugins/<id>/` | Go. Compiled in by `sigcomply build`; `init()` calls `plugin.RegisterSource`. |
| Vault backend | `.sigcomply/plugins/<id>/` | Go. `init()` calls `plugin.RegisterVaultBackend`. |
| Manual-evidence backend | `.sigcomply/plugins/<id>/` | Go. `init()` calls `plugin.RegisterManualReader`. |

There is no runtime plugin loading (no `.so`, IPC or WASM). The three Go kinds are the three
plugin axes in [`00-three-plugin-axes.md`](00-three-plugin-axes.md).

## Limits

- Frameworks, the manual-evidence catalog, the aggregation contract and the vault layout are not
  extensible. A customer adds policies; it cannot replace a framework or redefine a shipped
  evidence type.
- A project-local manual policy cannot add a catalog entry. It must point `catalog_entry:` at an
  entry the framework already declares (`sigcomply evidence catalog -f <fw>` lists them).
  Otherwise the `manual.pdf` plugin fails with `catalog entry "<id>" not declared` and the policy
  is tagged `error`.
- Go rules (`.sigcomply/policies/<id>/rules/`) and Go evidence types
  (`.sigcomply/evidence_types/<id>/`) are compiled by `sigcomply build` but never loaded: the
  rule registry is filled only from each framework's `Rules()`, and evidence types register only
  from JSON. `sigcomply build` prints a warning for both. Use `rule.rego` and a JSON schema.
- `plugin.yaml` in a plugin directory is never read. `spec.LoadPluginManifest` has no production
  caller. A plugin's `Emits()` is the only declaration that counts.
- There is no setting for the extensions directory: both `sigcomply build` and the bootstrap
  loader use `.sigcomply/`. A config that sets the removed `extensions.path` key fails at load.

## Project-local policies

Every policy needs `id`, `control`, `description`, `evidence_mode`, `severity` and `cadence`
(`internal/spec/policy.go`), and its `id` must not clash with a shipped one. The `id` names a
folder in every run and the policy's state file, so it uses the source-key grammar
(`vaultkey.IDPattern`): letters, digits, `.`, `_` and `-`, starting with a letter or digit. `control` is the
active framework's control ID (`CC6.1`, not `SOC2.CC6.1`); a project has one framework, so a
project-local policy belongs to it. An ID not in that framework's control catalog is a config
error, exit 3. Field reference and the `pass_when:` DSL:
[`03-policy-spec.md`](03-policy-spec.md).

A project-local policy appears in run output and on the cloud payload like a shipped one,
including its own `id` and `category`.

### Manual

```yaml
# .sigcomply/policies/acme.custom.cc6.3.contractor_review/policy.yaml
schema_version: policy.v1
id: acme.custom.cc6.3.contractor_review
evidence_mode: manual
control: CC6.3
severity: high
category: access_control
cadence: quarterly
description: Quarterly review of contractor access, signed by the engineering manager.
remediation: Perform the review and upload the signed PDF.
catalog_entry: access_review_quarterly   # must be a framework catalog entry
```

A manual policy has no `slots`, `pass_when:` or `rule:`. It shares the upload folder of the
catalog entry it names, so it passes or fails together with the shipped policy that uses the
same entry.

### Automated with `pass_when:`

```yaml
# .sigcomply/policies/acme.custom.cc6.1.mfa_enforced/policy.yaml
schema_version: policy.v1
id: acme.custom.cc6.1.mfa_enforced
evidence_mode: automated
control: CC6.1
severity: high
category: access_control
cadence: daily
description: Every user in the directory must have MFA enabled.
slots:
  evidence:
    accepts: [directory_user, directory_user.v2]
    cardinality: one-or-more
    required: true
pass_when:
  slot: evidence
  quantifier: all
  condition: { op: eq, field: payload.mfa_enabled, value: true }
```

Set `required: true` on every slot the check cannot do without. A required slot with no bound
source makes the policy `skip`. A slot that is not required evaluates over zero records, and
`all` over nothing is a vacuous `pass`, but only while another slot is bound: when no slot has a
bound source, the policy skips.

A `filter` that reads a schema-optional field must guard it with `is_set` inside `all_of`; see
[`03-policy-spec.md`](03-policy-spec.md) and the universal-field test in
[`04a-evidence-type-registry.md`](04a-evidence-type-registry.md).

### Automated with a Rego rule

Use `rule:` only for what `pass_when:` cannot express (cross-slot key joins are `pass_when:`'s
`matches_in`). The Rego `package` path is the rule ID, and the loader queries
`data.<package>.result`. `result` must be an object with a `status` string (`pass`, `fail`, ...)
and an optional `violations` array of `{resource_id, reason, details}`. Records arrive as
`input.slots.<slot>[_]`, each with `id`, `identity_key` and `payload`; parameters as
`input.params`.

```yaml
# .sigcomply/policies/acme.custom.cc6.1.contractor_count/policy.yaml
schema_version: policy.v1
id: acme.custom.cc6.1.contractor_count
evidence_mode: automated
control: CC6.1
severity: medium
category: access_control
cadence: daily
description: No more than 10 external identities.
slots:
  users:
    accepts: [directory_user, directory_user.v2]
    cardinality: one-or-more
    required: true
rule: sigcomply.acme.contractor_count
```

```rego
# .sigcomply/policies/acme.custom.cc6.1.contractor_count/rule.rego
package sigcomply.acme.contractor_count

import rego.v1

external := [u | some u in input.slots.users; u.payload.is_external == true]

result := {"status": "pass"} if count(external) <= 10

result := {"status": "fail", "violations": [{"resource_id": "external_identities", "reason": sprintf("%d external identities", [count(external)])}]} if count(external) > 10
```

`is_external` is optional in `directory_user.v2`, so a record without it simply does not count
here. A Rego rule gets no `is_set` protection from the evaluator; handle absent fields yourself.

A rule is code evaluated over evidence that may be sensitive, so it runs as a pure function of
its input. `NewRegoRule` (`internal/evaluator/rego_rule.go`) compiles every module against
`regoCapabilities`: OPA's builtins minus each one OPA marks non-deterministic. A module that
calls `http.send`, `net.lookup_ip_addr`, `json.match_schema`/`json.verify_schema` (remote
`$ref`), `opa.runtime` (the CLI's environment), `time.now_ns`, `rand.intn`, `uuid.rfc4122` or the
`io.jwt` signing and verifying builtins fails to load, and `check` stops with the compile error.
Use `input.now` (RFC 3339, the run's clock) instead of `time.now_ns()`. The pure
`net.cidr_*` helpers stay. Builtin errors are strict: a builtin that fails (a malformed
timestamp, for example) makes the policy `error` instead of leaving a value undefined. The
allowed list is pinned in `internal/evaluator/testdata/rego_builtins.golden`; an OPA upgrade that
adds a builtin fails `TestRegoBuiltinsGolden` until someone reviews it.

### Evidence types

Drop a JSON Schema at `.sigcomply/evidence_types/<id>.v<n>.json`; no build step. Format, loading
and validation rules: [`04a-evidence-type-registry.md`](04a-evidence-type-registry.md).

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "acme_principal",
  "version": 1,
  "description": "An Acme user with internal-only fields. Cross-source key: email.",
  "type": "object",
  "required": ["id", "mfa_enabled", "department"],
  "properties": {
    "id": { "type": "string" },
    "email": { "type": "string", "format": "email" },
    "mfa_enabled": { "type": "boolean" },
    "department": { "type": "string" },
    "security_clearance": { "type": "string", "enum": ["public", "internal", "confidential", "secret"] }
  },
  "additionalProperties": true
}
```

## Loading

Go extensions need `sigcomply build`, which produces a project-tailored binary
(`runBuild`, `cmd/sigcomply/build.go`):

1. `DiscoverExtensions` looks for `.sigcomply/`. If it does not exist, the command does nothing.
   If it exists, `readModulePath` requires a `go.mod` at the project root, even when there is no
   Go code to compile (exit 3 otherwise). The default local vault path is `./.sigcomply/vault`
   (`spec.DefaultLocalVaultPath`), so a project with only a local vault, or only data
   extensions, has `.sigcomply/` and fails `sigcomply build` without a `go.mod`. Such a project
   does not need `sigcomply build` at all.
2. It discovers Go packages under `.sigcomply/plugins/<name>/`, `.sigcomply/policies/<name>/rules/`
   and `.sigcomply/evidence_types/<name>/`.
3. `ValidateExtensions` checks each package: the `package` name must equal the directory name
   with `.` and `-` replaced by `_`, and the top-level non-test files must not import `os/exec`,
   `net` or `net/*`.
4. It runs `go vet` on the packages.
5. `GenerateEntrypoint` writes `.sigcomply/.build/sigcomply-custom/main.go`, which imports
   `github.com/sigcomply/sigcomply-cli/cmd/sigcomply` and blank-imports every discovered package
   so each `init()` registers.
6. It runs `go build` from the project directory. The default output is `./bin/sigcomply`.

The import check is not a sandbox. It reads only top-level files and only direct imports, so a
nested package or a third-party HTTP client passes. Extension code runs in-process with the CLI's
credentials and vault access. Review `.sigcomply/` like application code.

`go build ./...`, `go test ./...` and `go mod tidy` skip directories that start with `.`, so they
never see `.sigcomply/`. Name the path instead: `go test ./.sigcomply/plugins/...`. For the same
reason `go mod tidy` drops the `sigcomply-cli` requirement; add it with `go get` instead.

## The public API package

Go extensions import only `github.com/sigcomply/sigcomply-cli/plugin`, the module's one
non-`internal` package. It re-exports, as type aliases, what the three axes need:

| Axis | Implement | Register from `init()` | Supporting types |
|---|---|---|---|
| Source plugin | `plugin.SourcePlugin` (`ID`, `Emits`, `Init`, `Collect`), optionally `plugin.CaveatedSource` | `plugin.RegisterSource(id, factory, configKeys...)` | `Env`, `SourceFactory`, `SlotRequest`, `EvidenceRecord`, `RecordScope`, `SourceCaveat` |
| Vault backend | `plugin.Vault` | `plugin.RegisterVaultBackend(id, factory)` | `VaultFactory`, `VaultConfig`, `Envelope` |
| Manual-evidence backend | `plugin.ManualReader` | `plugin.RegisterManualReader(id, factory)` | `ManualReaderFactory`, `ManualFileInfo`, `ErrManualNotFound` |

Aliases mean a `plugin.EvidenceRecord` is the exact struct the collector validates and signs.
The package exposes registration only, no lookup. [`plugin/doc.go`](../../plugin/doc.go) lists
what is excluded and why. Drift guards: `plugin/plugin_test.go`, `plugin/external_module_test.go`
and `TestRunBuild_CompilesRealPluginAgainstPublicAPI` (`cmd/sigcomply/build_test.go`).

## Authoring a custom source plugin

The worked example reads a user export that an earlier CI step wrote to disk, which fits the
import rules. A plugin that must call a network API belongs upstream, inside the CLI module.

```go
// .sigcomply/plugins/acme.internal_iam/plugin.go
package acme_internal_iam

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sigcomply/sigcomply-cli/plugin"
)

const SourceID = "acme.internal_iam"

type user struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	MFA   bool   `json:"mfa"`
	Admin bool   `json:"admin"`
}

type Plugin struct{ exportPath string }

func (p *Plugin) ID() string      { return SourceID }
func (p *Plugin) Emits() []string { return []string{"directory_user"} }

func (p *Plugin) Init(_ context.Context, cfg map[string]any) error {
	p.exportPath, _ = cfg["export_path"].(string)
	if p.exportPath == "" {
		return fmt.Errorf("%s: export_path is required", SourceID)
	}
	if _, err := os.Stat(p.exportPath); err != nil {
		return fmt.Errorf("%s: %w", SourceID, err)
	}
	return nil
}

func (p *Plugin) Collect(_ context.Context, _ plugin.SlotRequest) ([]plugin.EvidenceRecord, error) {
	data, err := os.ReadFile(p.exportPath)
	if err != nil {
		return nil, fmt.Errorf("%s: read export: %w", SourceID, err)
	}
	var users []user
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, fmt.Errorf("%s: parse export: %w", SourceID, err)
	}
	now := time.Now().UTC()
	out := make([]plugin.EvidenceRecord, 0, len(users))
	for _, u := range users {
		payload, err := json.Marshal(map[string]any{
			"id": u.ID, "email": u.Email, "mfa_enabled": u.MFA, "is_admin": u.Admin,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, plugin.EvidenceRecord{
			Type:        "directory_user",
			ID:          u.ID,
			IdentityKey: u.Email, // cross-source dedup with aws.iam, okta
			SourceID:    SourceID,
			CollectedAt: now,
			Payload:     payload,
		})
	}
	return out, nil
}

func init() {
	plugin.RegisterSource(SourceID, func(ctx context.Context, env plugin.Env) (plugin.SourcePlugin, error) {
		p := &Plugin{}
		if err := p.Init(ctx, env.Config); err != nil {
			return nil, err
		}
		return p, nil
	}, "export_path")
}
```

- The factory receives `plugin.Env{Config, FrameworkExtras}`. There is no vault field; a plugin
  that needs storage configures its own.
- Resolve credentials and inputs in the factory, so a listed source that cannot run is a config
  error (exit 3) before collection.
- The plugin sets `CollectedAt` to the fetch time.

Configure and build:

```yaml
# .sigcomply.yaml (excerpt)
sources:
  acme.internal_iam:
    export_path: ./users.json
```

```bash
go mod init example.com/acme-project
go get github.com/sigcomply/sigcomply-cli@<version of the sigcomply binary you build with>
sigcomply build
./bin/sigcomply check
```

Every policy whose slot accepts `directory_user` now binds the plugin with no policy edit,
including the shipped `soc2.cc6.1.mfa_enforced_*` policies. Use `bindings:` under `policies.<id>`
to choose sources explicitly ([`08-project-config.md`](08-project-config.md) §The binding model).

To feed fields `directory_user` lacks, register a project-local type (`acme_principal` above),
add it to `Emits()`, emit one record of each type per user, and write policies that accept the
new type. Shipped policies ignore records of types they do not accept.

## Custom vault backends

```go
// .sigcomply/plugins/acme.nfs_vault/vault.go
package acme_nfs_vault

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/plugin"
)

type Vault struct{ root string }

func (v *Vault) Init(ctx context.Context) error                                        { return nil }
func (v *Vault) PutEnvelope(ctx context.Context, key string, e *plugin.Envelope) error { return nil }
func (v *Vault) PutJSON(ctx context.Context, key string, body any) error               { return nil }
func (v *Vault) PutBinary(ctx context.Context, key string, body []byte, meta map[string]string) error {
	return nil
}
func (v *Vault) GetBinary(ctx context.Context, key string) ([]byte, error) { return nil, nil }
func (v *Vault) List(ctx context.Context, prefix string) ([]string, error) { return nil, nil }

func init() {
	plugin.RegisterVaultBackend("acme.nfs", func(ctx context.Context, cfg *plugin.VaultConfig) (plugin.Vault, error) {
		v := &Vault{root: cfg.Str("path")} // every key except backend stays in cfg
		return v, v.Init(ctx)
	})
}
```

```yaml
vault:
  backend: acme.nfs
  path: /mnt/sigcomply
```

`vault.FromConfig` looks up the backend ID and calls the factory. Layout and write rules are in
[`05-vault-layout.md`](05-vault-layout.md).

## Custom manual-evidence backends

```go
// .sigcomply/plugins/acme.sftp_manual/reader.go
package acme_sftp_manual

import (
	"context"
	"fmt"
	"time"

	"github.com/sigcomply/sigcomply-cli/plugin"
)

type Reader struct{ host string }

// Get returns plugin.ErrManualNotFound for a missing key; any other error is a transport failure.
func (r *Reader) Get(ctx context.Context, key string) ([]byte, time.Time, error) {
	return nil, time.Time{}, plugin.ErrManualNotFound
}

// List returns every file under prefix, sorted by key. Empty is not an error.
func (r *Reader) List(ctx context.Context, prefix string) ([]plugin.ManualFileInfo, error) {
	return nil, nil
}

func init() {
	plugin.RegisterManualReader("acme.sftp", func(raw map[string]any) (plugin.ManualReader, string, string, string, error) {
		host, _ := raw["host"].(string)
		if host == "" {
			return nil, "", "", "", fmt.Errorf("manual.pdf acme.sftp: \"host\" required")
		}
		bucket, _ := raw["bucket"].(string)
		prefix, _ := raw["prefix"].(string)
		if prefix == "" {
			prefix = "manual/"
		}
		return &Reader{host: host}, "sftp", bucket, prefix, nil // reader, URI scheme, bucket, prefix
	})
}
```

```yaml
sources:
  manual.pdf:
    backend: acme.sftp
    host: sftp.acme.internal
    bucket: acme-manual-evidence
    prefix: manual/
```

The `manual.pdf` plugin still resolves folders from the catalog; only the reads change. The
manual-evidence contract is in [`14-manual-evidence.md`](14-manual-evidence.md).

## Contributing upstream

1. Move the code in-tree: source plugins to `internal/sources/<vendor>/`, policies to Go
   `.policy()` builders in `internal/frameworks/<fw>/policies_*.go` (manual ones also in
   `manualSpecs()`), evidence types to `internal/evidence_types/schemas/<id>.v<n>.json`.
2. Swap the façade for internal imports: `plugin.SourcePlugin` becomes `core.SourcePlugin`,
   `plugin.RegisterSource` becomes `sources.RegisterFactory`, and so on.
3. Add the tests a source plugin owes ([`04-source-plugins.md`](04-source-plugins.md) testing
   checklist, [`11-testing-strategy.md`](11-testing-strategy.md)).

Step-by-step recipes: [`docs/claude/recipes.md`](../claude/recipes.md). Contribution rules:
[`CONTRIBUTING.md`](../../CONTRIBUTING.md).

## Compatibility guarantees

The unit of the promise is the `plugin` package: what it re-exports is what an extension may rely
on; nothing under `internal/` is. Released versions are `v0.x`, and before 1.0 the package may
change in any release (check the CHANGELOG). From 1.0 the rules are:

- `SourcePlugin`, `Vault`, `ManualReader` and the value types they name are append-only within a
  major version.
- Shipped evidence types change only by adding optional fields; a breaking change coins a new
  type version ([`04a-evidence-type-registry.md`](04a-evidence-type-registry.md)).
- The vault format stays readable across majors.

Adding an export to `plugin/` is a promise for the whole major version. Add one only when a
documented extension point needs it, and never widen an `internal/` API to make a re-export
easier.
