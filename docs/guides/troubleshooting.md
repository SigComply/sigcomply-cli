# Troubleshooting & FAQ

Common failures with the SigComply CLI, in problem → cause → fix form.
Start with the [exit code](#exit-codes) — it tells you which class of
problem you have.

Back to the [docs hub](../README.md).

## Exit codes

Every command uses the same four exit codes:

| Code | Meaning | Typical response |
|------|---------|------------------|
| `0` | Passed — no violations | Nothing to do |
| `1` | Violations found | Remediate, or waive via `exceptions:` in config |
| `2` | Execution error | A source/API/network/vault error mid-run |
| `3` | Configuration error | Fix `.sigcomply.yaml` or the command's flags |

`1` means the CLI ran correctly and found failing policies. `2` and `3`
mean the CLI could not complete the run.

## Configuration errors (exit 3)

`.sigcomply.yaml` is loaded with a **strict** parser (`yaml.KnownFields`),
so anything it does not recognize is rejected outright.

| Problem | Cause | Fix |
|---------|-------|-----|
| Exit 3, framework not resolved | Missing `framework:` key | Add `framework: soc2` (or `iso27001`). `check` has no default. |
| Exit 3, unknown field | Plural typo `frameworks:` | The key is **singular**: `framework:` |
| Exit 3, unknown field | Any unrecognized **top-level** key | Remove it; only documented top-level keys are allowed (see [../configuration.md](../configuration.md)) |
| Exit 3 on `ci.fail_severity` | Invalid severity value | Use one of `info` \| `low` \| `medium` \| `high` \| `critical` |
| Exit 3 planning a policy | A `bindings:` block keyed on a nonexistent slot (e.g. `user_directory`, `access_keys`) | The conventional slot name is **`evidence`**: `bindings: { evidence: [okta] }` |
| Exit 3 from `init` / `init-ci` | Output file already exists | Pass `--force` to overwrite |
| Exit 3 from `init-ci` | Framework other than `soc2` | `init-ci` is **SOC2-only in v1-alpha** |
| Exit 3 from `report` | `--period` omitted, or `--format pdf`, or non-text format without `--out` | Pass `--period`; `pdf` is deferred; add `--out <file>` for json/csv |

### `check` ignores `--framework` and `SIGCOMPLY_FRAMEWORK`

**Problem:** you set `SIGCOMPLY_FRAMEWORK` or expected a `--framework` flag
on `check`, and the framework isn't what you expect.

**Cause:** `check` reads `framework:` from the **loaded config only**. It
has no `--framework` flag and ignores the env var. (`SIGCOMPLY_FRAMEWORK`
only affects `init` and `evidence catalog`.)

**Fix:** set `framework:` in `.sigcomply.yaml`. A missing `framework:` is a
config error (exit 3), not a `soc2` default.

## Sources and credentials

### A source I expected didn't run

**Problem:** you have `AWS_*` (or `GITHUB_TOKEN`, etc.) in the environment
but the source is never collected.

**Cause:** **the CLI does not auto-register sources from credentials.** You
must list each source explicitly under `sources:`. Credentials resolve from
the environment, but the source itself has to be declared.

**Fix:** add the source to `.sigcomply.yaml`, for example:

```yaml
sources:
  aws.iam:
    region: us-east-1
```

See [configure-sources.md](configure-sources.md) for the per-source
required keys.

### Missing or wrong credentials

**Problem:** a source errors (exit 2) with an auth/permission failure.

**Cause:** credentials come from the ambient environment, never the config
file (`AWS_*`, `GITHUB_TOKEN`, GCP ADC, `OKTA_API_TOKEN`, …). All collectors
are read-only.

**Fix:** provide the credential in the environment and grant read-only
access (e.g. `ReadOnlyAccess` or a scoped read policy for AWS). See
[configure-sources.md](configure-sources.md) and
[../configuration.md](../configuration.md).

## Cloud submission

### No cloud submission is happening

**Problem:** runs succeed but nothing appears in the dashboard.

**Cause:** cloud submission only auto-enables when **all** of these hold:
the CLI is running in CI, a valid OIDC token is present, and `--no-cloud`
was not passed.

**Fix:**

- Confirm you are in CI (locally, submission is off by design).
- Wire OIDC — [ci-github.md](ci-github.md) or [ci-gitlab.md](ci-gitlab.md).
- Remove `--no-cloud`, or force it with `--cloud` (which errors if there is
  no OIDC token).
- Confirm the project's repo URL is connected in the dashboard — see
  [cloud-dashboard.md](cloud-dashboard.md).

### GitLab cloud submission is silently skipped

**Problem:** on GitLab, the run evaluates and writes your vault but nothing
reaches the dashboard, with no error.

**Cause:** an older GitLab template named the id_token `SIGCOMPLY_OIDC_TOKEN`,
but the CLI submitter reads the token from `SIGCOMPLY_ID_TOKEN` (fallback
`ID_TOKEN`). The mismatch means cloud submission is skipped. Current templates
scaffold the correct name, so this only affects `.gitlab-ci.yml` files generated
by an earlier CLI.

**Fix:** ensure your `id_tokens:` block uses `SIGCOMPLY_ID_TOKEN:` (not
`SIGCOMPLY_OIDC_TOKEN:`), or re-scaffold with
`sigcomply init-ci --ci gitlab --force`. Full detail in
[ci-gitlab.md](ci-gitlab.md).

### Submissions return HTTP 402

**Problem:** cloud submission fails with a `402` and an upgrade URL.

**Cause:** your 2-month no-credit-card Pro trial has expired.

**Fix:** upgrade to Pro from the URL in the response. CLI runs, vault
writes, and signing are unaffected — only submission is gated. See
[cloud-dashboard.md](cloud-dashboard.md).

## Manual evidence

### <a id="manual-evidence-expected-files"></a>"Expected files in \<folder\>"

**Problem:** a manual policy fails pointing at a folder path.

**Cause:** the catalog-resolved folder
`{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/` had no supported
files for the period.

**Fix:** upload a supported file (PDF, JPEG, PNG, GIF, TIFF, WebP, BMP) to
exactly that folder, within the entry's temporal window. See
[manual-evidence.md](manual-evidence.md).

### Manual evidence isn't being read at all

**Problem:** a policy you expected to run from a PDF collects from an API
instead (or errors).

**Cause:** the policy is not wired to manual evidence.

**Fix:** set both keys on the policy:

```yaml
policies:
  <policy-id>:
    evidence_mode: manual
    catalog_entry: <catalog-id>
```

`catalog_entry` is required whenever `evidence_mode: manual`.

## Install and binary name

### `go install` produced `sigcomply-cli`, not `sigcomply`

**Problem:** after `go install github.com/sigcomply/sigcomply-cli@latest`,
the command is `sigcomply-cli`.

**Cause:** `go install` names the binary after the module's last path
segment.

**Fix:** symlink it:

```bash
ln -sf "$(go env GOPATH)/bin/sigcomply-cli" "$(go env GOPATH)/bin/sigcomply"
```

The prebuilt installer (`scripts/install.sh`) already installs it as
`sigcomply`. See [install.md](install.md). (There is no Homebrew package.)

## Frameworks

### HIPAA (or any other framework) isn't recognized

**Problem:** selecting `hipaa` fails.

**Cause:** only `soc2` and `iso27001` are registered. **HIPAA is not
supported** — there is no package and no policies. Any unregistered
framework name fails identically.

**Fix:** use `soc2` or `iso27001`. Note `init-ci` currently supports
**soc2 only** (v1-alpha).

## Next steps

- [../quickstart.md](../quickstart.md) — a known-good zero-to-passing run.
- [configure-sources.md](configure-sources.md) — sources and credentials.
- [manual-evidence.md](manual-evidence.md) — the manual evidence flow.
- [../configuration.md](../configuration.md) — full config reference.
- Back to the [docs hub](../README.md).
