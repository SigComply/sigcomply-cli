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

## Getting more detail: `--verbose`

When a run's one-line summary isn't enough, re-run `check` with `--verbose`
(`-v`):

```bash
sigcomply check --verbose
```

Verbose mode turns on **debug-level** logging (to stderr) on top of the
default info/warn output. It surfaces the detail behind the summary — the
per-policy first-run and gap-detection notes, coverage-skew and coverage-gap
diagnostics, the git commit-time parse, and the individual policy IDs behind
each aggregated warning. Redaction is always on regardless of verbosity: emails, ARNs, access
keys, UUIDs, and JWTs are stripped before anything is written, so `--verbose`
is safe to enable in CI logs.

For a still-deeper look at *what* was evaluated, read the signed
`result.json` / envelopes in your vault, or run `sigcomply report`.

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

### A configured source has no credentials

**Problem:** the run stops immediately with exit `3` and a message like:

```
Error: source "aws.iam": aws.iam: no usable AWS credentials: export
AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, run on a role-bearing CI
identity (OIDC web identity or an instance role), or add role_arn to this
source to assume an audit role: ...
```

**Cause:** the source is listed under `sources:` but nothing in the
environment can authenticate as anyone. Because `sources:` is the
operator's declaration of what this project audits, that is a
configuration error, and it is caught before any collection starts.

**Fix:** either supply the credential (see
[configure-sources.md](configure-sources.md) for the variables each
provider reads) or remove the source from `sources:` if it is genuinely
not in scope. Do not leave it listed and uncredentialed — that is the
state this check exists to refuse.

Note the failure is deliberately *early*. Before, a missing credential
surfaced at the first API call, after the collector had retried a
permanent failure through its whole backoff budget, once per binding.
A credential that resolves but is then *rejected* mid-collection is the
neighbouring case below — it is also no longer retried.

### Wrong or under-permissioned credentials

**Problem:** a source errors (exit 2) with an auth/permission failure
partway through the run.

**Cause:** a credential was resolved — so the startup check passed — but
the API rejected it, or it lacks read access to the resource. Whether a
credential is *sufficient* cannot be known until the API answers.
Credentials come from the ambient environment, never the config file
(`AWS_*`, `GITHUB_TOKEN`, GCP ADC, `OKTA_API_TOKEN`, …). All collectors
are read-only.

**Fix:** grant read-only access (e.g. `ReadOnlyAccess` or a scoped read
policy for AWS). See [configure-sources.md](configure-sources.md) and
[../configuration.md](../configuration.md).

**You should see this fast.** The collector classifies a collection
failure before deciding whether to retry it. A permanent rejection —
`401`, `403`, `404`, `400`, an AWS `AccessDenied*` / `ExpiredToken*` /
`UnauthorizedOperation`, an LDAP bind or ACL refusal — is reported after
a *single* attempt, because the answer will not change. Only transient
failures spend the retry budget: `429`, `408`, any `5xx`, AWS
throttling codes, connection errors and timeouts.

That budget is per binding and collection is sequential, so the
distinction is the difference between a report in seconds and one after
minutes of silence: on a PR run the policy is five attempts and roughly
three minutes of sleep *per binding*, and a single mis-scoped credential
hits every binding on that source. If a permission failure still seems
to hang, it is a failure shape the classifier does not yet recognise —
unrecognised errors are deliberately treated as retryable so that adding
a classifier can only ever shorten a doomed loop, never cut short one
that might have succeeded. Report it with the error text.

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
exactly that folder, within the entry's temporal window. Copy the path
from the message rather than composing it: `{period_id}` is the entry's
**cadence** window (`2026` for an annual entry, `2026-Q1` for a quarterly
one), not the `--period` you pass to `sigcomply report`. See
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

## Policies

### A policy reports `error` and names a field

**Problem:** `check` prints something like

```
[error] soc2.cc6.7.kms_key_rotation_enabled — CC6.7
    ↳ pass_when: the filter for slot "evidence" could not be evaluated, so
      the records in scope are unknown: policy references field
      "payload.is_customer_managed" which is not present on record "…"
```

**Cause:** a policy read a field the evidence record does not carry. The
evaluator never guesses: a condition it cannot evaluate leaves one
record's verdict unknown, and a *filter* it cannot evaluate leaves the
clause's whole scope unknown. Both surface as `error` (exit 2) rather
than a pass, because excluding the record would bias the result toward
passing — `all` and `none` are true of the empty set, so a filter that
fails on every record would return green having examined nothing.

**Fix:** either the source should populate the field, or the policy
should say the absence is acceptable. For a field the evidence type marks
optional, guard it with `is_set` inside an `all_of`:

```yaml
filter:
  op: all_of
  conditions:
    - { op: is_set, field: payload.is_customer_managed }
    - { op: eq, field: payload.is_customer_managed, value: true }
```

For a field the type marks `required`, a record missing it is a source
bug — check the plugin, not the policy.

### Controls are SKIPPED — and the compliance score went *up*

**Problem:** `check` exits `0`, and at the end prints

```
6 control(s) were SKIPPED and are NOT counted in the compliance score:
  soc2.cc6.1.password_min_length_14 — no configured source emits
    [password_policy] (slot "evidence")
  …
```

At plan time the same run warns:

```
[warn] coverage-gap: 6 required slot(s) have no configured source emitting
  an accepted evidence type; the affected policies will be SKIPPED and leave
  the compliance score denominator …
```

**Cause:** the score is `(passed + waived + carried_forward) / (total −
skipped − na)`. A skipped control leaves the **denominator**, so controls
nobody could answer *raise* the ratio rather than lowering it. Six
unanswerable password controls on a GCP- or Azure-only estate turn
"34 of 40" into "34 of 34". The run is still green and still exits `0`,
which is why the warning exists: **a green run that skips controls is not
a passing audit.**

The usual cause is that no configured source emits the evidence type the
slot accepts — `password_policy`, for instance, is emitted today only by
`aws.password_policy` and `okta`. A near neighbour is `coverage-skew`,
where a source *does* emit the right family but a different **version**;
that one is fixed by extending the slot's `accepts:`, not by wiring a new
source.

**Fix:** configure a source that emits the listed type. If the estate's
provider genuinely cannot answer the control, declare the decision instead
of leaving it implicit:

```yaml
controls:
  CC6.1:
    applicability: not_applicable
    reason: "Google Workspace exposes no per-class password policy"
```

That cascades `na` to every policy mapping to the control. It does not
improve the score — `na` leaves the denominator exactly as `skip` does —
but it turns a silent absence into a recorded decision with a reason, which
is what `report --view soa` prints and what an auditor can actually read.
(ISO 27001's `C.`-prefixed management-system controls cannot be declared
`not_applicable`; that is a config error, exit 3.)

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
