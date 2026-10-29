# Troubleshooting

Find the symptom, then apply the fix. Start with the exit code: `1` means the run completed and
policies failed; `2` and `3` mean the run did not complete. Full table:
[exit codes](../reference/commands.md).

For more detail on any run, add `--verbose` (`-v`). It adds debug logging on stderr. Emails, ARNs,
access keys, UUIDs and JWTs are redacted at every log level, so it is safe in CI logs.

## Configuration

| Symptom | Fix |
|---|---|
| `project config: missing required field "framework"` (exit `3`) | Add `framework: soc2` or `framework: iso27001`. `check` has no default framework and no `--framework` flag; it reads only the config file. |
| `yaml: unmarshal errors` naming a field (exit `3`) | The config parser rejects unknown keys. Fix the spelling; the framework key is singular: `framework:`. All keys: [configuration reference](../configuration.md). |
| `framework "hipaa" not supported (registered: [iso27001 soc2])` | Only `soc2` and `iso27001` exist. |
| `init` or `init-ci` exits `3` with `refusing to overwrite existing file` | Pass `--force` to overwrite. |
| `init-ci` exits `3` with `is not scaffolded` | `init-ci` accepts only `--framework soc2`. Its workflows read the framework from `.sigcomply.yaml`, so run `sigcomply init-ci --ci github --framework soc2` and keep your framework in the config. See [Use another framework](ci-github.md#use-another-framework). |
| `report` exits `3` | Pass `--period`. `--format pdf` is not available. JSON and CSV need `--out <file>`. |
| A policy fails to plan with an unknown slot in `bindings:` (exit `3`) | The slot is named `evidence` (`roster` and `accounts` for roster policies; `deployments` and `changes` for the two `production_deploys_from_approved_changes` policies): `bindings: { evidence: [okta] }`. |

## Sources and credentials

### A source never runs

The CLI collects only from sources listed under `sources:`. A credential in the environment does
not add a source. Add it: [Add an evidence source](configure-sources.md).

### The run stops before collecting, naming a source (exit 3)

```text
Error: source "aws.iam": aws.iam: no usable AWS credentials: export
AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, run on a role-bearing CI
identity (OIDC web identity or an instance role), or add role_arn to this
source to assume an audit role: ...
```

A listed source has no credential. Supply one (variables per source:
[sources reference](../reference/sources.md)), or remove the source if it is not in scope.

### A policy reports `error` with an auth or permission failure (exit 2)

The credential resolved but the API rejected it, or it lacks read access. Grant the read-only
permissions in the [sources reference](../reference/sources.md). Permission errors (`401`, `403`,
AWS `AccessDenied`) are reported after one attempt. Throttling, `5xx` and network errors are
retried: with `--pr` up to 5 attempts per slot with about 3 minutes of waits, with `--scheduled` up
to 3 attempts with 40 seconds of waits, and not at all on a plain `check`.

### GitLab job: AWS sources report no usable credentials

The AWS SDK needs `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`. Re-scaffold with
`sigcomply init-ci --ci gitlab --force`, or copy the `before_script` step that writes the ID token
to a file from a fresh scaffold. Then check the IAM OIDC provider lists `https://api.sigcomply.com`
as a client ID ([Run in GitLab CI](ci-gitlab.md#3-create-the-aws-oidc-provider-and-role)).

## Cloud submission

### Nothing reaches the dashboard

Check, in order:

1. `cloud.base_url: https://sigcomply.com` is in `.sigcomply.yaml`. Without it the CLI skips
   submission and logs nothing.
2. The run is in CI, and the job can mint an OIDC token (GitHub: `permissions: id-token: write`;
   GitLab: an `id_tokens:` entry named `SIGCOMPLY_ID_TOKEN`).
3. The run does not pass `--no-cloud`.
4. The repository is connected in the dashboard, and `cloud.project_id` is that project's
   **Project ID**.

Run once with `--cloud` to make the CLI name the missing piece:

```text
submit: --cloud was set but no cloud endpoint is configured; skipping submission. Set cloud.base_url in .sigcomply.yaml or pass --cloud-url <url>
submit: --cloud was set but no OIDC token detected; skipping
```

### `cloud.project_id is not set in .sigcomply.yaml`

A run that submits (unfiltered or `--scheduled`) has a cloud URL, from `cloud.base_url` or
`--cloud-url`, but the config names no project, so the run stops with exit `3` before it collects
anything. Copy the **Project ID** from your project's page on the dashboard into
`cloud.project_id` in `.sigcomply.yaml` and commit it. To run without submitting, pass
`--no-cloud`.

### `cloud.project_id: "…" is not a SigComply project ID`

The value is not `prj_` followed by 20 base58 characters (letters and digits except 0, O, I and l), so the run stops with exit `3`. Copy the
ID again from the project's page.

### A `submit:` warning with an HTTP status

The dashboard rejected the submission; the run itself is unaffected. Each status and its fix:
[Connect to SigComply Cloud](cloud-dashboard.md#fix-submission-errors). `402` means the trial
ended.

## Manual evidence

### <a id="manual-evidence-expected-files"></a>`manual evidence not found; expected files in: <folder>`

The folder had no files for the period. Upload to exactly that folder; copy the path from the
message. The period part is the entry's own cadence window (`2026` for an annual entry), not the
`--period` you pass to `report`. See [Upload manual evidence](manual-evidence.md#3-upload-the-files).

### `outside its upload window`

The message gives the newest file's upload time and the folder's period. The upload time must
fall between the start of that period and its end plus the entry's grace period (15 days for a
quarterly entry, 30 days for the others; `sigcomply evidence catalog -o json` lists each
entry's `grace_period`). Period dates are in UTC. Upload the file again during the period it
covers; after that period ends, runs read the next period's folder instead.

### `merge_failed`

The CLI could not merge the folder's files into one PDF. The message names the file it could not
read. Open that file to check it is a complete PDF, then replace it.

### `unsupported_file_type`

The folder holds a file that is not PDF, JPEG, PNG, GIF, TIFF, WebP or BMP. Remove it.

### `copy_paste_of_prior_period`

Every file is byte-identical to last period's. Upload this period's document.

## Policies

### A policy reports `error` and names a field

```text
[error] custom.keys.recently_used — CC6.1
    ↳ policy references field "payload.last_used_days" which is not present on
      record "…" (type "iam_access_key") — reference a field the evidence type
      guarantees, or guard it with is_set
```

A record lacks a field the policy reads (here, a key that was never used has no
`last_used_days`). The CLI reports `error` (exit `2`) instead of guessing. If you wrote the
policy, guard optional fields with `is_set`. For a built-in policy, report it with the error
text.

### A policy fails with `no <type> records`

```text
[fail] soc2.cc7.1.audit_logging_enabled — CC7.1
    ↳ no audit_log_trail records: audit logging not enabled or not found
```

The policy asks whether a service exists, and the source you configured found none in the
account, project or tenant it read. Turn the service on (here, a multi-region CloudTrail trail),
or check that the source reads the right account and region.

### Policies are skipped and the score went up

The run ends with:

```text
6 policies were SKIPPED and are NOT counted in the compliance score:
  soc2.cc6.1.password_min_length_14 — no configured source emits
    [password_policy.v2 password_policy] (slot "evidence")
```

No listed source emits the evidence type those policies need, or a listed source returned no
records for a policy about every resource of a kind. A skipped policy leaves the score's
denominator, so the score rises while those controls go unchecked. The run still exits `0`.

Fix it one of two ways:

- Add a source that emits the type. For `password_policy`: `aws.password_policy`, `okta`,
  `gcp.cloud_identity` or `azure.entra` ([sources reference](../reference/sources.md)).
- If no source of yours can answer the control, record the decision so it appears in the
  Statement of Applicability. This does not change the score:

  ```yaml
  controls:
    CC6.1:
      applicability: not_applicable
      reason: "Explain why the control does not apply."
  ```

  ISO 27001's `C.` clause requirements can't be declared `not_applicable` (exit `3`).

A `coverage-skew` warning is different: a source emits the right type in another version.

## Install

### `go install` produced `sigcomply-cli`

Link it as `sigcomply`:

```bash
ln -sf "$(go env GOPATH)/bin/sigcomply-cli" "$(go env GOPATH)/bin/sigcomply"
```

### The install script stops with `Unsupported` or `There is no release`

The script supports Linux on `amd64`, `arm64`, `armv6` and `armv7`, macOS on `amd64` and
`arm64`, and Windows on `amd64` in Git Bash, MSYS2 or Cygwin. Any other platform has no release
archive. On a supported platform where the script still fails, download the archive by hand:
[Install a release archive by hand](install.md#install-a-release-archive-by-hand).
