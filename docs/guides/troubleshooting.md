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
| `init-ci` exits `3` with `not scaffolded in v1-alpha` | `init-ci` scaffolds SOC 2 only. See [Use another framework](ci-github.md#use-another-framework). |
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
retried; with `--pr` the retry budget is about eight minutes per slot.

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
4. The repository is connected in the dashboard.

Run once with `--cloud` to make the CLI name the missing piece:

```text
submit: --cloud was set but no cloud endpoint is configured; skipping submission. Set cloud.base_url in .sigcomply.yaml or pass --cloud-url <url>
submit: --cloud was set but no OIDC token detected; skipping
```

### A `submit:` warning with an HTTP status

The dashboard rejected the submission; the run itself is unaffected. Each status and its fix:
[Connect to SigComply Cloud](cloud-dashboard.md#fix-submission-errors). `402` means the trial
ended.

## Manual evidence

### <a id="manual-evidence-expected-files"></a>`manual evidence not found; expected files in: <folder>`

The folder had no files for the period. Upload to exactly that folder; copy the path from the
message. The period part is the entry's own cadence window (`2026` for an annual entry), not the
`--period` you pass to `report`. See [Upload manual evidence](manual-evidence.md#3-upload-the-files).

### `uploaded outside the configured temporal window`

The newest file's upload time is outside the period plus grace. Upload the file again during the
period it covers.

### `unsupported_file_type`

The folder holds a file that is not PDF, JPEG, PNG, GIF, TIFF, WebP or BMP. Remove it.

### `copy_paste_of_prior_period`

Every file is byte-identical to last period's. Upload this period's document.

## Policies

### A policy reports `error` and names a field

```text
[error] soc2.cc6.7.kms_key_rotation_enabled — CC6.7
    ↳ pass_when: the filter for slot "evidence" could not be evaluated, so
      the records in scope are unknown: policy references field
      "payload.is_customer_managed" which is not present on record "…"
```

A record lacks a field the policy reads. The CLI reports `error` (exit `2`) instead of guessing.
If you wrote the policy, guard optional fields with `is_set`. For a built-in policy, report it
with the error text.

### Controls are skipped and the score went up

The run ends with:

```text
6 control(s) were SKIPPED and are NOT counted in the compliance score:
  soc2.cc6.1.password_min_length_14 — no configured source emits
    [password_policy.v2 password_policy] (slot "evidence")
```

No listed source emits the evidence type those policies need. A skipped policy leaves the score's
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

### The install script fails on 32-bit ARM or Windows

The script supports macOS and Linux on `amd64` and `arm64` only. Download the archive by hand:
[Install a release archive by hand](install.md#install-a-release-archive-by-hand).
