# Troubleshooting

Find the symptom, then apply the fix. Start with the exit code: `1` means the run completed and
policies failed; `2` and `3` mean the run did not complete. Full table:
[exit codes](../reference/commands.md#exit-codes).

For more detail on any run, add `--verbose` (`-v`). It adds debug logging on stderr. At every log
level, the CLI redacts emails, ARNs, UUIDs, AWS access key IDs, JWTs, and GitHub, GitLab and Okta
tokens in their standard formats.

## Install

### The install script stops with `Unsupported` or `There is no release`

The script supports Linux on `amd64`, `arm64`, `armv6` and `armv7`, macOS on `amd64` and
`arm64`, and Windows on `amd64` in Git Bash, MSYS2 or Cygwin. It picks the archive from
`uname -s` and `uname -m`: on 32-bit ARM, `armv6*` gets the `armv6` archive and `armv7*` or
`armv8l` gets `armv7`. Any other platform has no release archive. On a supported platform where
the script still fails, download the archive by hand:
[Install a release archive by hand](install.md#install-a-release-archive-by-hand).

### `Checksum mismatch`

The archive's SHA-256 differs from its entry in the release's `checksums.txt`. The script stops
without installing.

### `Build provenance verification failed`

With `gh` installed, the script verifies the archive's build provenance (step 3 of
[Install a release archive by hand](install.md#install-a-release-archive-by-hand)). This error
means the archive was not built by SigComply's release workflow from the commit the tag points at.
The script stops without installing.

### `Cannot download` the provenance bundle

The release is v0.91.0 or later but has no provenance bundle to download. The script stops
without installing.

### `Build provenance not verified`

A warning, not an error. Without `gh`, with an older `gh`, or for a release before v0.91.0, the
script installs after the checksum check alone. Set `SIGCOMPLY_REQUIRE_PROVENANCE=1` to make this
an error.

### `go install` produced `sigcomply-cli`

Link it as `sigcomply`:

```bash
ln -sf "$(go env GOPATH)/bin/sigcomply-cli" "$(go env GOPATH)/bin/sigcomply"
```

## Configuration

| Symptom | Fix |
|---|---|
| `project config: missing required field "framework"` (exit `3`) | Add `framework: soc2` or `framework: iso27001`. `check` has no default framework and no `--framework` flag; it reads only the config file. |
| `yaml: unmarshal errors` naming a field (exit `3`) | The config parser rejects unknown keys. Fix the spelling; the framework key is singular: `framework:`. All keys: [configuration reference](../configuration.md). |
| `framework "hipaa" not supported (registered: [iso27001 soc2])` | Only `soc2` and `iso27001` exist. |
| `init` or `init-ci` exits `3` with `refusing to overwrite existing file` | Pass `--force` to overwrite. |
| `init-ci` exits `3` with `is not scaffolded` | `init-ci` accepts only `--framework soc2`. Its workflows read the framework from `.sigcomply.yaml`, so run `sigcomply init-ci --ci github --framework soc2` and keep your framework in the config. See [Use another framework](ci-github.md#use-another-framework). |
| `report` exits `3` | Pass `--period`. `--format pdf` is not available. JSON and CSV need `--out <file>`. |
| A policy fails to plan with an unknown slot in `bindings:` (exit `3`) | Use the policy's slot name: [Pin a policy to one source](configure-sources.md#pin-a-policy-to-one-source). For most policies it is `evidence`: `bindings: { evidence: [okta] }`. |

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
AWS `AccessDenied`) fail after one attempt, so re-running doesn't help. Throttling, `5xx` and
network errors are retried: with `--pr` up to 5 attempts with about 3 minutes of waits, with
`--scheduled` up to 3 attempts with 40 seconds of waits, and not at all on a plain `check`.

### GitLab job: AWS sources report no usable credentials

The AWS SDK needs `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`. Re-scaffold with
`sigcomply init-ci --ci gitlab --force`, or copy the `AWS_ID_TOKEN` entry under `id_tokens:` and
the `before_script` step that writes it to a file from a fresh scaffold. Then check that the job's
role variable is set, and that the IAM OIDC provider lists `sts.amazonaws.com` as a client ID
([Run in GitLab CI](ci-gitlab.md#3-create-the-aws-oidc-provider-and-roles)).

### An AWS role trusts `https://api.sigcomply.com`

Roles set up from an earlier version of the CI guides trust the audience
`https://api.sigcomply.com`. SigComply receives every token with that audience, so such a role
trusts tokens that leave your CI. Give AWS its own token with the audience `sts.amazonaws.com`:

- GitHub Actions: re-scaffold with `sigcomply init-ci --ci github --force`, or set
  `audience: sts.amazonaws.com` on each `configure-aws-credentials` step. `sigcomply check` can't
  see which audience the AWS step used, so it gives no warning: check each workflow's `audience:`
  line yourself.
- GitLab CI: re-scaffold with `sigcomply init-ci --ci gitlab --force`, or add the `AWS_ID_TOKEN`
  entry and write it, not `SIGCOMPLY_ID_TOKEN`, to the token file. If you set `AWS_ROLE_ARN` as a
  project or group CI/CD variable, delete it: GitLab ranks it above the job's own `AWS_ROLE_ARN`,
  so both jobs would keep assuming the old role. `sigcomply check` warns while the AWS token still
  carries the SigComply audience.

Then change each role's trust policy as step 3 of [Run in GitHub Actions](ci-github.md#3-create-the-aws-oidc-provider-and-roles)
or [Run in GitLab CI](ci-gitlab.md#3-create-the-aws-oidc-provider-and-roles) shows, and remove
the old client ID from the IAM OIDC provider:

```bash
aws iam remove-client-id-from-open-id-connect-provider --open-id-connect-provider-arn <arn> --client-id https://api.sigcomply.com
```

## Cloud submission

### Nothing reaches the dashboard

Check, in order:

1. `cloud.base_url: https://sigcomply.com` is in `.sigcomply.yaml`. Without it the CLI skips
   submission and logs nothing.
2. The run is in CI, and the job can mint an OIDC token (GitHub: `permissions: id-token: write`;
   GitLab: an `id_tokens:` entry named `SIGCOMPLY_ID_TOKEN` with
   `aud: https://api.sigcomply.com`).
3. The run does not pass `--no-cloud`.
4. The repository is connected in the dashboard, and `cloud.project_id` is that project's
   **Project ID**.
5. The run covers every policy (`check` with no filter, or `--scheduled`) and is not in a pull
   request or merge request pipeline. Otherwise it prints `cloud submission skipped: ...` and
   sends nothing ([Commands](../reference/commands.md#sigcomply-check)).

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

The value is not `prj_` followed by 20 base58 characters (letters and digits except 0, O, I and
l), so the run stops with exit `3`. Copy the ID again from the project's page.

### `OIDC token: audience [...] does not include "https://api.sigcomply.com"`

The `SIGCOMPLY_ID_TOKEN` entry under `id_tokens:` has another audience, so the CLI did not send
it. Set `aud: https://api.sigcomply.com` on that entry. The run itself is unaffected.

### `oidc: AWS_WEB_IDENTITY_TOKEN_FILE holds a token with the SigComply Cloud audience`

GitLab only. On GitHub the AWS step exchanges its own token, so the CLI can't check it. The job
gives AWS a token minted for SigComply, so the AWS role trusts the audience
`https://api.sigcomply.com`, and SigComply receives tokens with that audience. Give AWS its own
token with the audience `sts.amazonaws.com` and remove `https://api.sigcomply.com` from the role's
trust policy and the IAM OIDC provider's client IDs:
[An AWS role trusts `https://api.sigcomply.com`](#an-aws-role-trusts-httpsapisigcomplycom).

### `oidc: ID_TOKEN is set but SIGCOMPLY_ID_TOKEN is not`

The CLI reads its GitLab token only from `SIGCOMPLY_ID_TOKEN`, so the run can't submit. Rename the
`id_tokens:` entry to `SIGCOMPLY_ID_TOKEN`, with `aud: https://api.sigcomply.com`.

### A `submit:` warning with an HTTP status

The dashboard rejected the submission; the run itself is unaffected. The plan never blocks a
submission: runs are recorded on every plan. The warning includes the HTTP status and an error
`code`:

| Status | `code` | Cause | Fix |
|---|---|---|---|
| none | none | No `submit:` line and no `submission accepted`: the CLI skipped submission. | Set `cloud.base_url`. Run with `--cloud` to see which condition is missing. |
| 401 | `token_expired` | The token expired before the CLI posted it. | Re-run the job. |
| 401 | `invalid_signature` | The token's signature or signing key did not verify. | Re-run; if it persists, check the token comes from GitHub Actions or GitLab. |
| 401 | `validation_error` | The token is malformed, has the wrong issuer, or its audience is not `https://api.sigcomply.com`. | On GitLab, set `aud: https://api.sigcomply.com` on the ID token. |
| 403 | `project_mismatch` | `cloud.project_id` doesn't name an active project for the token's repository. | See below. |
| 403 | `project_id_required` | The run sent no project ID: `cloud.project_id` is not set and the CLI is older than v0.90.1, which still runs without it (v0.90.1 and later exit `3` first). | Upgrade the CLI and set `cloud.project_id` in `.sigcomply.yaml` to the **Project ID** from the project's page. |
| 403 | `repository_mismatch` | The token's repository or owner ID differs from the IDs the project recorded on its first accepted run, for example because the repository was deleted and recreated under the same name. | Update the repository URL in the project's **Settings** tab, which clears the recorded IDs, or contact support. |
| 413 | `payload_too_large` | The request body is over 4 MB. | Contact support. |
| 422 | `validation_failed` or a message | The payload was rejected, for example because its `run_id` was already used by another project in your organization, or its summary counts or score disagree with its policy list. Resending the same run to the same project is not an error: it answers `200` and keeps the first copy. | Re-run the job; each run gets a new run ID. Check the message. |
| 503 | `jwks_unavailable` | The dashboard could not fetch your CI provider's signing keys to check the token. | Re-run the job later. |

`project_mismatch` has these causes. Matching ignores case.

- The ID is mistyped: copy the **Project ID** from the project's page into `cloud.project_id`.
- The ID belongs to another repository's project, or the repository is not connected: check that
  the project's repository URL matches the repository the job runs in. After a rename, paste the
  new URL in the project's **Settings** tab.
- The project is inactive: check it in **Settings**.

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
read. Open that file to check it is a complete PDF, then replace it. A PDF whose internal object
numbers go above 1,000,000 is also refused; printing it to a new PDF renumbers them.

### `conversion_failed`

The CLI could not convert an image to PDF. Either the file is not a complete image of the type
its extension says, or it is larger than 50 megapixels. A phone photo taken in a high-resolution
mode (108 or 200 megapixels) is over the limit; the default camera mode is not. Open the image to
check it, then downscale it or save it as a PDF and upload that instead.

### `file_too_large`

A file in the folder is larger than 100 MB. Split it into several files, or reduce it (for
example, scan at a lower resolution), and upload the parts to the same folder.

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

### A `coverage-skew` warning

A source emits the evidence type a slot needs, but in a version the slot doesn't accept, so the
affected policies are skipped. The warning names the fix: extend the slot's `accepts:` to include
the emitted version, or wire a source that emits the accepted version.
