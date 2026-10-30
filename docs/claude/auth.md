# Cloud submission auth

Read this before you touch `internal/submitter/`, the cloud flags on `check`, or anything that
authenticates the CLI to SigComply Cloud. The wire payload itself is owned by
[06-aggregation.md](../architecture/06-aggregation.md). Customer setup steps are owned by the
guides: [ci-github.md](../guides/ci-github.md), [ci-gitlab.md](../guides/ci-gitlab.md) and
[cloud-dashboard.md](../guides/cloud-dashboard.md). Don't copy them here.

OIDC and evidence signing are unrelated. The OIDC token authenticates one HTTP request to the
dashboard. Evidence is signed with per-file ephemeral Ed25519 keys (AGENTS.md Invariant #3) and
never leaves the vault.

## When the CLI submits

`submitter.Decide` decides per run. The full matrix (flags, base URL, CI detection, token) is
owned by [06-aggregation.md §Decision matrix](../architecture/06-aggregation.md#decision-matrix).
The rules that matter most here: submission is opt-in, so nothing is sent without
`cloud.base_url` (customer value `https://sigcomply.com`) or `--cloud-url`; without `--cloud`
the run must also be in CI with an OIDC token; there is no `cloud.enabled` (setting it is a
config error); and a failed submission is logged as a warning and does not change the exit code.

## Audience

The CLI always requests the audience `submitter.DefaultAudience` = `https://api.sigcomply.com`.
It is an identifier, not a host: never derive it from `base_url`, and never use it as a URL. The
dashboard's OIDC validator checks the same string (overridable on the dashboard side for
non-production hosts). The CLI has no audience override. Changing the audience is a cross-repo
contract change.

## Where the token comes from

`submitter.DefaultTokenProvider` tries GitHub Actions, then GitLab CI. `submitter.HasOIDC` only
checks that the env vars exist.

- GitHub Actions: the job needs `permissions: id-token: write`, which sets
  `ACTIONS_ID_TOKEN_REQUEST_URL` and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`. `githubActionsProvider`
  calls that URL with `audience=` and reads the JWT from the `value` field (10-second timeout).
- GitLab CI: the CLI cannot choose the audience. The job's `id_tokens:` block must mint a token
  with `aud: https://api.sigcomply.com` into `SIGCOMPLY_ID_TOKEN`. No other variable is read: a
  generic `ID_TOKEN` often holds a token minted for another receiver (AWS, Vault).

`Submit` reads every token's `aud` claim (unverified; Rails verifies the signature) and refuses
to send one that does not include `DefaultAudience`, whichever provider produced it. A token is
a credential for the receiver it was minted for, so forwarding a foreign one would hand that
credential to SigComply Cloud.

The reverse also holds (AGENTS.md invariant 6): SigComply Cloud receives every token minted for
`DefaultAudience`, so no cloud role may trust that audience. The `init-ci` templates give AWS its
own token with `sts.amazonaws.com`. `check` warns (`oidc:` prefix,
`submitter.AWSWebIdentityAudienceWarning`) when the file in `AWS_WEB_IDENTITY_TOKEN_FILE` holds
such a token. It is a warning, not a refusal: the run still works, the role's trust is what is
wrong, and the customer fixes it in IAM.

## The request and what Rails checks

`submitter.Submit` sends `POST {base_url}/api/v1/runs` with `Authorization: Bearer <jwt>`,
`X-OIDC-Provider: github|gitlab`, `X-Sigcomply-CLI-Version`, `X-SigComply-Project`
(`submitter.ProjectHeader`, from `cloud.project_id`, omitted when unset) and a 30-second timeout.
The body is `core.SubmissionPayload` (schema `aggregator.SchemaVersion`); the project ID is never
in it, so `cloud_golden.json` does not change.

The dashboard's OIDC validator picks the provider from the token's `iss`, not from
`X-OIDC-Provider`, verifies the signature against the provider's JWKS and checks the audience.
Only then does it choose the project from the verified claims (GitHub `repository`
(`owner/name`), GitLab `project_path` and `namespace_path`):

- With `X-SigComply-Project`, the project with that public ID must be active and its repository
  must match the claims (case-insensitive); otherwise `403 project_mismatch`, the same body
  whatever the reason.
- Without it (an older CLI: v0.89.0 and earlier never send it, v0.90.0 only warns when the key
  is unset; v0.90.1 and later exit `3` instead), Rails answers `403 project_id_required` before
  any project lookup.

Several organizations may register the same repository, so the claims alone no longer pick a
project. The project ID is public, not a secret: committing it to `.sigcomply.yaml` is what shows
the repository chose the project, so the CLI takes it from that file only (no flag, no env var).
A run that would submit (unfiltered or `--scheduled`, a cloud URL resolved, no `--no-cloud`, no
`--capture-cloud-payload`) without `cloud.project_id` exits `3` before collection
(`missingProjectIDError` in `cmd/sigcomply/check.go`); filtered runs never submit and are exempt.
Changing a claim the CLI relies on, or a header,
means checking that file in the same task.

## Credentials for sources

The CLI never exchanges an OIDC token for cloud-provider credentials. The CI job does that before
`sigcomply check` runs (for example with `aws-actions/configure-aws-credentials`), and each source
plugin uses its SDK's default credential chain. Listed sources must resolve credentials before
collection: `awscfg.Load` and `azcommon.NewCredential` resolve eagerly with a 60-second timeout,
so missing credentials are a config error (exit 3). Per-source credential setup:
[docs/reference/sources.md](../reference/sources.md).
