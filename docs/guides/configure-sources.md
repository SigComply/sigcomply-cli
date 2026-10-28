# Add an evidence source

List a source in `.sigcomply.yaml`, give the CLI read-only credentials for it, and confirm its
policies evaluate.

## Prerequisites

- The CLI installed ([install guide](install.md)).
- A `.sigcomply.yaml` in your repo. Create one with `sigcomply init -f soc2` (or `-f iso27001`).
- A read-only credential for the system you add. The keys, environment variables and permissions
  for each source are in the [sources reference](../reference/sources.md).

## Steps

1. Find the source ID in the [sources reference](../reference/sources.md). AWS, GCP and Azure have
   one source per service (for example `aws.iam`, `aws.s3`, `gcp.iam`, `azure.storage`). GitHub, GitLab,
   Okta and Active Directory have one each (`github`, `gitlab`, `okta`, `active_directory`).

2. Add it under `sources:` with its non-secret keys:

   ```yaml
   sources:
     aws.iam:
       region: us-east-1
     github:
       org: my-org
   ```

   The CLI collects only from sources listed here. A credential in your environment does not add
   a source by itself.

3. Export the credential in the environment that runs the CLI. Never put a secret in
   `.sigcomply.yaml`. For the example above:

   ```bash
   export GITHUB_TOKEN=<read-only token>
   # AWS: the standard SDK chain (AWS_PROFILE, AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, or a role)
   ```

   In CI, AWS, GCP and Azure can use an OIDC role instead of stored keys: see
   [GitHub Actions](ci-github.md) or [GitLab CI](ci-gitlab.md). GitHub, GitLab, Okta and Active
   Directory have no OIDC route and need a stored secret: see
   [Supply GitHub, GitLab, Okta and Active Directory credentials in CI](#supply-github-gitlab-okta-and-active-directory-credentials-in-ci).

4. Run the check:

   ```bash
   sigcomply check
   ```

   Policies bind to every listed source that emits the evidence type they need. You don't need a
   `bindings:` block.

## Verify

- The run starts with `Collecting evidence from N configured source(s):` and lists your source.
- A listed source with no credential stops the run before collection with exit code `3` and names
  the variables to set.
- A credential that the API rejects, or that lacks a permission, fails the affected policies with
  `error` and exit code `2`.
- If the run ends with `policies were SKIPPED`, no listed source emits the evidence those
  policies need. Skipped controls leave the compliance score. See
  [Troubleshooting](troubleshooting.md#policies-are-skipped-and-the-score-went-up).

## Supply GitHub, GitLab, Okta and Active Directory credentials in CI

These sources read a token from an environment variable. A CI job does not set it for you: store
the token as a secret and pass it to the step that runs `sigcomply check`. Without it, the run
exits `3` before collection with `token required`.

| Source | Variable | Token |
|---|---|---|
| `github` | `GITHUB_TOKEN` | A fine-grained personal access token or a GitHub App installation token with read access to the organization, including repository Administration: read on every repository. A classic token's user must be an admin of every repository. The access each policy needs is in the [GitHub section of the sources reference](../reference/sources.md#github). |
| `gitlab` | `GITLAB_TOKEN` | A personal, group or project access token with `read_api`, whose user is at least Reporter on each project. Maintainer reads code-owner approval settings; member MFA needs a group-owner token. |
| `okta` | `OKTA_API_TOKEN` | An API token created by a read-only administrator. |
| `active_directory` | `SIGCOMPLY_AD_BIND_PASSWORD` | The bind user's password. The runner must reach the domain controller, which hosted runners rarely can. |

To give two instances of a source different tokens, set `token_env` on each instance to the name
of its variable.

GitHub Actions does not pass its built-in `GITHUB_TOKEN` to steps on its own, and that token is
scoped to one repository: it cannot read organization members or settings, or any repository's
branch protection, which needs admin access. Store an organization
token as a repository or organization secret (here `SIGCOMPLY_GH_TOKEN`) and map it in the step:

```yaml
- name: Run SigComply
  run: sigcomply check --scheduled
  env:
    GITHUB_TOKEN: ${{ secrets.SIGCOMPLY_GH_TOKEN }}
    OKTA_API_TOKEN: ${{ secrets.SIGCOMPLY_OKTA_TOKEN }}
```

To avoid a long-lived personal token, create a GitHub App with read-only organization and
repository permissions, install it on the organization, and mint a short-lived installation
token in the job, for example with `actions/create-github-app-token`. Pass that token as
`GITHUB_TOKEN`.

In GitLab CI, add the token as a masked CI/CD variable named `GITLAB_TOKEN` (or
`OKTA_API_TOKEN`). GitLab exports CI/CD variables to jobs, so no `variables:` entry is needed. A
variable marked protected reaches only jobs on protected branches and tags, which suits a check
that runs on the default branch. The job's own `CI_JOB_TOKEN` cannot read group members or settings, so it does not work
as `GITLAB_TOKEN`.

Never put the token in `.sigcomply.yaml`: the file is committed with the repository.

## Pin a policy to one source

When two listed sources emit the same evidence type, every policy that needs it reads both. To
make a policy read only one, bind its `evidence` slot:

```yaml
policies:
  soc2.cc6.1.mfa_enforced_all_users:
    bindings:
      evidence: [okta]
```

The slot is named `evidence` for every policy except these:

| Policies | Slots |
|---|---|
| Identity-roster policies ([Check accounts against your identity roster](identity-roster.md)) | `roster`, `accounts` |
| `soc2.cc8.1.production_deploys_from_approved_changes`, `iso27001.8.32.production_deploys_from_approved_changes` | `deployments`, `changes` |

## Add a second account, org or subscription

Configure the same source again with a bracket suffix:

```yaml
sources:
  aws.iam:
    region: us-east-1
  "aws.iam[staging]":
    region: us-east-1
    role_arn: arn:aws:iam::210987654321:role/SigComplyAudit
  github:
    org: acme
  "github[labs]":
    org: acme-labs
    token_env: GITHUB_TOKEN_LABS
```

- AWS: the second instance needs a `role_arn` that your CI identity can assume.
- AWS regions: most `aws.*` sources read only the region they are given. To cover a second region,
  add an instance of each regional source with that `region`, such as `"aws.ec2[eu]"`. The
  account-wide sources (`aws.iam`, `aws.iam_access_key`, `aws.password_policy`, `aws.s3`) need no
  per-region instance. See [Regions](../reference/sources.md#regions).
- GitHub, GitLab, Okta, Active Directory: give each instance its own credential with `token_env`
  (or a literal `token`, `api_token`, `bind_password`). Without it, both instances use the same
  token.
- GCP and Azure: the second instance changes `project_id` or `subscription_id` but authenticates
  as the same identity, which must be able to read both.

Each instance's evidence is signed and stored separately under its own source ID. Details: the
[multiple instances section of the configuration reference](../configuration.md).

## Next steps

- [Upload manual evidence](manual-evidence.md) for controls no API can answer.
- [Check accounts against your identity roster](identity-roster.md).
- [Run in GitHub Actions](ci-github.md) or [Run in GitLab CI](ci-gitlab.md).
