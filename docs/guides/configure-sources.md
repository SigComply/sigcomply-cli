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

   In CI, use an OIDC role instead of stored keys: see [GitHub Actions](ci-github.md) or
   [GitLab CI](ci-gitlab.md).

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
- If the run ends with `control(s) were SKIPPED`, no listed source emits the evidence those
  policies need. Skipped controls leave the compliance score. See
  [Troubleshooting](troubleshooting.md#controls-are-skipped-and-the-score-went-up).

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

- AWS: the second instance needs a `role_arn` that your CI identity can assume. Two instances that
  differ only in `region` read the same account twice.
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
