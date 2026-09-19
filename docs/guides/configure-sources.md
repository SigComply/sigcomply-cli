# Configure evidence sources

How to declare evidence sources in `.sigcomply.yaml` and supply their credentials so that policies can collect automated evidence.

> Docs hub: [../README.md](../README.md)

## Prerequisites

- The CLI installed ([install guide](install.md)).
- A `.sigcomply.yaml` in your repo. `sigcomply init` scaffolds one:

  ```bash
  sigcomply init -f soc2
  ```

## The model: list sources, let policies auto-bind

Two rules drive source configuration:

1. **Sources do not auto-register from credentials.** Having `AWS_ACCESS_KEY_ID` in your environment is not enough — you must list each source explicitly under `sources:`. The config file names *which* sources to run; credentials still come from the ambient environment, never from the config file. **`sources:` is the source of truth**, so the reverse also holds: a source you list whose credentials are missing fails the run at startup (exit `3`) rather than being skipped. Listing a source is a claim that this project audits it.
2. **Policies auto-bind by evidence type.** Every policy declares the evidence type it needs and the CLI's planner binds it to any configured source that emits that type. You do **not** need a `bindings:` block to start.

The conventional slot name is `evidence`. You only add a binding override when more than one configured source emits the same type and you want to pin the policy to one of them:

```yaml
policies:
  <policy-id>:
    bindings:
      evidence: [okta]     # narrow this policy to the okta source
```

> Do not key bindings on names like `user_directory` or `access_keys` — those slot names do not exist and cause a config error (exit 3). If you override, key on `evidence` — except for the identity-roster policies, whose slots are `roster` and `accounts` (see [Identity roster](identity-roster.md)).

The one slot that **never** auto-binds is a roster slot: which directory holds your organization's people is your decision, made once with `experimental.roster.source`.

### Credentials come from the environment, never the config file

Never put secrets in `.sigcomply.yaml`. Each source reads its credentials from the ambient environment (or a CI-injected identity). The config file holds only non-secret keys like `region`, `org`, or `project_id`.

### Least privilege

All collectors are **read-only** — they use `Describe`/`List`/`Get` API calls only. Grant each source's credential the minimum read-only access it needs. For AWS, `ReadOnlyAccess` or a scoped read policy on the assumed role is sufficient. The full per-source RBAC breakdown lives in the [configuration reference](../configuration.md).

## Per-provider configuration

Each section below shows the `sources:` snippet, the environment variables that supply credentials, and the required config keys.

### AWS (`aws.*`)

```yaml
sources:
  aws.iam:
    region: us-east-1
```

- **Credentials (env):** the standard AWS SDK chain — `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE`, `AWS_REGION`; or an assumed IAM role / OIDC (recommended in CI).
- **Required config keys:** `region` is optional and falls back to the vault's `region` if omitted.
- **Least privilege:** attach `ReadOnlyAccess` (or a scoped read policy) to the assumed role.

Common AWS source ids you can list under `sources:` include:

| Source id | Evidence area |
|---|---|
| `aws.iam` | IAM users, MFA, access keys, password policy |
| `aws.s3` | S3 bucket encryption / public-access settings |
| `aws.cloudtrail` | Audit logging configuration |
| `aws.config` | AWS Config recorder state |
| `aws.kms` | Key management / rotation |
| `aws.rds` | Database encryption settings |
| `aws.ec2` | Security groups, EBS encryption |
| `aws.guardduty` | Threat detection enablement |

List only the sources whose evidence your framework's policies need; unused ones add no value. The [README supported-sources table](../../README.md) enumerates the full set.

### GCP (`gcp.*`)

```yaml
sources:
  gcp.iam:
    project_id: my-gcp-project
```

- **Credentials (env):** Application Default Credentials — `GOOGLE_APPLICATION_CREDENTIALS` pointing at a service-account key, or `gcloud auth application-default login` locally.
- **Required config keys:** `project_id`. Some sources use a different scope key — `customer_id` for `gcp.directory`, `organization_id` for `gcp.scc`.

### Azure (`azure.*`)

```yaml
sources:
  azure.storage:
    subscription_id: 00000000-0000-0000-0000-000000000000
```

- **Credentials (env):** the Azure SDK chain — `az login`, a managed identity, or an `AZURE_*` service principal (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`).
- **Required config keys:** `subscription_id` for ARM-based sources; `tenant_id` for Microsoft Graph-based sources.

### GitHub (`github`)

```yaml
sources:
  github:
    org: my-org
```

- **Credentials (env):** `GITHUB_TOKEN` (or a `token:` key in the source config). In GitHub Actions the workflow's built-in token can supply this.
- **Required config keys:** `org`.

### GitLab (`gitlab`)

```yaml
sources:
  gitlab:
    group: my-group
    # base_url: https://gitlab.example.com   # optional, for self-managed GitLab
```

- **Credentials (env):** `GITLAB_TOKEN` (or a `token:` key).
- **Required config keys:** `group`. Optional `base_url` for self-managed instances.

### Okta (`okta`)

```yaml
sources:
  okta:
    org_url: https://my-org.okta.com
```

- **Credentials (env):** `OKTA_API_TOKEN` (or an `api_token:` key).
- **Required config keys:** `org_url`.

### Active Directory (`active_directory`)

```yaml
sources:
  active_directory:
    url: ldaps://dc01.corp.example.com
    bind_dn: CN=sc-reader,OU=Service Accounts,DC=corp,DC=example,DC=com
    ca_cert: ./corp-ca.pem          # optional; else system roots
experimental:
  roster:
    source: active_directory        # AD exists to be the identity roster
```

- **Credentials (env):** `SIGCOMPLY_AD_BIND_PASSWORD` (or a `bind_password:` key). A dedicated non-admin bind user is enough.
- **Required config keys:** `url` (`ldaps://…`, or `ldap://…` with `start_tls: true` — plaintext LDAP is refused) and `bind_dn`.
- **Network:** domain controllers are rarely internet-facing; run the check on a self-hosted runner inside the network.
- Emits only the roster (`roster_entry`), so it is useful only as `experimental.roster.source`. Full key list: [configuration reference](../configuration.md#active-directory).

## Multiple accounts, orgs or subscriptions

One project can cover more than one cloud account. Configure the same
plugin twice, distinguishing the second with a bracket suffix:

```yaml
sources:
  aws.iam:
    region: us-east-1                                          # the account CI already authenticates as
  "aws.iam[staging]":
    region: us-east-1
    role_arn: arn:aws:iam::210987654321:role/SigComplyAudit    # a second account
```

The runner keeps one set of credentials and assumes the named role for
the second account — the standard cross-account setup. Grant that role
read-only access and allow your CI principal to assume it.

**Adding a region is not adding an account.** Two instances that differ
only by `region:` authenticate as the same principal and return the same
account's resources twice. If you want a second account, it needs a
`role_arn`. A role that cannot be assumed fails the run, so a
misconfiguration shows up as an error rather than as an account that
looks empty. The same is true of the default (no `role_arn`) path: if the
ambient chain resolves nothing, the run stops at startup.

For GitHub, GitLab, Okta and Active Directory, give each instance its own credential —
either a literal `token:` (`api_token:` for Okta, `bind_password:` for Active
Directory), or `token_env:` naming a different environment variable per
instance:

```yaml
sources:
  github:
    org: acme
  "github[labs]":
    org: acme-labs
    token_env: GITHUB_TOKEN_LABS
```

Without `token_env` the second instance falls back to the same shared
`GITHUB_TOKEN` as the first, and you collect one org twice.

For GCP and Azure, a second instance changes what is queried
(`project_id`, `subscription_id`) but still authenticates as the same
ambient identity, so it works only where that one principal can read
every project or subscription you list.

Each instance's evidence is collected, signed and stored separately —
records carry the instance key as their `source_id` and land in their own
envelope file — so an auditor can tell the accounts apart. If you declare
an estate with `experimental.scope.required_sources`, list each instance
key separately; asserting `aws.iam` does not assert `aws.iam[staging]`.

Instances auto-bind like any other source, so policies need no changes.

## A complete minimal example

```yaml
schema_version: project.v1
framework: soc2
sources:
  aws.iam:
    region: us-east-1
  github:
    org: my-org
vault:
  backend: local
  path: ./.sigcomply/vault
```

With `AWS_*` and `GITHUB_TOKEN` present in the environment, `sigcomply check` will plan, collect from both sources, and auto-bind every policy whose evidence type they emit.

A **missing** credential for a configured source is a configuration error: the run stops before collecting anything and exits `3`, naming the source and the environment variables to set. A credential that is present but **rejected or under-permissioned** still surfaces during collection as an execution error (exit `2`) — that one cannot be known until the API answers. Neither is ever a silent skip.

## Next steps

- [Quickstart](../quickstart.md) — run your first check locally.
- [Wire GitHub Actions](ci-github.md) / [Wire GitLab CI](ci-gitlab.md) — supply AWS credentials via OIDC in CI.
- [Manual evidence](manual-evidence.md) — configure the `manual.pdf` source for uploaded documents.

## See also

- [Configuration reference](../configuration.md) — full `.sigcomply.yaml` schema and per-source RBAC.
- [Docs hub](../README.md)
