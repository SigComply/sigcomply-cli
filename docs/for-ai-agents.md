# For AI agents

Runbook for an AI coding agent that a customer asked to set up SigComply in their repository.
Follow the steps in order. Check each exit code before you continue. Facts not on this page are
in the linked reference pages; read them rather than guessing.

## Rules

- One repository holds one framework. The key is singular: `framework: soc2` or
  `framework: iso27001`. No other framework exists.
- Never put credentials in `.sigcomply.yaml`. The CLI reads them from the environment.
- Never add identifiers (ARNs, emails, account IDs) to anything sent to SigComply Cloud. Only
  counts leave the customer's environment. `experimental.roster.aliases` and
  `experimental.vendors` may hold emails and vendor names; they stay in the repository.
- Don't invent commands, flags or keys. The commands are `check`, `init`, `init-ci`, `build`,
  `report`, `evidence catalog`, `evidence due`, `version` and `completion`
  ([Commands](reference/commands.md)). Config keys: [Configuration](configuration.md).
- Don't claim the setup makes the customer compliant. SigComply collects evidence and evaluates
  policies; an auditor decides.

## 1. Install

```sh
curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh | sh
sigcomply version
```

Expect exit `0` and a line `sigcomply <version> (commit <commit>, built <time>)`. The script
writes to `/usr/local/bin` and may run `sudo`; set `SIGCOMPLY_INSTALL_DIR` to a writable
directory if you can't use `sudo`. There is no Homebrew package. With `go install`, the binary is
named `sigcomply-cli`; see [Install](guides/install.md).

## 2. Scaffold the config

Ask the customer which framework they need, then run, from the repository root:

```sh
sigcomply init -f soc2
```

Expect exit `0`. Exit `3` with `refusing to overwrite` means `.sigcomply.yaml` exists. Edit it
instead, or pass `--force` only if the customer agrees to replace it.

## 3. Declare sources

Edit `sources:` to list every provider the customer uses. A provider is only read if it is
listed; credentials alone don't add it. Look up each source's ID, keys, credentials and
permissions in [Sources](reference/sources.md).

| Source | Credential from the environment | Required keys |
|---|---|---|
| `aws.*` | AWS SDK chain: `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`, `AWS_PROFILE`, web identity or an instance role | none (`region` optional) |
| `gcp.*` | Application Default Credentials | `project_id`, or `customer_id` / `organization_id` depending on the source |
| `azure.*` | `az login`, managed identity or `AZURE_*` service principal | `subscription_id` for resource sources |
| `github` | `GITHUB_TOKEN`, or the variable named by `token_env` | `org` |
| `gitlab` | `GITLAB_TOKEN`, or the variable named by `token_env` | `group` |
| `okta` | `OKTA_API_TOKEN`, or the variable named by `token_env` | `org_url` |
| `active_directory` | `SIGCOMPLY_AD_BIND_PASSWORD` | `url`, `bind_dn` |

`token_env` names a different variable per instance when one source appears twice, for example
`"github[labs]"` with `token_env: GITHUB_TOKEN_LABS`.

Policies bind to sources automatically by evidence type. Don't add a `bindings:` block unless
two sources emit the same type and the customer wants one of them. If you add one, key it by a
real slot name: `evidence` for most policies, `roster` and `accounts` for the identity-roster
policies, `changes` and `deployments` for the change-management policies. Any other slot name
exits `3`.

## 4. Choose storage

For CI, set `vault:` and `sources.manual.pdf` to a bucket (`backend: s3`, `gcs` or
`azure_blob`). The local default only suits a laptop. Keys: [Configuration](configuration.md).

## 5. Run a check locally

```sh
sigcomply check
echo $?
```

| Exit | Meaning | What to do |
|---|---|---|
| `0` | No policy failed | Continue |
| `1` | A policy failed, or the declared scope is incomplete. Normal on a first run: manual-evidence policies fail until documents are uploaded. | Read the `↳` reason lines and the skipped-policy block, report them to the customer, continue |
| `2` | Execution error: a policy ended as `error`, a provider rejected a credential, or a flag was unknown or conflicting | Read the error; fix the credential's permissions or the command |
| `3` | Configuration error: invalid config, unknown framework, or a listed source with no credentials | Fix the config or export the named variables |

`check` has no `--framework` flag; passing one exits `2`. `ci.fail_on_violation: false` makes
failing policies exit `0`.

## 6. Scaffold CI

Find where the repository is hosted, then run one of:

```sh
sigcomply init-ci --ci github
sigcomply init-ci --ci gitlab
```

`init-ci` accepts only `--framework soc2`. For an ISO 27001 project, run
`sigcomply init-ci --ci github --framework soc2`; the workflows read the framework from the
config. Then:

1. Replace the `AWS_ROLE_ARN` placeholder with the customer's role ARN.
2. Tell the customer that the AWS IAM OIDC provider and the role's trust policy must accept the
   audience `https://api.sigcomply.com`, which the workflows request.
3. On GitLab, tell the customer to create one daily pipeline schedule (for example `0 2 * * *`);
   the scheduled job runs `sigcomply check --scheduled`.
4. Tell the customer the vault must be a bucket: `--scheduled` keeps per-policy state there.

Setup details: [CI on GitHub](guides/ci-github.md), [CI on GitLab](guides/ci-gitlab.md).

The scaffolded workflows pass no GitHub, GitLab, Okta or Active Directory token. If `sources:`
lists one of those, the customer stores the token as a CI secret and the workflow step maps it to
the variable in the table in step 3; without it, `check` exits `3`. Steps and token scopes:
[Supply credentials in CI](guides/configure-sources.md#supply-github-gitlab-okta-and-active-directory-credentials-in-ci).

## 7. Cloud submission (only if the customer has SigComply Cloud)

Add to `.sigcomply.yaml`:

```yaml
cloud:
  base_url: https://sigcomply.com
  project_id: prj_...   # ask the customer: the Project ID on their project's page
```

`cloud.project_id` must be the customer's real Project ID (`prj_` and 20 letters and digits);
never invent one. A malformed value exits `3`. Without it, `check` warns when a cloud URL is set
(the next release will exit `3`). Without `cloud.base_url`, nothing is submitted. With it, submission happens in CI with an OIDC
token; no secret is needed. Only `sigcomply check` with no filter and `--scheduled` submit;
`--cadence`, `--cadences`, `--on-push` and `--pr` runs check a subset and never submit. The customer connects the repository on the dashboard
([Cloud dashboard](guides/cloud-dashboard.md)).

## 8. Report manual evidence to the customer

```sh
sigcomply evidence due --all
```

Always exits `0` when the scan completes. Give the customer the list of folders. Only they can
produce the documents. Upload rules: [Manual evidence](guides/manual-evidence.md).

## Common mistakes

- `frameworks:` (plural) or `--framework` on `check`.
- Slot names that don't exist, such as `user_directory` or `access_keys`.
- Expecting submission without `cloud.base_url`.
- Setting `cloud.base_url` without `cloud.project_id`, or making up a project ID.
- Treating exit `1` on a first run as a broken setup.
- Using `collect`, `evaluate`, `config`, `evidence init` or `evidence path`. They don't exist.
- `hipaa` or any other unregistered framework.

## AGENTS.md template for the customer repository

Commit this as `AGENTS.md` in the customer's repository. Replace the bracketed values.

```markdown
# AGENTS.md

This repository runs SigComply ([soc2 | iso27001]) in [GitHub Actions | GitLab CI].
Docs: https://github.com/SigComply/sigcomply-cli/blob/main/docs/README.md

- Config: `.sigcomply.yaml`. The framework key is singular: `framework:`.
- Credentials come from the environment, never the config file.
- Run: `sigcomply check` (no `--framework` flag). Read results with
  `sigcomply report --period <period-id>`; `check` prints it as `<framework>/<period-id>`,
  and either form works. A period with no runs exits 3.
- Exit codes: 0 no failures, 1 failing policies or incomplete scope, 2 execution
  error, 3 configuration error.
- Missing documents: `sigcomply evidence due --all`.
- Never add ARNs, emails, usernames or account IDs to anything sent to SigComply Cloud.
```

## See also

- [Commands](reference/commands.md), [Configuration](configuration.md),
  [Sources](reference/sources.md)
- [llms.txt](../llms.txt)
