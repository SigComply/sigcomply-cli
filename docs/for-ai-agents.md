# For AI agents

A deterministic runbook for an AI coding agent setting up a customer's own SOC 2 compliance repository with the SigComply CLI.

Back to the [documentation hub](README.md).

This page is written for an AI coding agent (Claude Code, Cursor, Codex) that a customer has pointed at these docs. Follow the steps in order. Every command is complete and copy-pasteable; expected exit codes are given so you can self-verify.

## Prerequisites

- A shell on macOS or Linux.
- The customer's code in a git repository hosted on **GitHub** or **GitLab** (you will branch on which).
- Read-only cloud credentials available in the environment (for the automated SOC 2 checks). AWS is the common starting point: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` (or a role / OIDC).
- One repo = one framework = one evidence vault. For SOC 2, set `framework: soc2`.

## 1. Install the CLI

```bash
curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh | sh
sigcomply version
```

`sigcomply version` prints `sigcomply <ver> (commit <c>, built <t>)` and exits `0`.

Go-toolchain alternative — note it installs the binary as `sigcomply-cli`, so symlink it:

```bash
go install github.com/sigcomply/sigcomply-cli@latest
ln -sf "$(go env GOPATH)/bin/sigcomply-cli" "$(go env GOPATH)/bin/sigcomply"
```

There is no Homebrew package.

## 2. Scaffold the config

```bash
sigcomply init -f soc2
```

This writes a ready-to-edit `.sigcomply.yaml` that runs out of the box against a local vault. It refuses to overwrite an existing file unless you pass `--force` (else exit `3`).

## 3. A minimal valid `.sigcomply.yaml`

If you are writing the config by hand, this is a known-good minimal file that loads and plans cleanly:

```yaml
schema_version: project.v1
framework: soc2
sources:
  aws.iam:
    region: us-east-1
vault:
  backend: local
  path: ./.sigcomply/vault
```

Key rules:

- The framework key is **singular**: `framework:` — never `frameworks:`.
- Policies **auto-bind** to any configured source that emits the evidence type they need. You do **not** need a `bindings:` block to start.
- If you ever must override a binding, key it on the slot named `evidence` and a real source id, e.g. `bindings: { evidence: [okta] }`. Slot names like `user_directory` or `access_keys` **do not exist** and cause exit `3`.

## 4. Add sources and credentials

List each source you want under `sources:` — the CLI does **not** auto-register sources from credentials, but credentials themselves are read from the ambient environment, never the config file.

| Source id prefix | Credentials (from env) | Required config keys |
|---|---|---|
| `aws.*` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE`, `AWS_REGION`; or IAM role / OIDC | `region` (optional; falls back to vault region) |
| `gcp.*` | ADC: `GOOGLE_APPLICATION_CREDENTIALS` or `gcloud auth application-default login` | `project_id` (or `customer_id`, `organization_id`) |
| `azure.*` | `az login` / managed identity / `AZURE_*` service principal | `subscription_id` / `tenant_id` |
| `github` | `GITHUB_TOKEN` (or config `token`) | `org` |
| `gitlab` | `GITLAB_TOKEN` (or config `token`) | `group` (optional `base_url`) |
| `okta` | `OKTA_API_TOKEN` (or config `api_token`) | `org_url` |

All collectors are read-only (Describe/List/Get). For AWS, attach `ReadOnlyAccess` or a scoped read policy to the assumed role. Detailed per-source RBAC is in [configuration.md](configuration.md).

## 5. Scaffold CI

Determine where the customer's code is hosted, then run exactly one branch.

**If GitHub:**

```bash
sigcomply init-ci --ci github
```

This writes per-cadence workflows under `.github/workflows/`. Each workflow job must have OIDC permission so the cloud submission (and AWS role assumption) can mint a token — the scaffold already includes it:

```yaml
permissions:
  id-token: write
  contents: read
```

No SigComply secret is needed on GitHub; the Actions runner mints the OIDC JWT.

**If GitLab:**

```bash
sigcomply init-ci --ci gitlab
```

This writes a single `.gitlab-ci.yml` at the repo root with cadence-keyed jobs. Add one GitLab pipeline schedule per cadence (Settings → CI/CD → Pipeline schedules) with a `CADENCE` variable.

> **GitLab OIDC token name.** The `id_tokens:` block must name the token `SIGCOMPLY_ID_TOKEN` (fallback `ID_TOKEN`) — that is the env var the CLI's Cloud submitter reads. Current templates scaffold this correctly. If you encounter a `.gitlab-ci.yml` naming it `SIGCOMPLY_OIDC_TOKEN` (from an older CLI), rename it or cloud submission is silently skipped. See [Troubleshooting](guides/troubleshooting.md).

`init-ci` is SOC 2 only in v1-alpha; other frameworks exit `3`.

## 6. Run a check

```bash
sigcomply check
```

`check` reads `framework:` from the config — it has **no** `--framework` flag. Expected outcomes for self-verification:

- Exit `0` — all policies passed.
- Exit `1` — violations found (only when `ci.fail_on_violation` is set in config).
- Exit `2` — execution error.
- Exit `3` — configuration error (e.g. a missing `framework:`).

You can scope a run to one cadence, e.g. `sigcomply check --cadence daily`. The run writes signed evidence to the vault. Inspect it read-only with:

```bash
sigcomply report --period <id> --view latest
```

`--period` is required (e.g. `2026-Q1`); missing → exit `3`.

## Common mistakes to avoid

- **Framework key is singular** — `framework: soc2`, never `frameworks: [soc2]`.
- **The binding slot is `evidence`** — not `user_directory` or `access_keys`. Those slot names do not exist and cause exit `3`.
- **`check` has no `--framework` flag** and ignores `SIGCOMPLY_FRAMEWORK`; it reads the framework from config only.
- **Never put identifiers in any cloud-facing config** — no ARNs, emails, usernames, or account IDs. The model is non-custodial; only counts leave your environment.
- **`collect`, `evaluate`, and `config` commands do not exist.** Do not invent them. Wired commands are `check`, `init`, `init-ci`, `build`, `report`, `evidence catalog`, `version`.
- **HIPAA is not registered.** Only `soc2` and `iso27001` exist; any other framework name fails.
- **`go install` names the binary `sigcomply-cli`** — symlink it to `sigcomply`.
- **There is no Homebrew package.**

## AGENTS.md template for the customer repo

Commit this file as `AGENTS.md` in the customer's compliance repository so any agent working there has local guidance. Replace the bracketed values.

```markdown
# AGENTS.md — SigComply compliance repo

This repository runs SigComply SOC 2 evidence collection. One repo = one
framework = one evidence vault. Docs: https://github.com/SigComply/sigcomply-cli

## Dev environment

- Framework: soc2 (set as `framework: soc2` in `.sigcomply.yaml`, singular key).
- Credentials come from the environment, never the config file:
  AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_REGION (or a role/OIDC).
- CI host: [GitHub Actions | GitLab CI].

## Setup

    curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh | sh
    sigcomply version   # expect exit 0

Config lives in `.sigcomply.yaml`. Regenerate a starter with `sigcomply init -f soc2`.

## Run a check

    sigcomply check              # full run; reads framework from config
    sigcomply check --cadence daily
    sigcomply report --period [YYYY-Qn] --view latest

Exit codes: 0 passed · 1 violations · 2 execution error · 3 config error.

## Do not

- Do not add identifiers (ARNs, emails, usernames, account IDs) to any
  cloud-facing config. The model is non-custodial — only counts leave.
- Do not use `frameworks:` (plural) — the key is singular `framework:`.
- Do not key a `bindings:` block on `user_directory`/`access_keys`; the
  slot is `evidence`.
- Do not pass `--framework` to `check`; it reads config only.
- Do not use `collect`, `evaluate`, or `config` — they are not wired.
- Do not select `hipaa` — only `soc2` and `iso27001` are registered.
```

## See also

- [Quickstart](quickstart.md) — zero to a first passing check.
- [Configuration](configuration.md) — full `.sigcomply.yaml` schema.
- [Commands](reference/commands.md) — every command and flag.
- [/llms.txt](../llms.txt) — machine-readable doc index.
- [Documentation hub](README.md).
