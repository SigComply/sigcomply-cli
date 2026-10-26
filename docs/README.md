# SigComply CLI documentation

The `sigcomply` CLI evaluates SOC 2 and ISO 27001 policies against your infrastructure from your
own CI, collects the documents you upload, and signs the evidence into storage you own. New to
it? Start with the [Quickstart](quickstart.md).

## Tutorials

| Page | What you do |
|---|---|
| [Quickstart](quickstart.md) | Run a first check against one AWS account on your machine and add one document |
| [Run SigComply in CI](getting-started.md) | Move the project to CI with a bucket vault, AWS OIDC and, optionally, the SigComply Cloud dashboard |

## How-to guides

| Guide | Task |
|---|---|
| [Install](guides/install.md) | Install the CLI, pin a version, verify the download |
| [Configure sources](guides/configure-sources.md) | Add AWS, GCP, Azure, GitHub, GitLab, Okta or Active Directory with read-only credentials |
| [Identity roster](guides/identity-roster.md) | Check every system's accounts and cloud IAM grants against the directory that lists your people |
| [CI on GitHub](guides/ci-github.md) | Set up the scaffolded GitHub Actions workflows and AWS OIDC |
| [CI on GitLab](guides/ci-gitlab.md) | Set up the scaffolded `.gitlab-ci.yml`, pipeline schedules and AWS OIDC |
| [Manual evidence](guides/manual-evidence.md) | Upload documents to the right folder, and build declaration PDFs with the Evidence SPA |
| [Vendor and third-party risk](guides/vendor-risk.md) | Declare your vendors and collect assurance documents per vendor |
| [ISMS clauses and the SoA](guides/isms-clauses.md) | Cover ISO 27001's clause 4-10 requirements and generate the Statement of Applicability |
| [Cloud dashboard](guides/cloud-dashboard.md) | Connect a repository to SigComply Cloud and invite your auditor |
| [Verify evidence](guides/verify-evidence.md) | Check signatures, coverage and scope with `sigcomply report` and the `/verify` page |
| [Troubleshooting](guides/troubleshooting.md) | Fix common errors |

## Reference

| Page | Contents |
|---|---|
| [Commands](reference/commands.md) | Commands, flags, exit codes, framework resolution |
| [Configuration](configuration.md) | Every `.sigcomply.yaml` key, environment variables, storage backends |
| [Sources](reference/sources.md) | Per-source config keys, credentials, permissions and evidence types |
| [Frameworks](reference/frameworks.md) | Framework IDs, policy and control counts, ISO 27001 control prefixes |
| [Changelog](../CHANGELOG.md) | Changes per release |

## Explanation

| Page | Topic |
|---|---|
| [Concepts](concepts.md) | What SigComply does and doesn't do, the two evidence flows, what leaves your environment, signing and its limits, what the score hides |
| [SECURITY.md](../SECURITY.md) | Threat model and how to report a vulnerability |

## For AI agents

| Page | Purpose |
|---|---|
| [For AI agents](for-ai-agents.md) | Runbook for an agent setting up a customer repository, with an `AGENTS.md` template |
| [llms.txt](../llms.txt) | Index of these docs for language models |

Contributors: [ARCHITECTURE.md](../ARCHITECTURE.md) and [architecture/](architecture/) describe
the internals.
