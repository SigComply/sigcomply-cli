# SigComply CLI documentation

The complete documentation set for the `sigcomply` CLI — the zero-trust,
non-custodial compliance engine that collects and signs SOC 2 evidence in your
own CI/CD, keeping raw evidence in your own storage.

> **New here?** Start with the **[Quickstart](quickstart.md)** — zero to your
> first passing `sigcomply check` in about 10 minutes, entirely on your machine.

> **Pointing an AI agent at these docs?** See **[for-ai-agents.md](for-ai-agents.md)**
> and **[/llms.txt](../llms.txt)** for an agent-oriented index and a runbook you
> can drop into your customer repo.

These docs follow the [Diátaxis](https://diataxis.fr/) model: **Tutorials** teach
by doing, **How-to guides** solve a specific task, **Reference** is dry lookup,
and **Explanation** covers the "why".

## Tutorials

Hand-held, start-to-finish learning paths.

| Doc | What you'll do |
|---|---|
| [Quickstart](quickstart.md) | Install, `sigcomply init`, and run your first passing `check` against AWS into a local vault (~10 min). |
| [Getting started](getting-started.md) | The full SOC 2 journey: connect SigComply Cloud, wire up CI with OIDC, add manual evidence, and invite your auditor. |

## How-to guides

Task-focused recipes for a specific goal.

| Doc | Task |
|---|---|
| [Install](guides/install.md) | Install the CLI (script or Go), pin a version, verify. |
| [Configure sources](guides/configure-sources.md) | Declare sources and supply read-only credentials for AWS, GCP, Azure, GitHub, GitLab, Okta. |
| [CI on GitHub](guides/ci-github.md) | Scaffold and wire per-cadence GitHub Actions workflows with OIDC. |
| [CI on GitLab](guides/ci-gitlab.md) | Scaffold `.gitlab-ci.yml`, pipeline schedules, and OIDC (incl. the id-token caveat). |
| [Manual evidence](guides/manual-evidence.md) | Upload PDF/image evidence to a bucket folder and consume it from a policy. |
| [Cloud dashboard](guides/cloud-dashboard.md) | Connect a repo, start the Pro trial, and manage auditor seats. |
| [Verify evidence](guides/verify-evidence.md) | Use `report` views and the `/verify` SPA to check signatures and integrity. |
| [Troubleshooting](guides/troubleshooting.md) | Diagnose common errors, exit codes, and the GitLab cloud caveat. |

## Reference

Exhaustive, dry lookup.

| Doc | Contents |
|---|---|
| [Commands](reference/commands.md) | Every command, flag, default, and exit code. |
| [Frameworks](reference/frameworks.md) | Shipped frameworks, policy counts, and manual catalog overview. |
| [Configuration](configuration.md) | Full `.sigcomply.yaml` schema, env vars, and precedence. |

## Explanation

Background and design rationale.

| Doc | Topic |
|---|---|
| [Concepts](concepts.md) | The non-custodial model, the aggregation boundary, ephemeral signing, and the two evidence flows. |
| [Architecture docs](architecture/) | Deep design docs (layers, evidence-type registry, vault layout, cadence, …). |

## For AI agents

| Doc | Purpose |
|---|---|
| [For AI agents](for-ai-agents.md) | Runbook for agents setting up a customer compliance repo, plus an `AGENTS.md` template. |
| [llms.txt](../llms.txt) | Machine-readable index of these docs. |

## See also

- [Project README](../README.md) — the front-door router.
- [CLAUDE.md](../CLAUDE.md) — context for AI coding assistants working **on** the CLI itself.
