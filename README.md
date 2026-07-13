# sigcomply

> Zero-trust, non-custodial compliance engine — **"Evidence without Access."**

The `sigcomply` CLI runs in your CI/CD, evaluates open Go-native policies against
your infrastructure and uploaded evidence, and signs the resulting evidence
locally into your **own** storage. Only aggregated **counts** and pass/fail
scores — never raw evidence, never identifiers — are (optionally) submitted to a
private cloud dashboard. Ships **SOC 2** (2017 Trust Services Criteria,
production-ready, default) and **ISO/IEC 27001:2022** (all 93 Annex A controls).

**One project = one source-control repo = one compliance framework = one evidence vault.**

## Install

Primary — downloads the prebuilt binary for your OS/arch from the latest GitHub release:

```sh
curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh | sh
```

Alternatively, with a Go toolchain:

```sh
go install github.com/sigcomply/sigcomply-cli@latest
```

> `go install` names the binary after the module's last path segment, so it
> installs as `sigcomply-cli`. Rename or symlink it to `sigcomply` so the
> commands below work as written:
>
> ```sh
> ln -sf "$(go env GOPATH)/bin/sigcomply-cli" "$(go env GOPATH)/bin/sigcomply"
> ```
>
> The module path is lowercase (`github.com/sigcomply/sigcomply-cli`) and
> case-sensitive — type it exactly.

Verify the install:

```sh
sigcomply version
# sigcomply <version> (commit <c>, built <t>)
```

## Quickstart

```sh
sigcomply init -f soc2          # scaffold .sigcomply.yaml
export AWS_ACCESS_KEY_ID=...     # read-only AWS credentials
export AWS_SECRET_ACCESS_KEY=...
sigcomply check                  # plan → collect → evaluate → sign → store
sigcomply report --period 2026-Q1   # read-only vault snapshot
```

`check` reads `framework:` from `.sigcomply.yaml` (it has **no** `--framework`
flag). Exit `0` = all policies passed, `1` = violations found. Signed evidence
lands in `./.sigcomply/vault`. Full walkthrough:
[docs/quickstart.md](docs/quickstart.md).

## Supported sources

The CLI ships built-in source plugins across seven providers, all
self-registering and compiled in. **Each source you want must be listed in the
`sources:` block of your config** — credentials are read from the ambient
environment, but the CLI does not auto-register a source just because
credentials exist.

| Provider | Coverage |
|---|---|
| **AWS** | IAM, access keys, password policy, S3, RDS, DynamoDB, EC2, Lambda, EKS, ECR, KMS, Secrets Manager, CloudTrail, CloudWatch, Config, VPC, security groups, ACM, Backup, GuardDuty, Inspector, Security Hub, security alerts |
| **GCP** | Cloud Identity, IAM, Compute, GKE, Cloud SQL, Firestore, Cloud Storage, KMS, Secret Manager, Logging, Audit Logs, Cloud Asset, VPC, firewall, Artifact Registry, Backup & DR, Certificate Manager, Security Command Center |
| **Azure** | Entra ID, Storage, SQL, Cosmos DB, VMs, AKS, ACR, Key Vault, Monitor, Network, Backup, certificates, Defender for Cloud, Policy |
| **GitHub** | repositories, org members, org security policy, Dependabot findings |
| **GitLab** | repositories, group members |
| **Okta** | directory users, assigned apps |
| **Manual** | PDF/image evidence from any S3 / GCS / Azure Blob / local folder |

Because policies bind to a cloud-neutral *evidence type* and never to a vendor, a
control like "MFA enforced on admins" or "object storage encrypted at rest" is
satisfied identically by AWS, GCP, or Azure with zero policy changes — and adding
a new source for an existing type needs no policy edits.

## Commands

| Command | Purpose |
|---|---|
| `sigcomply check` | Plan → collect → evaluate → aggregate → sign/store → submit. |
| `sigcomply init` | Scaffold a starter `.sigcomply.yaml` for the chosen framework. |
| `sigcomply init-ci` | Scaffold per-cadence CI workflow files (SOC 2 in v1-alpha). |
| `sigcomply build` | Compile a project-tailored binary with `.sigcomply/` Go extensions. |
| `sigcomply report` | Read-only auditor snapshot of the vault. |
| `sigcomply evidence catalog` | Print the manual-evidence catalog (`-o text\|json`). |
| `sigcomply version` | Print version, commit, and build time. |

Full flag reference: [docs/reference/commands.md](docs/reference/commands.md).

Exit codes: `0` passed · `1` violations · `2` execution error · `3` configuration error.

## Project model

**One project = one source-control repository = one compliance framework.** A
project is the GitHub or GitLab repo you run `sigcomply` in. Its `.sigcomply.yaml`
selects exactly one framework (`framework: soc2`). Customers pursuing multiple
frameworks (e.g. SOC 2 + ISO 27001) use multiple repos — one per framework — each
with its own config, CI workflow, and evidence vault.

## Manual evidence

For evidence that isn't an API call (declarations, training certificates, HR
exports), the CLI scans a folder in your storage:

```
{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/
```

Upload any number of files — PDF, JPEG, PNG, GIF, TIFF, WebP, or BMP. Images are
auto-converted to PDF and all files are merged into one before evaluation. The
CLI checks only that supported files are present within the temporal window; it
does **not** read PDF contents. Details: [docs/guides/manual-evidence.md](docs/guides/manual-evidence.md).

The optional [Evidence SPA](https://github.com/SigComply/sigcomply-evidence-spa)
generates PDFs for declaration- and checklist-style entries — the CLI never talks
to it.

## CI/CD

Run `sigcomply init-ci --ci github` (or `--ci gitlab`) to scaffold per-cadence
workflow files that download the released binary and run `sigcomply check` on a
schedule. Add `permissions: id-token: write` for OIDC-based cloud submission.
Guides: [docs/guides/ci-github.md](docs/guides/ci-github.md) ·
[docs/guides/ci-gitlab.md](docs/guides/ci-gitlab.md). Copy-paste examples live
under `examples/`.

## Documentation

Full docs are in [docs/](docs/README.md), organized by the
[Diátaxis](https://diataxis.fr/) model:

| Type | Doc |
|---|---|
| **Tutorial** | [Quickstart](docs/quickstart.md) — zero to first passing check, local, ~10 min |
| **Tutorial** | [Getting started](docs/getting-started.md) — full SOC 2 journey incl. CI + cloud |
| **How-to** | [Install](docs/guides/install.md) · [Configure sources](docs/guides/configure-sources.md) · [CI on GitHub](docs/guides/ci-github.md) · [CI on GitLab](docs/guides/ci-gitlab.md) |
| **How-to** | [Manual evidence](docs/guides/manual-evidence.md) · [Cloud dashboard](docs/guides/cloud-dashboard.md) · [Verify evidence](docs/guides/verify-evidence.md) · [Troubleshooting](docs/guides/troubleshooting.md) |
| **Reference** | [Commands](docs/reference/commands.md) · [Frameworks](docs/reference/frameworks.md) · [Configuration](docs/configuration.md) |
| **Explanation** | [Concepts](docs/concepts.md) — non-custodial model, signing, aggregation |
| **For AI agents** | [For AI agents](docs/for-ai-agents.md) · [llms.txt](llms.txt) |

Deep design docs live under [docs/architecture/](docs/architecture/); AI-coding
context in [CLAUDE.md](CLAUDE.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).
