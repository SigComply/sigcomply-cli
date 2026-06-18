# sigcomply

> Zero-trust, non-custodial compliance engine — **"Evidence without Access."**

The `sigcomply` CLI runs locally in your CI/CD and turns infrastructure state
into signed compliance evidence — without giving any third party access to
your data, credentials, or production environment. Raw evidence stays in
your own storage; only aggregated counts and pass/fail scores are submitted
to the optional Compliance Dashboard.

Ships SOC 2 (Type II) and ISO/IEC 27001:2022 (all 93 Annex A controls)
policy libraries. Policies are open, Go-native declarative definitions
(a `pass_when` DSL) — inspect, fork, and contribute.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/sigcomply/sigcomply-cli/main/scripts/install.sh | sh
```

This downloads the pre-built binary for your platform from the latest
GitHub release. Alternatively, with a Go toolchain:

```sh
go install github.com/sigcomply/sigcomply-cli@latest
```

## Quick start

```sh
sigcomply check
```

The framework comes from `framework:` in `.sigcomply.yaml` (or the
`SIGCOMPLY_FRAMEWORK` env var); `check` has no `--framework` flag.
Auto-detects collectors based on available credentials (`AWS_*`,
`GITHUB_TOKEN`, GCP ADC, …), evaluates the framework's policies locally,
writes signed `EvidenceEnvelope` files to your storage backend, and (in
CI with OIDC) submits aggregated results to the SigComply Cloud API.

## Supported sources

The CLI ships 59 built-in source plugins across seven providers, all
self-registering and compiled in:

| Provider | Coverage |
|---|---|
| **AWS** (23) | IAM, access keys, password policy, S3, RDS, DynamoDB, EC2, Lambda, EKS, ECR, KMS, Secrets Manager, CloudTrail, CloudWatch, Config, VPC, security groups, ACM, Backup, GuardDuty, Inspector, Security Hub, security alerts |
| **GCP** (18) | Cloud Identity, IAM, Compute, GKE, Cloud SQL, Firestore, Cloud Storage, KMS, Secret Manager, Logging, Audit Logs, Cloud Asset, VPC, firewall, Artifact Registry, Backup & DR, Certificate Manager, Security Command Center |
| **Azure** (14) | Entra ID, Storage, SQL, Cosmos DB, VMs, AKS, ACR, Key Vault, Monitor, Network, Backup, certificates, Defender for Cloud, Policy |
| **GitHub** | repositories, org members, org security policy, Dependabot findings |
| **GitLab** | repositories, group members |
| **Okta** | directory users, assigned apps |
| **Manual** | PDF/image evidence from any S3 / GCS / Azure Blob / local folder |

Because policies bind to a cloud-neutral *evidence type* and never to a
vendor, a control like "MFA enforced on admins" or "object storage
encrypted at rest" is satisfied identically by AWS, GCP, or Azure with
zero policy changes — and adding a new source for an existing type needs
no policy edits. Full provider × evidence-type coverage matrix:
[docs/architecture/04-source-plugins.md](docs/architecture/04-source-plugins.md).

## Commands

| Command | Purpose |
|---|---|
| `sigcomply check` | Plan → collect → evaluate → aggregate → sign/store → submit. |
| `sigcomply init-ci` | Scaffold per-cadence CI workflow files. |
| `sigcomply build` | Compile a project-tailored binary with `.sigcomply/` Go extensions. |
| `sigcomply report` | Read-only auditor snapshot of the vault. |
| `sigcomply evidence catalog` | Print the manual-evidence catalog (`-o text\|json`). |
| `sigcomply version` | Print version, commit, and build time. |

Exit codes: `0` passed · `1` violations · `2` execution error · `3`
configuration error.

## Project model

**One project = one source-control repository = one compliance framework.**
A project is the GitHub or GitLab repo you run `sigcomply` in. Its
`.sigcomply.yaml` selects exactly one framework (`framework: soc2`).
Customers pursuing multiple frameworks (e.g. SOC 2 + ISO 27001) use
multiple repos — one per framework — each with its own config, CI
workflow, and evidence vault.

## Manual evidence

For evidence that isn't an API call (declarations, training certificates,
HR exports), the CLI scans a folder in your storage:

```
{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/
```

Upload any number of files — PDF, JPEG, PNG, GIF, TIFF, WebP, or BMP to the
folder above. Images are auto-converted to PDF; all files are merged into one
before evaluation. `sigcomply check` resolves each manual policy's folder from
the framework's catalog and the active period, then scans it.

Set the framework via `SIGCOMPLY_FRAMEWORK` or `framework:` in your config file
(default: `soc2`).

The optional [Evidence SPA](https://github.com/SigComply/sigcomply-evidence-spa)
is a standalone helper that generates PDFs for declaration- and checklist-style
entries — the CLI never talks to it. For all other manual evidence (HR exports,
training certificates, scanned documents) you produce the file yourself and
upload it to the folder above.

## CI/CD

Run `sigcomply init-ci` to scaffold standalone, per-cadence workflow
files calibrated to your framework's cadence distribution. On GitHub
Actions it writes `compliance-{daily,weekly,monthly,quarterly,annual,on-push}.yml`
under `.github/workflows/`; each downloads the binary from GitHub
Releases and runs `sigcomply check` for that cadence.

Copy-paste starting points also live under `examples/`:
`examples/github-actions/{basic,multi-environment}.yml` and
`examples/gitlab-ci.yml`. A first-class packaged GitLab CI component is
not yet available — copy or `include:` the example pipeline.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — system design, evidence flows, signing
- [docs/configuration.md](docs/configuration.md) — config file, env vars, flags
- [CLAUDE.md](CLAUDE.md) — context for AI coding assistants

## License

Apache-2.0 — see [LICENSE](LICENSE).
