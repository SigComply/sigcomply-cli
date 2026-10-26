# sigcomply

SigComply is a compliance engine and evidence collector that runs in your own CI. The
`sigcomply` CLI uses your read-only credentials to pull configuration from AWS, GCP, Azure,
GitHub, GitLab, Okta and Active Directory, and evaluates it against open SOC 2 and ISO 27001
policies. For controls no API can answer (policies, training records, reviews), it collects the
documents you upload: it checks that a supported file is present for the period, merges the
files into one PDF and signs it. It does not read or judge what the documents say; your auditor
does.

Raw evidence and results stay in storage you own. With a paid SigComply Cloud plan, the CLI also
sends pass/fail counts per policy, never identities, and the dashboard turns them into reports
for you and your auditor. SigComply does not certify anything; your auditor decides whether
you comply.

## What you get

- Open policies for SOC 2 (2017 Trust Services Criteria) and ISO/IEC 27001:2022. For ISO 27001
  that covers all 93 Annex A controls, 26 of them with an automated check, plus
  the 16 management-system requirements of clauses 4-10. Counts per framework are in
  [Frameworks](docs/reference/frameworks.md).
- Signed evidence in your own storage: a local folder, S3, GCS or Azure Blob. Each evidence file
  is signed with a one-time Ed25519 key, and each run has a signed manifest of file hashes.
- A list of the documents you still owe, with the folder for each: `sigcomply evidence due`.
- CI workflows for GitHub Actions and GitLab CI, scaffolded by `sigcomply init-ci`.
- Read-only reports from your storage, including the ISO 27001 Statement of Applicability:
  `sigcomply report`.
- Optional: the SigComply Cloud dashboard (paid, counts only), and the
  [Evidence SPA](https://sigcomply.github.io/sigcomply-evidence-spa/), a browser page that turns
  declaration and checklist forms into PDFs and verifies signed evidence files.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh | sh
```

The script installs the latest release into `/usr/local/bin`. For a pinned version, another
folder or `go install`, see [Install](docs/guides/install.md).

## Try it

```sh
sigcomply init -f soc2
export AWS_ACCESS_KEY_ID=<your-access-key-id> AWS_SECRET_ACCESS_KEY=<your-secret-access-key>
sigcomply check
sigcomply report --period <period-id>
```

`init` writes a `.sigcomply.yaml` that reads AWS IAM and stores signed results in
`./.sigcomply/vault`. `check` prints the period ID on its first summary line, for example
`soc2/2026-Q4`. The [Quickstart](docs/quickstart.md) walks through this run step by step.

## Documentation

All docs are indexed in [docs/README.md](docs/README.md).

| You want to | Read |
|---|---|
| Run a first check on your machine | [Quickstart](docs/quickstart.md) |
| Run SigComply in CI, with or without the dashboard | [Getting started](docs/getting-started.md) |
| Do one task: add a source, upload evidence, verify a run | [How-to guides](docs/README.md#how-to-guides) |
| Look up a command, flag, config key or exit code | [Reference](docs/README.md#reference) |
| Understand what leaves your environment and how signing works | [Concepts](docs/concepts.md) |
| Set up a repo with an AI coding agent | [For AI agents](docs/for-ai-agents.md) |
| See what changed between releases | [Changelog](CHANGELOG.md) |

Contributors: start with [CONTRIBUTING.md](CONTRIBUTING.md) and [ARCHITECTURE.md](ARCHITECTURE.md).
Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
