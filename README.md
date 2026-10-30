# sigcomply

SOC 2 and ISO 27001 checks and signed evidence, run in your own CI.

SigComply runs in your GitHub or GitLab pipeline, checks your cloud and SaaS configuration
against SOC 2 and ISO 27001, and signs the evidence into storage you own. The CLI is free to use
and its source is public. SigComply Cloud (paid, with a 2-month free trial) is an optional
dashboard: it receives pass/fail counts per policy and turns them into a record of every
scheduled run and reports for you and your auditor.

Evidence without access: no vendor gets a role in your cloud or OAuth access to your code host
and identity provider, including us.

## Why teams use it

- Your evidence stays in your storage. The CLI reads AWS, GCP, Azure, GitHub, GitLab, Okta
  and Active Directory with the credentials you give your own pipeline, and writes the evidence
  to a bucket or folder you own.
- Compliance checks run like tests. `sigcomply init` writes the config and `sigcomply init-ci`
  writes the CI workflow. A policy violation fails the build, like a failing test. No agents on
  laptops and no OAuth apps to install.
- Signed evidence your auditor can verify. Every evidence file and every run is signed. A
  file changed after the run fails verification. Keep the bucket write-once (for example S3
  Object Lock) and nobody can replace and re-sign it.

SigComply checks configuration and collects evidence. It doesn't run vendor reviews, security
training, device monitoring or background checks, host a trust center, or perform the audit. A
GRC platform covers more of that, and needs more access to your systems to do it. SigComply does
not certify anything; your auditor decides whether you comply.

## How it works

1. A step in your pipeline runs `sigcomply check`, on a daily schedule, and on pull requests and
   pushes to main.
2. Automated policies evaluate configuration read from cloud and SaaS APIs.
3. Manual policies check that a document (a policy, a training record, a review) is in the right
   folder for the period. The CLI never reads or judges what the document says; your auditor
   does.
4. The CLI writes the signed evidence, the results and a signed manifest of every file's hash
   to your storage. With SigComply Cloud turned on, it also sends pass/fail counts per policy,
   never evidence files, their hashes, or the names, emails and account IDs of what it checked.

A run prints one line per policy and exits 1 if any policy fails (2 on an execution error). This
run had only manual evidence configured; the counts depend on the release and your sources:

```text
SigComply check soc2/2026-Q4 — 133 policies
  pass=1 fail=51 carried=0 skip=81 error=0 na=0 waived=0
  [fail] soc2.a1.1.capacity_management_process — A1.1
      ↳ manual evidence not found; expected files in: file://./evidence/manual/capacity_management_process/2026/
  [pass] soc2.a1.2.business_continuity_plan — A1.2
...
Results written to ./.sigcomply/vault/soc2/2026-Q4/run_20261030T090413Z_e84412b4
```

[How it works](docs/how-it-works.md) covers a run stage by stage: API and manual evidence,
signing and verification, what leaves your pipeline, and links to every implementation doc.

## Try it in five minutes, no cloud account

```sh
curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh | sh
```

The script installs the latest release into `/usr/local/bin`. For a pinned version, another
folder or `go install`, see [Install](docs/guides/install.md).

The [Quickstart](docs/quickstart.md) runs SigComply on your laptop with manual evidence only, so
it needs no credentials. You run a check, add one PDF to make a control pass, verify the
signatures, then change a file and watch verification fail. Its last step adds a read-only AWS
account to see automated checks.

## Add it to your pipeline

```sh
sigcomply init                 # writes .sigcomply.yaml
sigcomply init-ci --ci github  # or --ci gitlab; writes the CI workflow
```

[Run SigComply in CI](docs/getting-started.md) walks through the rest: a bucket for the
evidence, a CI role that your pipeline assumes over OIDC, the first run, and uploading manual
evidence. To send counts to SigComply Cloud, add `cloud.base_url` and your project ID to the
config ([Cloud dashboard](docs/guides/cloud-dashboard.md)).

## What it checks

- SOC 2 (2017 Trust Services Criteria) and ISO/IEC 27001:2022. For ISO 27001 that covers
  all 93 Annex A controls, 26 of them with an automated check, plus
  the 16 management-system requirements of clauses 4-10. Counts per framework are in
  [Frameworks](docs/reference/frameworks.md).
- Sources: AWS, GCP, Azure, GitHub, GitLab, Okta, Active Directory, and manual documents in a
  local folder, S3, GCS or Azure Blob ([Sources](docs/reference/sources.md)).
- Every policy is readable in the source. You can add your own policies (YAML or Rego) in your
  repository, and `check` loads them. Custom sources are Go; `sigcomply build` compiles them
  into the CLI.
- Reports from your own storage, including the ISO 27001 Statement of Applicability:
  `sigcomply report`.

## Documentation

All docs are indexed in [docs/README.md](docs/README.md).

| You want to | Read |
|---|---|
| Understand how SigComply works before you adopt it | [How it works](docs/how-it-works.md) |
| Try it on your laptop, no cloud account needed | [Quickstart](docs/quickstart.md) |
| Run SigComply in CI, with or without the dashboard | [Run SigComply in CI](docs/getting-started.md) |
| Do one task: add a source, upload evidence, verify a run | [How-to guides](docs/README.md#how-to-guides) |
| Look up a command, flag, config key or exit code | [Reference](docs/README.md#reference) |
| Read what leaves your environment and the limits of signing | [Concepts](docs/concepts.md) |
| Set up a repo with an AI coding agent | [For AI agents](docs/for-ai-agents.md) |
| See what changed between releases | [Changelog](CHANGELOG.md) |

Contributors: start with [CONTRIBUTING.md](CONTRIBUTING.md) and [ARCHITECTURE.md](ARCHITECTURE.md).
Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## License

SigComply is an open core product. The CLI is free to use and its source is public, but it is
source-available, not open source: it is licensed under the
[Elastic License 2.0](LICENSE) (ELv2). The paid part today is SigComply Cloud. Paid CLI features
added later may need a license key.

Under ELv2 you can use, copy, modify and redistribute the CLI, including at work and in your
CI, at no cost. You may not:

- provide it to others as a hosted or managed service that gives them a substantial set of its
  features or functionality;
- move, change, disable or circumvent its license key functionality, or remove or obscure a
  feature that a license key protects;
- alter, remove or obscure SigComply's licensing, copyright or other notices.

Anyone you give a copy to must also get the license terms, and modified copies must carry a
prominent notice that you changed them.

Code published before the license change, including every release up to and including
v0.90.2, was released under Apache-2.0 and remains available under it. See [NOTICE](NOTICE).
For other licensing terms, contact support@sigcomply.com.
