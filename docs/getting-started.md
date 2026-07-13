# Getting started

The full SOC 2 journey — from signing up on SigComply Cloud to inviting your
auditor — with the CLI running automatically in CI.

This tutorial builds on the [Quickstart](quickstart.md), which gets you a first
passing `check` locally. Here we go end to end: connect the cloud dashboard, run
in CI with OIDC, add manual evidence, and hand results to an auditor. Each stage
links to a focused how-to guide for the deep detail.

> If you haven't run `sigcomply check` locally yet, do the
> [Quickstart](quickstart.md) first — it takes ~10 minutes. Back to the
> [docs hub](README.md).

**The journey:**

1. Sign up on SigComply Cloud and connect your repo
2. Install the CLI and scaffold a config
3. Configure your real sources and credentials
4. Scaffold CI and enable OIDC
5. First CI run → starts your 2-month Pro trial
6. View results on the dashboard
7. Add manual evidence
8. Invite your auditor

## 1. Sign up and connect your repo

The cloud dashboard is the optional paid tier that turns submitted counts into
compliance dashboards and auditor reports.

1. Sign up on **SigComply Cloud**. The first user becomes the organization owner.
2. **Connect a project** by pasting your GitHub or GitLab **repo URL**. This
   registers the repo so OIDC tokens minted by its CI are recognized on
   submission.

> If you later rename the repo, re-paste the URL on the dashboard — otherwise
> OIDC authentication for submissions will break.

Full walkthrough: [guides/cloud-dashboard.md](guides/cloud-dashboard.md).

## 2. Install the CLI and scaffold a config

Install the CLI (see [guides/install.md](guides/install.md)) and, from the root
of the repo you just connected:

```sh
sigcomply init -f soc2
```

This writes `.sigcomply.yaml`. Commit it to the repo — CI will use it.

## 3. Configure your real sources and credentials

Edit `.sigcomply.yaml` to declare every source you want SigComply to collect from.
**Each source must appear in the `sources:` block** — the CLI reads credentials
from the environment but does not auto-register a source just because credentials
exist.

For example, an AWS + GitHub project:

```yaml
schema_version: project.v1
framework: soc2
sources:
  aws.iam:
    region: us-east-1
  aws.s3:
    region: us-east-1
  github:
    org: your-org
vault:
  backend: s3
  bucket: your-evidence-vault
  region: us-east-1
  prefix: sigcomply/
```

Credentials come from the environment: `AWS_*` for AWS, `GITHUB_TOKEN` for
GitHub, GCP ADC for GCP, and so on — never from the config file. All collectors
use read-only calls; attach `ReadOnlyAccess` or a scoped read policy.

Per-source keys and least-privilege details:
[guides/configure-sources.md](guides/configure-sources.md).

> For a real audit, use a durable vault (S3/GCS/Azure Blob) with write-once or
> versioned storage — see [Verify evidence](guides/verify-evidence.md) and
> [Concepts](concepts.md) for why. Local vaults are for dev/CI experimentation.

## 4. Scaffold CI and enable OIDC

Generate per-cadence CI workflows. **If your code is on GitHub:**

```sh
sigcomply init-ci --ci github
```

This writes one workflow per cadence under `.github/workflows/`
(`compliance-daily.yml`, `-weekly`, `-monthly`, `-quarterly`, `-annual`, and
`-on-push.yml`). Each workflow includes the OIDC permission the runner needs:

```yaml
permissions:
  id-token: write
  contents: read
```

No SigComply secret is required — the Actions runner mints the OIDC JWT (audience
`https://api.sigcomply.com`), and cloud submission auto-enables in CI. You'll also
set an `AWS_ROLE_ARN` for an IAM role whose trust policy allows the GitHub OIDC
provider. Details: [guides/ci-github.md](guides/ci-github.md).

**If your code is on GitLab:**

```sh
sigcomply init-ci --ci gitlab
```

This writes a single `.gitlab-ci.yml` with cadence-keyed jobs driven by pipeline
schedules. GitLab OIDC needs an `id_tokens:` block with
`aud: https://api.sigcomply.com`. **Read [guides/ci-gitlab.md](guides/ci-gitlab.md)
carefully** — the shipped template has a known id-token naming caveat that must be
corrected for cloud submission to work.

> `init-ci` ships SOC 2 cadence templates in v1-alpha; other frameworks exit 3.

## 5. First CI run starts your Pro trial

Commit and push the config and workflows. On the first run that submits to the
cloud, SigComply automatically starts a **2-month, no-credit-card Pro trial** for
your organization. During the trial the compliance dashboard and auditor portal
are fully available. (After the trial expires, submissions return HTTP 402 with an
upgrade URL.)

## 6. View results on the dashboard

Open SigComply Cloud. The projects list and per-policy evaluations render the
submitted counts, scores, and staleness — never raw evidence. Remember the
privacy invariant: the cloud sees `mfa_disabled_count: 3`, never the identities
behind it. More: [guides/cloud-dashboard.md](guides/cloud-dashboard.md).

## 7. Add manual evidence

Some SOC 2 evidence isn't an API call — access reviews, signed NDAs, training
certificates, risk-acceptance declarations. For these, upload files to a folder in
your storage:

```
{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/
```

Configure the manual source once (it's a project-level singleton):

```yaml
sources:
  manual.pdf:
    backend: s3
    bucket: your-evidence-bucket
    region: us-east-1
    prefix: manual/
```

Then point a policy at a catalog entry:

```yaml
policies:
  <policy-id>:
    evidence_mode: manual
    catalog_entry: <catalog-id>
```

Browse catalog entry IDs with `sigcomply evidence catalog -f soc2`. The CLI checks
only that supported files (PDF/JPEG/PNG/GIF/TIFF/WebP/BMP) are present within the
temporal window — it does not read PDF contents. Full guide:
[guides/manual-evidence.md](guides/manual-evidence.md).

## 8. Invite your auditor

As the organization owner, invite auditor seats from the dashboard. The auditor
receives a set-password email and logs into the auditor portal to review results
and download reports (auditors cannot self-register).

For independent spot-checks, auditors can verify any signed `EvidenceEnvelope`
themselves — either with `sigcomply report --view integrity` against the vault, or
with the in-browser `/verify` page of the Evidence SPA. See
[guides/verify-evidence.md](guides/verify-evidence.md) and
[guides/cloud-dashboard.md](guides/cloud-dashboard.md).

## Next steps

- **[Configure sources](guides/configure-sources.md)** — per-source keys and RBAC.
- **[CI on GitHub](guides/ci-github.md)** / **[CI on GitLab](guides/ci-gitlab.md)** — the full CI setup.
- **[Manual evidence](guides/manual-evidence.md)** — the complete upload-and-consume flow.
- **[Cloud dashboard](guides/cloud-dashboard.md)** — connection, trial, and auditor management.
- **[Concepts](concepts.md)** — why the model is non-custodial and how signing works.
- Back to the **[docs hub](README.md)**.
