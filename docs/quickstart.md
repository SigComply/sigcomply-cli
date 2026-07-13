# Quickstart

Your first passing `sigcomply check`, start to finish, on your own machine.

**Goal:** in about 10 minutes you'll have your first passing `sigcomply check`
writing signed SOC 2 evidence to a local vault — no cloud, no CI, no credit card.

Everything runs locally against a read-only AWS account. When you're done, you'll
have signed evidence in `./.sigcomply/vault` and a passing run summary.

> This is the hand-held happy path. For the fuller journey (CI, cloud dashboard,
> manual evidence, auditors), continue to [Getting started](getting-started.md).
> Back to the [docs hub](README.md).

## Prerequisites

- **An AWS account** you can read from, with credentials that have read-only
  access (e.g. the AWS-managed `ReadOnlyAccess` policy). All SigComply collectors
  use read-only `Describe`/`List`/`Get` calls only.
- **The `sigcomply` CLI** installed and on your `PATH`. If you haven't yet:

  ```sh
  curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh | sh
  ```

  Verify it:

  ```sh
  sigcomply version
  # sigcomply <version> (commit <c>, built <t>)
  ```

  Full install options: [guides/install.md](guides/install.md).

## Step 1 — Scaffold a config

From an empty directory (or your project repo), generate a ready-to-edit config:

```sh
sigcomply init -f soc2
```

This writes `.sigcomply.yaml` and prints the path. It refuses to overwrite an
existing file unless you pass `--force`.

A minimal, known-good config looks like this — the scaffold is a commented
superset of it:

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

Two things to know:

- **Credentials never go in this file.** They come from the ambient environment
  (Step 2). The config only names the sources you want and where to store
  evidence.
- **Policies auto-bind** to any configured source that emits the evidence type
  they need — you do **not** need a `bindings:` block to start.

## Step 2 — Export read-only AWS credentials

`sigcomply` reads AWS credentials from the environment using the standard AWS SDK
chain:

```sh
export AWS_ACCESS_KEY_ID=AKIAEXAMPLE
export AWS_SECRET_ACCESS_KEY=examplesecret
export AWS_REGION=us-east-1
```

(You can also use `AWS_PROFILE`, `AWS_SESSION_TOKEN`, or an assumed IAM role —
anything the AWS SDK understands.)

## Step 3 — Run the check

```sh
sigcomply check
```

`check` reads `framework: soc2` from your config (it has no `--framework` flag),
plans the SOC 2 policies for the current period, collects evidence from the AWS
source, evaluates each policy, and signs the results into your vault.

## What you'll see

A run summary is printed to your terminal, followed by an exit code:

- **Exit `0`** — every evaluated policy passed.
- **Exit `1`** — the run completed but found violations (policies that failed).
- Exit `2` = execution error, `3` = configuration error.

Check the exit code with:

```sh
echo $?
```

Both `0` and `1` mean the run worked — `1` just means your infrastructure has
findings to remediate, which is normal on a first run.

## Where your evidence landed

Everything is written to the local vault you configured (`./.sigcomply/vault`):

- **Signed `EvidenceEnvelope` files** — one per evidence file, each signed with a
  fresh ephemeral Ed25519 keypair (the private key is discarded immediately; the
  public key and signature are embedded in the envelope).
- **A per-run `manifest.json`** — a signed list of file hashes covering the whole
  run, so the run is integrity-verifiable from a single signature.

Run paths use basic ISO 8601 timestamps without colons (e.g. `20260325T100000Z`).
This vault is yours — raw evidence never leaves it.

Take a read-only look at what was produced:

```sh
sigcomply report --period 2026-Q1
```

(Use the period ID for the current quarter.) See
[guides/verify-evidence.md](guides/verify-evidence.md) for the available views.

## Next steps

- **[Getting started](getting-started.md)** — connect SigComply Cloud, run in CI
  with OIDC, add manual evidence, and invite an auditor.
- **[Configure sources](guides/configure-sources.md)** — add GCP, Azure, GitHub,
  GitLab, or Okta sources with read-only credentials.
- **[CI on GitHub](guides/ci-github.md)** / **[CI on GitLab](guides/ci-gitlab.md)** — automate `check` on a cadence.
- **[Configuration reference](configuration.md)** — the full `.sigcomply.yaml` schema.
- Back to the **[docs hub](README.md)**.
