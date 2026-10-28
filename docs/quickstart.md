# Quickstart

In this tutorial you run SigComply on your own machine against one AWS account, store the
signed evidence in a local folder, and make one manual-evidence control pass by adding a
document. Nothing leaves your machine.

## Before you start

You need:

- AWS credentials with read-only access to one account, for example a user or role with the
  AWS-managed `ReadOnlyAccess` policy. Sources only read: SigComply makes read calls, plus
  `iam:GenerateCredentialReport`, which asks AWS to build the account's credential report. The
  [source reference](reference/sources.md) lists every API action. The CLI writes only to the vault you configure, here a local folder.
- A macOS or Linux shell.
- Any PDF file, to use as a stand-in document in step 5.

## 1. Install the CLI

```sh
curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh | sh
sigcomply version
```

The script installs the latest release into `/usr/local/bin` and runs `sudo` if it can't write
there. To install somewhere else, set `SIGCOMPLY_INSTALL_DIR` first. Other options are in
[Install](guides/install.md).

## 2. Create a project and scaffold a config

```sh
mkdir sigcomply-quickstart
cd sigcomply-quickstart
sigcomply init -f soc2
```

`init` writes `.sigcomply.yaml`, a commented SOC 2 config that works as it is. These are the
lines that matter for this tutorial:

```yaml
framework: soc2

sources:
  aws.iam:
    region: us-east-1
  aws.iam_access_key:
    region: us-east-1
  aws.password_policy:
    region: us-east-1
  # aws.acm: { region: us-east-1 }
  # ... one commented line per AWS service
  manual.pdf:
    backend: local
    path: ./evidence

vault:
  backend: local
  path: ./.sigcomply/vault
```

- `sources` lists where evidence comes from. AWS has one source per service: `aws.iam` reads IAM
  users, `aws.iam_access_key` their access keys, and `aws.password_policy` the account password
  policy. The file lists every other AWS source commented out; uncomment a line to read that
  service too. `manual.pdf` reads documents you upload under `./evidence/manual/` (`manual/` is
  the default prefix inside that folder).
- `vault` is where SigComply writes signed results: here, a local folder.

Credentials never go in this file. The CLI reads them from the environment.

Relative paths such as `./evidence` and `./.sigcomply/vault` resolve against the directory you
run `sigcomply` in, not the folder that holds the config. Run every command from the project
root.

`init` prints a reminder to keep the local vault out of git. Do it now, before a `git add .`
picks up hundreds of run files:

```sh
echo '.sigcomply/vault/' >> .gitignore
```

## 3. Export your AWS credentials

```sh
export AWS_ACCESS_KEY_ID=<your-access-key-id>
export AWS_SECRET_ACCESS_KEY=<your-secret-access-key>
```

`AWS_PROFILE`, `AWS_SESSION_TOKEN` and anything else the AWS SDK reads also work.

## 4. Run a check

```sh
sigcomply check
echo $?
```

The CLI names the sources it is about to read, then prints one line per policy. The first line
of the summary names the framework and the period, for example:

```
SigComply check soc2/2026-Q4 — <n> policies
  pass=... fail=... carried=0 skip=... error=0 na=0 waived=0
```

Note this run period (`2026-Q4` here). You need it in step 6. The last lines name the run folder
in the vault and the `report` command that reads it back. The CLI takes the period from the
current UTC time.

`echo $?` prints `1` on a first run. That is expected: some policies fail. You'll see three
kinds of lines:

- `[pass]` and `[fail]` lines for IAM policies, such as `soc2.cc6.1.mfa_enforced_all_users`, and
  for the access key and password policies.
  Under a failing policy, a `↳` line says what failed.
- `[fail]` lines for documents you haven't uploaded yet. SOC 2 ships 50 catalog entries whose
  evidence is a document (a policy, a training record, a review), and each line names the
  folder to put it in:

  ```
  [fail] soc2.c1.3.nda_policy — C1.3
      ↳ manual evidence not found; expected files in: file://./evidence/manual/nda_policy/2026/
  ```

- `[skip]` lines for policies that need a source you haven't configured, such as GitHub or an
  AWS service whose line is still commented out. A block at the end of the output lists each skipped policy and the evidence type it
  needs.

If `check` exits `3` with `no usable AWS credentials`, the variables from step 3 aren't set in
this shell.

## 5. Add one document

Make the NDA policy pass. Use the folder from its `↳` line. The last part of that path is not the
run period from step 4: each document has its own period, set by how often it is due. The NDA
policy is annual, so its folder is the calendar year. Replace `2026` below if your
output shows a different year, and use the path of any PDF you have:

```sh
mkdir -p evidence/manual/nda_policy/2026
cp /path/to/any.pdf evidence/manual/nda_policy/2026/
sigcomply check
```

The NDA line now reads `[pass] soc2.c1.3.nda_policy — C1.3`. The CLI checked that a supported
file is in the folder for the period. It did not read the file. Judging what a document says
is your auditor's job. The run still exits `1`, because the other policies still fail.

To list every document the framework expects and where it goes, run:

```sh
sigcomply evidence due --all
```

## 6. Look at the evidence

Each run writes a folder under `.sigcomply/vault/soc2/<period>/`:

```
run_20261026T201203Z_14f82a86/
  manifest.json          # SHA-256 hash of every file in the run, signed
  summary.json           # status of every policy
  policies/<policy-id>/
    result.json          # the policy result, with the full list of failing resources
    envelopes/           # the evidence the policy read, signed
    attachments/         # manual policies only: <entry ID>.pdf, the uploaded files merged
```

Read it back with `report`, using the period ID from step 4 (`2026-Q4` or `soc2/2026-Q4` both
work):

```sh
sigcomply report --period 2026-Q4
sigcomply report --period 2026-Q4 --view integrity
```

The first command lists each policy's latest status. The second re-checks every signature and
file hash in the period's runs and prints `pass` for each intact run.

## Next steps

- [Run SigComply in CI](getting-started.md): run SigComply in CI on a schedule, and optionally send
  results to the SigComply Cloud dashboard.
- [Configure sources](guides/configure-sources.md): add GCP, Azure, GitHub, GitLab, Okta or
  Active Directory.
- [Concepts](concepts.md): what leaves your environment, how signing works, and what a passing
  score does not tell you.
