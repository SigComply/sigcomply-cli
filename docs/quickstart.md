# Quickstart

In this tutorial you run SigComply on your own machine with no cloud account and no
credentials. You make one manual-evidence policy pass by adding a document, verify the signed
evidence, and watch verification fail after you change a file. The checks send nothing anywhere.
To see how the pieces fit together first, read [How SigComply works](how-it-works.md).

## Before you start

You need:

- A macOS or Linux shell.
- Any PDF file, to use as a stand-in document in step 4. On macOS you can make one with
  `printf 'test\n' > a.txt && cupsfilter a.txt > a.pdf 2>/dev/null`.

## 1. Install the CLI

```sh
curl -fsSL https://raw.githubusercontent.com/SigComply/sigcomply-cli/main/scripts/install.sh | sh
sigcomply version
```

The script installs the latest release into `/usr/local/bin` and runs `sudo` if it can't write
there. To install somewhere else, set `SIGCOMPLY_INSTALL_DIR` for the `sh` that runs the script
(`... | SIGCOMPLY_INSTALL_DIR="$HOME/bin" sh`) and add that folder to your `PATH`. Other options
are in [Install](guides/install.md).

## 2. Create a project with only the manual-evidence source

```sh
mkdir sigcomply-quickstart
cd sigcomply-quickstart
sigcomply init
```

`init` writes `.sigcomply.yaml`, a commented SOC 2 config. Run every command in this tutorial
from this folder: relative paths in the config resolve against the directory you run
`sigcomply` in. Two folders matter here:

- `evidence/`, where you put documents for manual policies. You create it in step 4.
- `.sigcomply/vault/`, the vault, where each run writes its signed evidence and results. The
  CLI creates it on the first run.

The scaffolded config reads three AWS sources. You have no credentials in this tutorial, so open
`.sigcomply.yaml` in an editor and delete these six lines under `sources:`:

```yaml
  aws.iam:
    region: us-east-1
  aws.iam_access_key:
    region: us-east-1
  aws.password_policy:
    region: us-east-1
```

Leave the commented lines (`# aws.acm: ...`) as they are. Without the comments, the `sources:`
block is now:

```yaml
sources:
  manual.pdf:
    backend: local
    path: ./evidence
```

`manual.pdf` reads documents from `./evidence/manual/` (`manual/` is the default prefix inside
that folder). The `vault:` block further down points at `./.sigcomply/vault`.

## 3. Run a check

```sh
sigcomply check
echo $?
```

`echo $?` prints `1`: policies failed. That is expected on a first run. The output starts with a
summary line that names the framework and the run period:

```
SigComply check soc2/2026-Q4 — 133 policies
  pass=0 fail=52 carried=0 skip=81 error=0 na=0 waived=0
```

The period after the `/` (`2026-Q4` here) comes from the current UTC date. Note yours: you need
it in step 5. The numbers depend on the release you installed.

Then comes one line per policy, of two kinds:

- `[fail]` lines for manual policies. SOC 2 ships 52 catalog entries whose evidence is a
  document (a policy, a training record, a review). None is on file yet, so each fails, and
  its `↳` line names the folder to put the document in:

  ```
  [fail] soc2.a1.2.business_continuity_plan — A1.2
      ↳ manual evidence not found; expected files in: file://./evidence/manual/business_continuity_plan/2026/
  ```

- `[skip]` lines for automated policies. They read cloud and SaaS APIs, and no source that could
  feed them is configured. A block near the end lists each skipped policy and the evidence type
  it needs:

  ```
  81 policies were SKIPPED and are NOT counted in the compliance score:
    soc2.a1.2.backup_plan_exists — no configured source emits [backup_plan] (slot "evidence")
    ...
  ```

The last two lines name the run folder in the vault and the command that reads it back:

```
Results written to ./.sigcomply/vault/soc2/2026-Q4/run_20261030T091210Z_7a5555d6
Next: sigcomply report --period 2026-Q4 (add --view integrity to verify the signatures)
```

## 4. Add one document

List every document the framework expects and where it goes:

```sh
sigcomply evidence due --all
```

```
manual evidence: 52 of 52 entries have an empty folder (run period 2026-Q4)
  ENTRY                             CADENCE    PERIOD   DUE IN  UPLOAD TO
  access_review_quarterly           quarterly  2026-Q4  62d     file://./evidence/manual/access_review_quarterly/2026-Q4/
  ...
  business_continuity_plan          annual     2026     62d     file://./evidence/manual/business_continuity_plan/2026/
  ...
```

Each entry has its own period, set by how often it is due. The business continuity plan is
annual, so its folder is the calendar year, not the run period from step 3. Use the year from its
`UPLOAD TO` column in place of `2026` below, and the path of any PDF you have:

```sh
mkdir -p evidence/manual/business_continuity_plan/2026
cp /path/to/any.pdf evidence/manual/business_continuity_plan/2026/
sigcomply check
```

The summary now shows one pass, and the policy's line reads:

```
  pass=1 fail=51 carried=0 skip=81 error=0 na=0 waived=0
  ...
  [pass] soc2.a1.2.business_continuity_plan — A1.2
```

The CLI checked that a supported file is in the folder for the period, merged it into one PDF,
and signed a record of its hash. It did not read the file. Judging what a document says is your
auditor's job. The run still exits `1`, because the other manual policies still fail.

## 5. Verify the evidence

Each run wrote a folder under `.sigcomply/vault/soc2/<period>/`. The second run's folder looks
like this:

```
run_20261030T091226Z_d4db2191/
  manifest.json          # SHA-256 hash of every file in the run, signed
  summary.json           # status of every policy
  policies/
    soc2.a1.2.business_continuity_plan/
      result.json        # the policy result
      envelopes/
        signed_document__manual.pdf_business_continuity_plan.json   # signed record of the file hashes
      attachments/
        business_continuity_plan.pdf                                # your files, merged into one PDF
    ...
```

Check every file of every run in the period. Use your period from step 3 in place of `2026-Q4`:

```sh
sigcomply report --period 2026-Q4 --view integrity
```

```
# sigcomply report — framework=soc2 period=2026-Q4 view=integrity

RUN_PATH                                    STATUS  FILES_OK  DETAIL
soc2/2026-Q4/run_20261030T091210Z_7a5555d6  pass    186/186   -
soc2/2026-Q4/run_20261030T091226Z_d4db2191  pass    187/187   -
```

`report` re-hashes each file, compares it with the run's `manifest.json`, and checks the
manifest's signature.

## 6. Change a file and verify again

Append an empty line to the signed envelope of the policy that passed, in the latest run, then
verify again. Use your period in place of `2026-Q4`:

```sh
RUN=$(ls -d .sigcomply/vault/soc2/*/run_* | tail -1)
echo >> "$RUN/policies/soc2.a1.2.business_continuity_plan/envelopes/signed_document__manual.pdf_business_continuity_plan.json"
sigcomply report --period 2026-Q4 --view integrity
echo $?
```

```
# sigcomply report — framework=soc2 period=2026-Q4 view=integrity

RUN_PATH                                    STATUS  FILES_OK  DETAIL
soc2/2026-Q4/run_20261030T091210Z_7a5555d6  pass    186/186   -
soc2/2026-Q4/run_20261030T091226Z_d4db2191  fail    186/187   hash mismatch: policies/soc2.a1.2.business_continuity_plan/envelopes/signed_document__manual.pdf_business_continuity_plan.json
Error: report: integrity verification failed for 1 of 2 run(s)
```

`echo $?` prints `1`. One changed byte is enough to fail verification.

You can also check one envelope's signature in your browser: drop an envelope, and its merged
PDF from `attachments/`, on the [`/verify` page](https://sigcomply.github.io/sigcomply-evidence-spa/verify).
Nothing is uploaded. [Verify evidence](guides/verify-evidence.md) explains both checks.

Signatures show that a file changed after the run. They don't show who signed it: anyone who can
write to the vault can replace a file and sign it again. For real evidence, use a bucket with
write-once storage. [How SigComply works](how-it-works.md#signing-and-verification) explains why.

## 7. Optional: add an AWS account

To see automated checks, you need AWS credentials with read-only access to one account, for
example a user or role with the AWS-managed `ReadOnlyAccess` policy. Sources only read:
SigComply makes read calls, plus `iam:GenerateCredentialReport`, which asks AWS to build the
account's credential report. The [source reference](reference/sources.md) lists every API action.

Export the credentials in your shell:

```sh
export AWS_ACCESS_KEY_ID=<your-access-key-id>
export AWS_SECRET_ACCESS_KEY=<your-secret-access-key>
```

`AWS_PROFILE`, `AWS_SESSION_TOKEN` and anything else the AWS SDK reads also work. Credentials
never go in `.sigcomply.yaml`.

Put the three AWS sources back under `sources:`:

```yaml
sources:
  aws.iam:
    region: us-east-1
  aws.iam_access_key:
    region: us-east-1
  aws.password_policy:
    region: us-east-1
  manual.pdf:
    backend: local
    path: ./evidence
```

`aws.iam` reads IAM users, `aws.iam_access_key` their access keys, and `aws.password_policy` the
account password policy. To read another AWS service, uncomment its line in the config.

Run `sigcomply check` again. The IAM, access key and password policies now print `[pass]` or
`[fail]` instead of `[skip]`, such as `soc2.cc6.1.mfa_enforced_all_users`. Under a failing
policy, a `↳` line says what failed. If `check` exits `3` with `no usable AWS credentials`, the
variables aren't set in this shell.

## Next steps

- [Run SigComply in CI](getting-started.md): run SigComply on a schedule with a bucket vault,
  and optionally send counts to the SigComply Cloud dashboard.
- [How SigComply works](how-it-works.md): what each run does, what leaves your pipeline, and the
  limits of the signatures.
- [Manual evidence](guides/manual-evidence.md): folder names, file types, upload windows and the
  Evidence SPA form helper.
