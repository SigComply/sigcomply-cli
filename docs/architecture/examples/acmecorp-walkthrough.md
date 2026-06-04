# Worked example — AcmeCorp's SOC 2 setup

This walks through how AcmeCorp uses the SigComply CLI end-to-end. It
reads alongside [`acmecorp.sigcomply.yaml`](acmecorp.sigcomply.yaml)
and assumes familiarity with the
[CI execution model](../09-ci-execution-model.md).

The point: show the architecture working — how a real (if fictional)
project pursues SOC 2 with a mix of automated and manual evidence, a
custom policy, a custom plugin, parameter overrides, exceptions, and
cadence overrides — across a cadence-aligned CI workflow set.

---

## The customer

AcmeCorp:

- Mid-sized SaaS, ~80 employees
- Pursuing SOC 2 Type II
- One AWS account (`acme-prod`) in `us-east-1`
- Code on GitHub Enterprise Cloud (org `acme`); the project is one
  repo: `github.com/acme/infrastructure`
- Okta SSO for all employees
- An internal authorization service (`auth.acme-internal.com`) that
  manages access for the customer-facing app's operators —
  predates the Okta rollout, still in use
- 10–30 contractors at any time, tracked outside Okta
- Some compliance evidence is naturally manual: quarterly access
  reviews, annual security training certificates, contractor reviews

Their nightly + on-push + scheduled CI workflows run the SigComply
CLI, signing evidence into AcmeCorp's own S3 bucket and submitting
aggregated counts to SigComply Cloud.

---

## The setup

After running `sigcomply init-ci --framework soc2 --ci github`,
AcmeCorp's repo looks like this:

```
github.com/acme/infrastructure
├── .sigcomply.yaml                              # see acmecorp.sigcomply.yaml
├── .sigcomply/
│   ├── policies/
│   │   └── acme.custom.cc6.1.contractor_review/
│   │       └── policy.yaml                       # pass_when DSL (the common case)
│   ├── plugins/
│   │   └── acme.internal_iam/
│   │       ├── plugin.yaml
│   │       └── plugin.go
│   └── evidence_types/                           # project-local schemas, if any
└── .github/workflows/
    ├── compliance-on-push.yml      # every PR / push to main
    ├── compliance-daily.yml        # 03:00 UTC daily cron
    ├── compliance-weekly.yml       # Monday 04:00 UTC
    ├── compliance-monthly.yml      # 1st of month 04:00 UTC
    ├── compliance-quarterly.yml    # Jan/Apr/Jul/Oct 1st at 04:00 UTC
    └── compliance-annual.yml       # Jan 1 at 05:00 UTC
```

**The project.** One source-control repo. One framework (`soc2`). One
`.sigcomply.yaml` that declares everything. The repo identity
`acme/infrastructure` is the project identity.

**No `manual_catalog/` directory.** Manual-evidence catalogs are
generated in Go from each framework's `manualSpecs()` and compiled into the
binary — there are no `catalogs/*.yaml` files in the repo. The real
`.sigcomply/` extension directories are `policies/`, `plugins/`, and
`evidence_types/`. A custom manual catalog entry (like AcmeCorp's
`contractor_review_quarterly`) is declared by its project-local custom
policy, not in a standalone catalog file.

**The vault.** `s3://acme-evidence/sigcomply/`, one bucket per
project.

**The manual evidence bucket.** `s3://acme-evidence/manual/`, also
one bucket per project (the `manual.pdf` source is a project-level
singleton).

**Cadence overrides** in `.sigcomply.yaml`:

```yaml
policy_cadences:
  soc2.cc6.1.mfa_enforced: hourly                    # stricter than default daily
  soc2.cc6.1.access_review_quarterly: monthly        # stricter than default quarterly
  soc2.cc1.4.security_training_annual: annual        # explicit
```

These overrides change which CI workflow runs each policy. Because
AcmeCorp set `mfa_enforced` to `hourly`, it now runs in
`compliance-on-push.yml` and `compliance-daily.yml` (catches everything
≥ daily by `on_push: true`). It does NOT run in the hourly cron
unless AcmeCorp also creates a `compliance-hourly.yml` workflow with
the appropriate cron.

---

## Scenario 1 — A push to main, 2026-02-15 13:55 UTC

A developer merges a PR. The `compliance-on-push.yml` workflow fires.

**Inside the job:**

```
sigcomply check --on-push
```

This selects all policies tagged `on_push: true`. By default that's
every automated policy with a cadence ≤ daily. AcmeCorp hasn't
overridden any `on_push` flags, so this is most of the automated
policy set. Manual
policies (quarterly access review, annual training, etc.) have
`on_push: false` by default and are excluded — they have natural
human-driven cadences that don't align with PR feedback.

**The CLI:**

1. Loads config, registers in-binary plugins and policies plus
   AcmeCorp's `acme.internal_iam` plugin and
   `acme.custom.cc6.1.contractor_review` policy.
2. Plans:
   - `run_id`: a fresh UUID
   - `framework`: soc2
   - `period_id`: `2026-Q1` (derived from `commit_time`)
   - the on-push automated policy set in scope (filtered by `on_push`)
3. Collects: per-policy fetches against AWS IAM, AWS S3, AWS
   CloudTrail, Okta, GitHub, AcmeCorp's internal IAM — many of these
   sources are hit multiple times (once per consuming policy, per the
   KISS-no-DRY axiom).
4. Evaluates each policy. Most pass.
5. Persists per-policy envelopes + result.json to the vault.
6. Aggregates → submits to SigComply Cloud.

**Outcome:** every in-scope policy passes. Job exits 0. PR shows green.
Runtime: ~7 minutes.

**Vault contents from this run:**

```
soc2/2026-Q1/run_20260215T135500Z_a3f8b2c1/
   manifest.json                       # period_id=2026-Q1, commit_sha=...
   summary.json
   policies/                            # one folder per in-scope policy
      soc2.cc6.1.mfa_enforced/
         envelopes/
            directory_user__okta.json
            directory_user__acme.internal_iam.json
         result.json
      ...
```

Quarterly and annual policies don't appear in this run's folder —
they're not in scope.

---

## Scenario 2 — Nightly daily cron, 2026-02-16 03:00 UTC

`compliance-daily.yml` fires.

```
sigcomply check --cadence daily
```

This selects all policies with effective cadence `daily` (plus
`hourly` and `continuous`, which are stricter and therefore must also
run at least daily). For AcmeCorp's project:

- All the standard daily automated checks
- `soc2.cc6.1.mfa_enforced` (overridden to `hourly` → also caught
  by `--cadence daily` because hourly is stricter than daily)
- AcmeCorp's custom policy `acme.custom.cc6.1.contractor_review` has
  `cadence: quarterly` (declared in its `policy.yaml`) and is NOT
  included.

Result: similar to Scenario 1's flow, mostly the same evidence
collected. One small difference: a stale credential.

**The catch.** One of AcmeCorp's CI deployment keys hit 60 days of
age overnight. The `soc2.cc6.1.access_key_rotation` policy (which
AcmeCorp set to a stricter `max_age_days: 60`) catches it.

- Policy status: `fail`
- Violation: `AKIA...XYZ exceeds 60-day rotation policy.` (in vault,
  with the AKIA ID stored in the full violation list — never sent to
  the cloud)
- Cloud submission: `resources_evaluated: 14, resources_failed: 1,
  message: "1 of 14 access keys exceed 60-day rotation policy."`

The job exits 1 because `ci.fail_on_violation: true` and
`ci.fail_severity: high` and this is a high-severity policy. CI
shows red. But the vault is fully populated; the cloud submission
went through. The "failure" is a successful report, not a system
failure.

An engineer sees the alert, rotates the key, pushes the fix. The next
`compliance-on-push.yml` run picks up the fix and the policy passes.
The period roll-up (latest-wins) now shows
`soc2.cc6.1.access_key_rotation: pass` for Q1.

---

## Scenario 3 — Quarterly cron, 2026-04-01 04:00 UTC

`compliance-quarterly.yml` fires.

```
sigcomply check --cadence quarterly
```

This selects only quarterly-cadence policies:

- AcmeCorp's custom policy `acme.custom.cc6.1.contractor_review`
- Several SOC 2 manual-evidence policies that AcmeCorp didn't
  override
- (`soc2.cc6.1.access_review_quarterly` is now `monthly` per
  AcmeCorp's override — it runs in the monthly cron, not the
  quarterly one.)

**The catch.** The Q2 2026 contractor review PDF hasn't been uploaded
yet. The compliance manager is in a Tuesday meeting; the cron fired
before she got to it.

**The CLI's output:**

```
[error] Policy acme.custom.cc6.1.contractor_review requires manual evidence.

   Evidence:   contractor_review_quarterly
   Period:     2026-Q2
   Expected:   s3://acme-evidence/manual/contractor_review_quarterly/2026-Q2/

   To remediate:
   1. Generate the contractor review PDF (use the SigComply Evidence SPA
      at https://evidence.sigcomply.com, or your own tooling).
   2. Upload one or more files (PDF, JPEG, PNG, GIF, TIFF, WebP, or BMP)
      to the folder above. Any filename is accepted.
   3. Manually re-run the appropriate compliance workflow
      (Settings → Actions → Re-run workflow).
```

This same message appears in the policy's `result.json` in the
vault and in the violation `reason` field. The cloud submission
includes a counts-only summary: `resources_evaluated: 1,
resources_failed: 1, message: "1 of 1 contractor reviews missing."`

The job exits 1. The compliance manager gets the GitHub Actions
notification, opens the run page, sees the error message with the
exact upload path. She generates the PDF, uploads it. Then she goes
to the workflow page and clicks "Re-run workflow." The CLI runs
again, finds the PDF this time, the policy passes. The period
roll-up updates.

**Note**: AcmeCorp didn't have to wait until July 1 (the next
quarterly cron) for the system to catch the fix. Manual workflow
trigger handles the re-run. The CLI is unaware that this was a "fix"
run vs an originally-scheduled run — both invocations are
self-contained, with no shared state. The vault simply accumulates
another run folder, and the period roll-up uses the latest result.

---

## Scenario 4 — A workflow that doesn't run

The annual policy `soc2.cc1.4.security_training_annual` has cadence
`annual` and runs in `compliance-annual.yml`. AcmeCorp ran it
successfully on 2026-01-08 (the training PDF for 2026 was uploaded
in early January). Now it's late February.

**No daily / quarterly / on-push run touches this policy.** Nothing
triggers it. AcmeCorp's vault has one annual run for 2026 that says
"pass," and the period roll-up reflects that for the entire year.

If the policy had failed in January and never re-ran, the system
would still show "fail" — that's the latest result. The compliance
manager would notice (via dashboard alerting) and re-trigger the
annual workflow with a remediated PDF.

The cadence model is **eventually consistent**: it doesn't try to
prove the system *cannot* drift between cron firings, only that the
cron fires at minimum the declared interval. For continuous
monitoring of high-risk policies, AcmeCorp can override their
cadence to `daily` or `hourly` — which puts them in the more frequent
crons.

---

## What auditors see, six weeks later

AcmeCorp's auditor logs into SigComply Cloud or opens
`s3://acme-evidence/sigcomply/soc2/2026-Q1/` directly. They see:

- The full SOC 2 policy set + AcmeCorp's 1 custom policy
- Per-policy state: each shows the latest result across all runs in
  the period
- Cadence labels next to each: "daily policy, last run 2026-03-30",
  "quarterly policy, last run 2026-02-12"

For `soc2.cc6.1.access_key_rotation` (which eventually `pass` after
remediation): green. Click in and see the timeline of runs — a fail
on 2026-02-16, then a pass on 2026-02-16 after the remediation push.

For `soc2.cc6.1.mfa_enforced` (cadence overridden to `hourly`): the
auditor sees many runs in Q1 (the on-push + daily ones). All
passing except the one that hit the legacy.deploy.bot exception.
They click the exception detail: approved by Jane Doe on 2026-01-15,
expires 2026-09-30. They click "View in repo" → GitHub shows the git
commit that added the exception.

For `acme.custom.cc6.1.contractor_review`: green for Q1 and Q2. They
click the Q2 evidence: a signed envelope confirming the PDF was
present, the SHA-256 hash of the PDF, and a link to the PDF in the
attachments. They download the PDF, verify the hash matches, and
open the PDF in their browser. The PDF is the human-readable signed
review.

For `soc2.cc6.7.waf_in_front_of_web_app`: shown as "N/A" with the
documented justification ("API-only product surface; no public web
app").

**The auditor never logs into anything AcmeCorp doesn't own.** The
vault is in AcmeCorp's S3 bucket. The exceptions are in AcmeCorp's
git history. The PDFs are in AcmeCorp's manual evidence bucket. The
auditor reviews the dashboard for navigation, but the *truth* lives
in AcmeCorp's infrastructure. If AcmeCorp deleted their SigComply
Cloud subscription tomorrow, the audit trail would survive intact in
their own storage.

---

## What changed at AcmeCorp because of this architecture

| Concern | Conventional vendor | SigComply |
|---|---|---|
| Where does evidence live? | Vendor's cloud | AcmeCorp's own S3 |
| What does the dashboard see? | Full evidence including user emails, ARNs | Counts and statuses only |
| Can AcmeCorp verify evidence without the vendor? | No | Yes — open envelope format, public-key verifiable offline |
| Can AcmeCorp customize a policy without forking? | Limited | Yes — `.sigcomply/policies/` |
| Can AcmeCorp use their internal IAM system? | Typically not | Yes — write a project-local plugin |
| Can AcmeCorp swap data sources? | Limited | Yes — bindings re-wire any policy |
| What does the vendor see if breached? | Everything | Counts and policy statuses |
| Is the audit trail in git? | No | Yes — `.sigcomply.yaml`, exceptions, CI workflows, custom code |
| Who decides when checks run? | Vendor's scheduler (cloud-side) | AcmeCorp's CI cron (their infrastructure) |
| Who decides what's "due" this quarter? | Vendor's state machine | AcmeCorp's CI cron schedule + git config |

The architecture makes the operational answer match the marketing
positioning. "Evidence without access" isn't a feature claim; it's a
property of the system that auditors can verify by reading code and
configuration that all live in AcmeCorp's own repo and storage.
