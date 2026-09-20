# Vendor and third-party risk

How to declare your third-party register and collect assurance evidence for each vendor separately, for SOC 2 CC9.1/CC9.2 and ISO 27001 A.5.19–A.5.23.

> Docs hub: [../README.md](../README.md)

## The problem this solves

Before this release, vendor risk was three folders: one for the vendor risk assessment, one for the due-diligence process, one for reviewed contracts — all of them flat. That is a reasonable shape for "do you have a process" and a useless shape for "is it operating".

A company with three infrastructure providers and twelve SaaS vendors had **one place to put one PDF**. There was no way to say that eleven vendors are current and one has not sent a report in two years — and that is precisely what an auditor samples. **One entry was not N vendors.**

Now the register lives in `.sigcomply.yaml`, and two catalog entries fan out over it: one evidence folder per vendor, checked independently every run.

## Declare the register

Add an `experimental.vendors` block. It is the inventory CC9.2 asks you to maintain, kept as reviewable configuration rather than as a document nobody can diff:

```yaml
experimental:
  vendors:
    declared_by: ciso@acme.example
    declared_at: "2026-09-19"
    register:
      - id: acme_cloud
        name: Acme Cloud Platform
        tier: critical
        subservice: true
        services: Production hosting and object storage
        assurance_period_end: "2026-03-31"

      - id: initech_pay
        name: Initech Payments
        tier: high
        services: Card processing
        assurance_period_end: "2026-06-30"

      - id: zeta_news
        name: Zeta Newsletter
        tier: low
        tier_rationale: Marketing email only; no customer or employee data.
        approved_by: ciso@acme.example
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Stable slug, 1–40 chars of `[a-z0-9_-]`. Names this vendor's evidence folder, so changing it re-files their evidence. |
| `name` | yes | How a human refers to the vendor. Appears in `evidence due` and in the signed record. |
| `tier` | yes | `critical`, `high`, `moderate` or `low`. See below — it is mechanical, not a label. |
| `subservice` | no | True for a **subservice organization**: one that performs part of your service, not merely supplies you. Drives the CUEC mapping entry and matters for the carve-out vs inclusive method in your own report. |
| `services` | no | Free text. Advisory, never evaluated. |
| `assurance_period_end` | no | The last day the vendor's own report actually covers. See [Freshness](#freshness-the-most-common-cc92-finding). |
| `tier_rationale` | for `low` | Why this vendor sits at this tier. |
| `approved_by` | for `low` | Who signed that off. |

It lives under `experimental:` for the same reason `experimental.scope` does — the config loader is strict, so a brand-new top-level key would hard-fail every older pinned CLI. See [Config evolution](../architecture/08-project-config.md#config-evolution-policy).

## What each tier owes

Tier changes **which artifact** a vendor owes. It never changes **whether** one is owed.

| Tier | Owes |
|---|---|
| `critical`, `high` | Independent assurance: a SOC 2 Type II, an ISO 27001 certificate, or a penetration-test report. |
| `moderate` | A lighter artifact — a completed security questionnaire, a trust-page snapshot, or a DPA. |
| `low` | No upload, but a written `tier_rationale` and an `approved_by`. The config will not load without both. |

That last row is deliberate and worth understanding. An earlier design let the lower tiers carry no obligation at all — and that would have reproduced the worst failure mode this product has: an operator-chosen value that silently deletes a requirement, leaves the compliance score untouched, and so makes **under-declaring your estate raise your score**. It is the same defect as declaring an ISO clause not applicable, which the planner refuses outright.

So `low` is not an absence. It is an approved exemption, it carries a justification and a name, and it appears in the signed evidence record where an auditor reads it. Tiering everything `low` does not produce a quiet green — it produces a register full of exemptions somebody has to defend.

## Where the evidence goes

A fan-out entry has no folder of its own. Each vendor gets one:

```
{bucket}/{prefix}/vendor_assurance.acme_cloud/{period_id}/
{bucket}/{prefix}/vendor_assurance.initech_pay/{period_id}/
{bucket}/{prefix}/cuec_mapping.acme_cloud/{period_id}/
```

Any number of files may go in each folder; images are converted to PDF and everything is merged, exactly as for any other manual entry ([Manual evidence](manual-evidence.md)).

`sigcomply evidence due` names each vendor individually, so you are told which vendor is missing rather than that one of them is:

```
manual evidence: 3 of 50 entries have an empty folder (run period 2026-Q3)
  ENTRY                                   CADENCE  PERIOD  DUE IN  UPLOAD TO
  cuec_mapping [Acme Cloud Platform]      annual   2026    102d    s3://acme-eu/manual/cuec_mapping.acme_cloud/2026/
  vendor_assurance [Acme Cloud Platform]  annual   2026    102d    s3://acme-eu/manual/vendor_assurance.acme_cloud/2026/
  vendor_assurance [Initech Payments]     annual   2026    102d    s3://acme-eu/manual/vendor_assurance.initech_pay/2026/
```

Both entries are annual, so `{period_id}` is the year — one upload per
vendor per year, read by every run in that year.

A `low`-tier vendor never appears here. It owes no artifact, so it has no deadline.

## Freshness: the most common CC9.2 finding

A stale assurance report is the single most common CC9.2 finding, and it is invisible to a presence check. The temporal window proves **when you uploaded the file**, not what the file covers — so a FY2023 SOC 2 report uploaded this morning passes, and would go on passing every year forever.

`assurance_period_end` closes that. Declare the last day the vendor's report actually covers, and the check fails once that date is more than **15 months** before the audit period begins (twelve months of a Type II, plus the bridge-letter gap auditors accept):

```
[fail] soc2.cc9.2.vendor_assurance — CC9.2
  initech_pay: Initech Payments (initech_pay): evidence failed validation:
    [assurance_out_of_date (declared coverage ended 2019-12-31, more than 15 months before the period began)]
```

**This date is declared, never parsed.** SigComply does not open the PDF and does not claim to — see [what this does not do](#what-this-does-not-do). What it gives an auditor is an assertion recorded in version control and re-checked on every run. Leave the field out and the freshness check simply does not run for that vendor.

## The entries

| Framework | Catalog entry | Control | Fans out over |
|---|---|---|---|
| SOC 2 | `vendor_assurance` | CC9.2 | every vendor in the register |
| SOC 2 | `vendor_contracts_reviewed` | CC9.2 | every vendor in the register |
| SOC 2 | `cuec_mapping` | CC9.2 | vendors with `subservice: true` |
| SOC 2 | `vendor_lifecycle_process` | CC9.2 | — (one folder) |
| ISO 27001 | `supplier_assurance` | A.5.19 | every supplier in the register |
| ISO 27001 | `supplier_security_agreements` | A.5.20 | every supplier in the register |
| ISO 27001 | `supplier_lifecycle_process` | A.5.19 | — (one folder) |

**Contracts and agreements fan out** for the same reason assurance reports do: each vendor has its own contract, and an auditor samples them per vendor. A single consolidated PDF cannot show that the one vendor they asked about is covered.

**The lifecycle entries deliberately do not fan out.** The artifact is the documented procedure — how a third party is onboarded and, critically, how its access and data are removed when the relationship ends — plus the period's onboarding and termination records. It *cannot* fan out over the register, because a terminated vendor is by definition one you delete from the register: a per-member folder set can never hold evidence for the relationship that actually ended.

**CUEC mapping** is the complementary user entity controls listed in a subservice organization's own report — the controls *their* report assumes *you* operate. It fans out over subservice organizations because AWS's CUECs are not GCP's. Note these are CUECs, not **CSOCs** (complementary subservice organization controls, which are what you expect of them); the two get conflated constantly and auditors ask about them separately.

ISO says "supplier" where SOC 2 says "vendor", so the entries are named accordingly. `supplier_assurance` sits under **A.5.19** (information security in supplier relationships) rather than A.5.22, which already has `supplier_service_monitoring` and asks a different question: ongoing service-delivery review, not the standing assurance the relationship rests on.

## Without a register

Every one of these entries works with no `experimental.vendors` block at all — they behave as ordinary single-folder manual entries at `{prefix}/vendor_assurance/{period_id}/`. Declaring the register is what turns one folder into one per vendor. Nothing about an existing project changes until you add it.

## What this does not do

Consistent with every manual entry, SigComply checks that a document is **on file**, not what it says:

- It does **not** read the vendor's report, extract text, or parse a date out of it. `assurance_period_end` is your declaration.
- It does **not** check the auditor's opinion is unqualified.
- It does **not** check the report's scope covers the services you actually consume, or that the report is for the right entity.
- It does **not** fully verify your register is complete. Nothing can compare it against the vendors you *really* use — that set exists only in your head and your invoices. What it does do is check the register against the one baseline it can observe: every source in your `sources:` block is itself a third party, so a configured source no register entry claims is warned about at plan time (`vendors: source "github" is configured but no register entry claims it`). Tag an entry with the sources it supplies to satisfy the check:

  ```yaml
  register:
    - id: github
      name: GitHub
      tier: high
      providers: [github]          # or a full source ID, e.g. aws.iam
  ```

  The warning is advisory and never fails a run — whether a source belongs in your third-party register is your call, and a vendor that supplies no configured source (a payroll processor, a law firm) simply leaves `providers:` empty.

Three of the five most common CC9.2 findings live in that list. The check is real and it is narrow: *each vendor you declared has a current document on file, and you have said what period it covers.* Read the documents.

## See also

- [Manual evidence](manual-evidence.md) — the folder scheme, supported formats, temporal window
- [Configuration reference](../configuration.md#experimentalvendors--declaring-the-third-party-register)
- [Project config architecture](../architecture/08-project-config.md)
