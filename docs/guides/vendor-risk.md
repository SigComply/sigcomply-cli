# Collect evidence per vendor

Declare your third-party register in `.sigcomply.yaml` so the vendor entries of SOC 2 (CC9.2)
and ISO 27001 (A.5.19, A.5.20) get one evidence folder per vendor, each checked on its own.

Without a register these entries are ordinary single-folder manual entries. With one, an auditor
sampling a single vendor can see that vendor's own documents, and `evidence due` names the vendor
whose folder is empty.

## Prerequisites

- A configured manual evidence source ([Upload manual evidence](manual-evidence.md)).
- Your list of vendors, with a tier for each.

## 1. Declare the register

Add an `experimental.vendors` block:

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
| `id` | yes | 1 to 40 characters of `a-z`, `0-9`, `_` and `-`, starting with a letter or digit. It names the vendor's folders, so changing it moves their evidence. |
| `name` | yes | Shown in `evidence due`, in failure messages and in the signed record. |
| `tier` | yes | `critical`, `high`, `moderate` or `low`. |
| `subservice` | no | `true` for a subservice organization (one that performs part of your service). Adds a CUEC mapping folder for the vendor. |
| `services` | no | Free text. Not evaluated. |
| `assurance_period_end` | no | The last day the vendor's own report covers. See step 3. |
| `providers` | no | Configured source IDs or providers this vendor supplies, for example `[github]` or `[aws.iam]`. |
| `tier_rationale` | for `low` | Why the vendor is low tier. |
| `approved_by` | for `low` | Who approved the low tier. |

What each tier owes:

| Tier | Evidence |
|---|---|
| `critical`, `high` | Independent assurance: a SOC 2 Type II report, an ISO 27001 certificate or a penetration-test report. |
| `moderate` | A lighter document: a completed security questionnaire, a trust-page snapshot or a DPA. |
| `low` | No upload. The config does not load without `tier_rationale` and `approved_by`, and both appear in the signed record. |

All keys: [configuration reference](../configuration.md).

## 2. Upload each vendor's documents

These entries fan out over the register:

| Framework | Entry | Control | One folder per |
|---|---|---|---|
| SOC 2 | `vendor_assurance` | CC9.2 | vendor |
| SOC 2 | `vendor_contracts_reviewed` | CC9.2 | vendor |
| SOC 2 | `cuec_mapping` | CC9.2 | vendor with `subservice: true` |
| ISO 27001 | `supplier_assurance` | A.5.19 | supplier |
| ISO 27001 | `supplier_security_agreements` | A.5.20 | supplier |

The lifecycle entries (`vendor_lifecycle_process` for SOC 2, `supplier_lifecycle_process` for ISO
27001) and SOC 2's `vendor_risk_assessment` (CC9.1) keep a single folder.

A fan-out folder is the entry ID, a dot and the vendor ID:

```text
{prefix}vendor_assurance.acme_cloud/{period}/
{prefix}cuec_mapping.acme_cloud/{period}/
```

All these entries are annual, so `{period}` is the year. Get the exact paths from:

```bash
sigcomply evidence due --all
```

```text
  cuec_mapping [Acme Cloud Platform]               annual     2026     66d     file://./evidence/manual/cuec_mapping.acme_cloud/2026/
  vendor_assurance [Acme Cloud Platform]           annual     2026     66d     file://./evidence/manual/vendor_assurance.acme_cloud/2026/
  vendor_assurance [Initech Payments]              annual     2026     66d     file://./evidence/manual/vendor_assurance.initech_pay/2026/
  vendor_contracts_reviewed [Acme Cloud Platform]  annual     2026     66d     file://./evidence/manual/vendor_contracts_reviewed.acme_cloud/2026/
  vendor_contracts_reviewed [Initech Payments]     annual     2026     66d     file://./evidence/manual/vendor_contracts_reviewed.initech_pay/2026/
```

A `low` vendor has no folders and never appears here. File rules are the same as for any manual
entry ([Upload manual evidence](manual-evidence.md#3-upload-the-files)).

## 3. Declare how current each report is

An upload date says when you filed a report, not what period it covers. Set
`assurance_period_end` to the last day the vendor's report covers. The CLI fails the vendor once
that date is more than 15 months (450 days) before the audit period starts. It does not read the
date from the PDF; the value is your declaration. Leave it out and the CLI skips this check for
that vendor.

## 4. Run the check

```bash
sigcomply check --cadence annual
```

## Verify

Each fan-out policy reports the vendors that failed, by name:

```text
  [fail] soc2.cc9.2.vendor_assurance — CC9.2
      ↳ Initech Payments (initech_pay): evidence failed validation: [assurance_out_of_date (declared coverage ended 2024-06-30, more than 15 months before the period began)]
  [fail] soc2.cc9.2.vendor_contracts_reviewed — CC9.2
      ↳ 2 of 3 resources failed, e.g. Acme Cloud Platform (acme_cloud): no evidence found; expected files in: file://./evidence/manual/vendor_contracts_reviewed.acme_cloud/2026/
```

At plan time, the CLI warns about each configured source that no register entry claims
(`... is configured but no register entry claims it ...`). Add the vendor, or add the source to an
existing entry's `providers:`. The warning never fails the run.

## Limits

The CLI checks that each declared vendor has a document on file in the period, and that the
coverage date you declared is recent enough. It does not read the vendor's report, check the
auditor's opinion, check that the report's scope covers the services you use, or know about
vendors you left out of the register. Your auditor reviews those.

## Next steps

- [Upload manual evidence](manual-evidence.md).
- [Verify evidence](verify-evidence.md).
