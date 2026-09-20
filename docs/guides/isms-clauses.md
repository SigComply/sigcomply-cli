# ISMS clauses and the Statement of Applicability (ISO 27001)

How to satisfy the 16 management-system requirements of ISO 27001 clauses 4–10, and how to generate the Statement of Applicability a certification auditor asks for first.

> Docs hub: [../README.md](../README.md)

## Why there are 16 more policies than Annex A

Certification is granted against your **information security management system**, not against Annex A. Annex A is the reference set of controls; clauses 4 to 10 are the requirements the organization itself has to meet. A Stage 1 audit is, in practice, a documentation review of those clauses — is the scope written down, is there a risk assessment process, were internal audits conducted, did top management review the ISMS.

Until this release SigComply shipped the 93 Annex A controls and nothing for clauses 4–10. You could pass every check, read a clean coverage report, and fail Stage 1. The ISO 27001 framework now carries both, counted separately and never blended:

- **93 Annex A controls** — the selectable catalog. 26 have an automated check; 67 are manual-only.
- **16 management-system requirements** — clauses 4–10, all manual, all annual.

The design rationale is in [ISMS clauses and the SoA](../architecture/13-isms-clauses-and-soa.md).

## Prerequisites

- An ISO 27001 project: `framework: iso27001` in `.sigcomply.yaml`.
- A configured `sources.manual.pdf` block — one manual-evidence bucket per project. If you have not set one up, do that first: [Manual evidence](manual-evidence.md#step-2--configure-the-manual-evidence-source).

## The 16 requirements

Each row is one control, one policy, and one folder. All 16 are `document_upload` entries on an **annual** cadence.

| Control | Clause | Upload | Catalog entry |
|---|---|---|---|
| `C.4.1-4.2` | 4.1, 4.2 | The ISMS context and interested-parties analysis — the internal and external issues relevant to the ISMS and the requirements of interested parties. | `isms_context` |
| `C.4.3` | 4.3 | The ISMS scope statement, including the boundaries and interfaces it covers and what it excludes. | `isms_scope` |
| `C.5.2` | 5.2 | The information security policy approved by top management. This is the ISMS-level policy of clause 5.2, distinct from the topic-specific policy suite of Annex A 5.1. | `isms_policy` |
| `C.5.3` | 5.3 | The document assigning ISMS responsibilities and authorities, including who reports on ISMS performance to top management. | `isms_roles` |
| `C.6.1.2` | 6.1.2 | The risk assessment methodology — the risk acceptance criteria and the criteria for performing assessments. | `risk_assessment_process` |
| `C.6.1.3` | 6.1.3 | The risk treatment process and the risk treatment plan, with the risk owners' approval and their acceptance of residual risks. | `risk_treatment_process` |
| `C.6.2` | 6.2 | The information security objectives and the plans to achieve them — what, with what resources, by whom, by when, and how results are evaluated. | `isms_objectives` |
| `C.7.2` | 7.2 | Competence evidence for security-relevant roles — role competence requirements plus the qualifications, certifications or training records that meet them. Not the general awareness training of Annex A 6.3. | `competence_records` |
| `C.7.5` | 7.5 | The ISMS document register or document control procedure, showing version control, approval and review of ISMS documentation. | `documented_information` |
| `C.8.1` | 8.1 | Operational planning records showing ISMS processes are carried out as planned, including control of planned changes and of outsourced processes. | `operational_planning` |
| `C.8.2` | 8.2 | The current risk register — the results of the latest risk assessment, with risk owners and evaluated risk levels. | `risk_assessment_results` |
| `C.8.3` | 8.3 | The results of risk treatment — the implementation status of each planned treatment and the residual risk after it. | `risk_treatment_results` |
| `C.9.1` | 9.1 | The ISMS monitoring and measurement results — what is measured, by which method, when, by whom, and the evaluation of the results. | `isms_monitoring` |
| `C.9.2` | 9.2 | The internal audit program and the reports from audits conducted under it, with findings and their resolution. This is your own audit of your ISMS, distinct from the independent review of Annex A 5.35. | `internal_audit` |
| `C.9.3` | 9.3 | Management review minutes covering the clause 9.3.2 inputs, together with the decisions taken. | `management_review` |
| `C.10.2` | 10.2 | The nonconformity and corrective action log — the nature of each nonconformity, the action taken, and the results of that action. | `corrective_action` |

**The Statement of Applicability is not in this list.** Clause 6.1.3 d) requires one, and SigComply generates it — see [Generate the Statement of Applicability](#generate-the-statement-of-applicability). `C.6.1.3` asks for the risk treatment *process and plan*, which the SoA does not replace.

**Three of these are not strictly mandatory documented information** under the 2022 text: `C.4.1-4.2`, `C.5.3` and `C.7.5`. Clauses 4.1/4.2 require the determination to be made rather than documented, 5.3 requires roles to be assigned and communicated, and 7.5 governs how documented information is controlled. They are included because every certification audit asks for them, and flagged here because a list advertised as "the mandatory documents" that quietly exceeds the standard would be an overclaim.

## Where each document goes

The folder scheme is the ordinary manual-evidence one — nothing about these 16 is special:

```
{bucket}/{prefix}/{catalog_entry}/{period_id}/
```

`{period_id}` follows the entry's cadence. All 16 clause entries are annual, so with the config below the ISMS scope statement for 2026 goes to:

```
s3://acme-evidence/manual/isms_scope/2026/
```

One upload covers the year — every run in 2026 reads that same folder, whatever quarter it lands in.

Any number of supported files (PDF, JPEG, PNG, GIF, TIFF, WebP, BMP) may go in the folder; they are converted to PDF where needed and merged into one before evaluation. The CLI checks that supported files are **present**, **valid**, and **uploaded inside the temporal window** (the period plus a 30-day grace). It does not read the document — reviewing what it says is the auditor's job.

The period is the one containing your **HEAD commit's timestamp**, not today's date, so evidence cannot be staged into a future period's folder ahead of time. See [Manual evidence — which period, and by when](manual-evidence.md#which-period-and-by-when).

To see the whole ISO catalog (87 entries, of which these 16 are the clause ones):

```bash
sigcomply evidence catalog -f iso27001 -o text
```

To see which folders are still empty for the current period:

```bash
sigcomply evidence due
```

It lists only genuinely empty folders, names the exact upload URI for each, and always exits 0.

## You cannot exclude a management-system requirement

Applicability is a Statement-of-Applicability concept, and the SoA is about the control catalog. Clauses 4–10 are not on that menu, so declaring one `not_applicable` is a configuration error and the run stops before any collection (exit `3`):

```
project config: controls["C.9.2"]: "C.9.2" is a management-system requirement
of iso27001 (Internal audit) and cannot be declared not_applicable —
certification is granted against the management system, not against a subset
of it
```

The reason it is refused rather than honored: control-level applicability **cascades** to every policy under the control. An accepted exclusion would mark the internal-audit policy `na`, drop it out of the compliance-score denominator, and *raise* your score for declining to have an ISMS.

Marking one `applicable` explicitly is allowed and does nothing. Recording an `approved_by` against one is allowed. Excluding an **Annex A** control is exactly what applicability is for and is unchanged.

## Record your applicability decisions

`controls:` in `.sigcomply.yaml` holds the two halves of what clause 6.1.3 d) asks for per Annex A control:

- `justification` — why the control **is** included. Optional.
- `applicability: not_applicable` + `reason` — why it is **not**. `reason` is required whenever a control is excluded.
- `approved_by` — who signed the decision off. Recommended for both, and it appears in the SoA.

Setting `justification` on an excluded control is a configuration error: an exclusion has a `reason`, and a row the SoA reports as excluded must not also carry an inclusion justification.

```yaml
schema_version: project.v1
framework: iso27001

sources:
  manual.pdf:
    backend: s3
    bucket: acme-evidence
    region: us-east-1
    prefix: manual/

controls:
  # An inclusion the organization reasoned about. This text appears in the
  # SoA verbatim, instead of a derived one.
  A.5.7:
    justification: >-
      Threat intelligence is consumed from the CISA KEV feed and our cloud
      provider's security bulletins; findings are triaged weekly by the
      security engineer on rotation.
    approved_by: ciso@acme.com

  # An exclusion. reason is required; it is what the auditor reads.
  A.7.4:
    applicability: not_applicable
    reason: >-
      Fully remote organization with no offices or datacenters in scope of the
      ISMS; all production infrastructure is AWS-managed.
    approved_by: ciso@acme.com

  # Allowed, and a no-op — a management-system requirement is always
  # applicable. Useful only to record the approver.
  C.9.2:
    approved_by: ciso@acme.com
```

A control you say nothing about is applicable, and its SoA justification is derived (see below).

## Generate the Statement of Applicability

```bash
sigcomply report --period 2026-Q3 --view soa
```

For the spreadsheet an auditor will actually work in:

```bash
sigcomply report --period 2026-Q3 --view soa --format csv --out soa-2026-Q3.csv
```

The view is read-only: it never writes to the vault, never calls the cloud, and never needs OIDC.

### It needs your project config

`--view soa` is the one report view that refuses to run without `.sigcomply.yaml`, because the applicability decisions live only there — there is nothing in the vault to read them from. Without it every control would render as applicable, silently turning a deliberate, approved exclusion into an inclusion on the one document a certification auditor reads first.

So run it from the repo root, or pass `-c <path>`. Passing **both** `--vault` and `--framework` makes the CLI skip the config file, and the SoA then fails with:

```
report: --view soa needs the project config for its applicability decisions —
pass -c <path to .sigcomply.yaml>, or drop --vault/--framework so
.sigcomply.yaml is read
```

### Reading the output

```
93 catalog controls: 92 applicable, 1 excluded

Of the 92 applicable
  71 implemented           — every check that ran passed
  3 partially implemented — some checks passed, some did not
  2 not implemented       — every check that ran failed
  16 not evaluated         — no check ran this period

Note: 16 management-system requirements (clauses 4-10) are outside the Statement
of Applicability and cannot be excluded; see report --view coverage. 88 inclusions
carry a derived justification; set controls.<id>.justification to record the
organization's own reasoning.

CONTROL  NAME                                APPLICABLE  STATUS       ASSURANCE  JUSTIFICATION
A.5.1    Policies for information security   yes         implemented  manual     (derived) Applicable — no exclusion declared. Evidenced by 1 manual evidence item.
A.5.7    Threat intelligence                 yes         implemented  manual     Threat intelligence is consumed from the CISA KEV feed ...
A.7.4    Physical security monitoring        no          excluded     none       Fully remote organization with no offices or datacenters ...
```

| Column | Means |
|---|---|
| `CONTROL` / `NAME` | The catalog control. Only Annex A and any project-local catalog controls appear — never the 16 clause requirements. |
| `APPLICABLE` | `no` only where you declared `applicability: not_applicable`. Everything else is `yes`. |
| `STATUS` | Derived from **this period's** results: `implemented` (every check that ran passed, counting a carried-forward check as the pass it inherits), `partially implemented`, `not implemented`, `not evaluated` (no check ran), or `excluded`. A policy resolved to `na` never ran, so it abstains rather than voting either way — a control with nothing but `na` policies reports `not evaluated`. |
| `ASSURANCE` | `automated` (infrastructure was inspected), `manual` (a document is on file), or `none` (no check implements this control). An implemented control evidenced only by a PDF is a weaker claim, and the SoA does not flatten the two. |
| `JUSTIFICATION` | Your `justification` for an included control, or your `reason` for an excluded one. Prefixed `(derived)` where SigComply wrote it rather than you. |

CSV carries the same rows plus `justification_derived`, `evaluated`, `policies` and `approved_by`.

**A waiver and an N/A are not the same claim here.** `state: waived` says "this control applies to us and we are knowingly accepting the gap", so it counts toward `implemented` — the reason and expiry are on the row for the auditor to weigh. `state: na` says "no check ran", so it counts toward nothing and the control falls back to whatever its other policies showed, or to `not evaluated`. If you want a control to read as addressed, waive it and say why; declaring it N/A will not manufacture a pass.

Two things the statuses deliberately do not do. **`not evaluated` is not a pass** — an annual control writes no result in three quarters out of four, so a Q2 SoA will legitimately show many of them; generate the SoA from a period in which the annual cadence ran if you want those rows filled in. And **a derived justification is not your reasoning** — it is accurate ("Verified by 3 automated checks") and says nothing about why *your* organization kept the control. Fill in `controls.<id>.justification` for anything you actually deliberated over; the note counts how many are still derived.

### Where the 16 show up instead

They are counted in the SoA note and reported in full by the coverage view, which now carries a `KIND` column and its own counters:

```bash
sigcomply report --period 2026-Q3 --view coverage
```

```
93 of 93 catalog controls have a check
  26 automated  — verified by inspecting your infrastructure
  67 manual     — satisfied by a document being on file

16 management-system requirements (counted apart — they are not selectable)
  4 with evidence on file this period, 12 without
```

The two totals are never added together. "93 Annex A controls and 16 management-system requirements" is the honest form; "109 controls" is not, because it would make the headline improve on the day the gap was discovered.

## Migrating an existing ISO 27001 project

**Expect 16 new failing policies on your next annual run.** They are annual-cadence manual policies whose folders are empty, so until the documents are uploaded:

- `sigcomply check --cadence annual` reports them as failures and exits `1`.
- Your compliance score drops — 16 policies move into the denominator and none of them pass. This is a correction to a score that was previously computed over an incomplete universe, not a regression in your posture.
- The SigComply Cloud dashboard shows the same drop, for the same reason.

Nothing else changes: no config key is required, no existing control's behavior moves, and the daily and quarterly workflows are unaffected (all 16 are annual).

To work through it:

1. Run `sigcomply evidence due`. It lists every clause folder still empty for the current period and prints the exact upload URI for each. It always exits 0, so you can read it without a red build.
2. Upload what you already have. Most organizations pursuing ISO 27001 already hold a scope statement, a risk register and a policy — those three close `C.4.3`, `C.8.2` and `C.5.2` immediately.
3. For what you do not have, the failing policy's remediation text names the document. Producing it is ISMS work, not tool work; the CLI can only tell you it is missing.
4. Once the folders are filled, re-run `sigcomply check --cadence annual`, then `sigcomply report --view soa` for the Stage 1 deliverable.

If you want the failures off your build while you work through the backlog, waive them the same way as any other policy — with a `reason` and an `expires_at` — rather than excluding the control, which is refused:

```yaml
policies:
  iso27001.clause.9.2.internal_audit:
    exceptions:
      - state: waived
        reason: "First internal audit scheduled for 2026-11; ISMS-14."
        approved_by: ciso@acme.com
        expires_at: 2026-12-31
```

A waiver is visible in git, dated, and expires. It is honest about the gap in a way an exclusion would not be.

## Troubleshooting

**`controls["C.9.2"]: ... cannot be declared not_applicable` (exit `3`).** You excluded a management-system requirement. Remove the `applicability` key; waive the policy instead if you need the build green.

**`controls["A.7.4"]: justification records why a control is included; use reason for an exclusion` (exit `3`).** The control has both `applicability: not_applicable` and `justification`. Keep the `reason`, drop the `justification`.

**`report: --view soa needs the project config ...`.** You passed both `--vault` and `--framework`, so the config file was not read. Drop one of them, or pass `-c .sigcomply.yaml`.

**`report: the soa view needs the framework's control catalog; none was supplied`.** The framework could not be resolved. Check `framework:` in the config, or pass `-f iso27001`.

**Every clause row says `not evaluated` in the SoA.** The clause policies are annual; if the annual cadence has not run in this period there are no results to report. The 16 do not appear as SoA rows at all — check `--view coverage` for their status.

**A clause policy fails with "expected files" after you uploaded.** Check the folder is `{prefix}/{catalog_entry}/{period_id}/` with the catalog entry from the table above (`isms_scope`, not `C.4.3`), and that the upload timestamp falls inside the period. See [Troubleshooting — manual evidence](troubleshooting.md#manual-evidence-expected-files).

## See also

- [Manual evidence](manual-evidence.md) — the flow these 16 policies use, unchanged.
- [ISMS clauses and the SoA](../architecture/13-isms-clauses-and-soa.md) — why the two kinds of control exist and how the SoA is assembled.
- [Project config — the controls section](../architecture/08-project-config.md#the-controls-section) — applicability, the cascade, and precedence over policy-level exceptions.
- [Frameworks](../reference/frameworks.md) — the full ISO 27001 control and policy inventory.
- [Configuration reference](../configuration.md) — every `.sigcomply.yaml` key.
- [Docs hub](../README.md)
