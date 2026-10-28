# Collect ISMS clause evidence and generate the Statement of Applicability

Upload the documents for the 16 management-system requirements of ISO 27001 clauses 4 to 10, and
generate the Statement of Applicability (SoA) for your auditor.

The ISO 27001 framework holds two separate sets of controls, counted apart:

- **93 Annex A controls** — the selectable catalog. 26 have an automated check; 67 are manual-only.
- **16 management-system requirements** (clauses 4 to 10): all manual, all annual, and not
  selectable. Their control IDs start with `C.`.

## Prerequisites

- An ISO 27001 project: `framework: iso27001` in `.sigcomply.yaml`.
- A configured manual evidence source ([Upload manual evidence](manual-evidence.md#1-configure-the-manual-evidence-source)).

## 1. Upload the clause documents

Each requirement is one policy and one folder. All 16 are annual `document_upload` entries.

| Control | Policy | Upload | Catalog entry |
|---|---|---|---|
| `C.4.1-4.2` | `iso27001.clause.4.1.isms_context` | The internal and external issues relevant to the ISMS, and the requirements of interested parties. | `isms_context` |
| `C.4.3` | `iso27001.clause.4.3.isms_scope` | The ISMS scope statement, with its boundaries, interfaces and exclusions. | `isms_scope` |
| `C.5.2` | `iso27001.clause.5.2.isms_policy` | The information security policy approved by top management (the clause 5.2 policy, not the Annex A 5.1 topic policies). | `isms_policy` |
| `C.5.3` | `iso27001.clause.5.3.isms_roles` | The assignment of ISMS responsibilities and authorities. | `isms_roles` |
| `C.6.1.2` | `iso27001.clause.6.1.2.risk_assessment_process` | The risk assessment method: risk acceptance criteria and assessment criteria. | `risk_assessment_process` |
| `C.6.1.3` | `iso27001.clause.6.1.3.risk_treatment_process` | The risk treatment process and plan, with risk owners' approval of residual risks. | `risk_treatment_process` |
| `C.6.2` | `iso27001.clause.6.2.isms_objectives` | The security objectives and the plans to achieve them. | `isms_objectives` |
| `C.7.2` | `iso27001.clause.7.2.competence_records` | Competence requirements for security roles and the records that meet them (not the Annex A 6.3 awareness training). | `competence_records` |
| `C.7.5` | `iso27001.clause.7.5.documented_information` | The ISMS document register or document control procedure. | `documented_information` |
| `C.8.1` | `iso27001.clause.8.1.operational_planning` | Records that ISMS processes run as planned, including planned changes and outsourced processes. | `operational_planning` |
| `C.8.2` | `iso27001.clause.8.2.risk_assessment_results` | The current risk register. | `risk_assessment_results` |
| `C.8.3` | `iso27001.clause.8.3.risk_treatment_results` | The status of each planned treatment and the residual risk. | `risk_treatment_results` |
| `C.9.1` | `iso27001.clause.9.1.isms_monitoring` | Monitoring and measurement results and their evaluation. | `isms_monitoring` |
| `C.9.2` | `iso27001.clause.9.2.internal_audit` | The internal audit program and its reports (not the Annex A 5.35 independent review). | `internal_audit` |
| `C.9.3` | `iso27001.clause.9.3.management_review` | Management review minutes and decisions. | `management_review` |
| `C.10.2` | `iso27001.clause.10.2.corrective_action` | The nonconformity and corrective action log. | `corrective_action` |

`C.4.1-4.2`, `C.5.3` and `C.7.5` are not strictly mandatory documented information in the 2022
text, but certification audits ask for them.

The folder is `{prefix}{catalog entry}/{year}/`, for example `manual/isms_scope/2026/`. One
upload covers every run in that year. The upload must fall inside the year plus a 30-day grace
period, and you can't upload ahead into a future year. Folder and file rules:
[Upload manual evidence](manual-evidence.md#3-upload-the-files).

To see the whole ISO catalog (87 entries, of which these 16 are the clause ones):

```bash
sigcomply evidence catalog -f iso27001 -o text
```

To list the empty folders with their upload paths:

```bash
sigcomply evidence due --all
```

Until you upload, each clause policy fails on every scheduled run (`sigcomply check --scheduled`
exits `1`). To keep the build green while you work through them, waive the policy with a reason
and an expiry date:

```yaml
policies:
  iso27001.clause.9.2.internal_audit:
    exceptions:
      - state: waived
        reason: "First internal audit scheduled for 2026-11; ISMS-14."
        approved_by: ciso@acme.com
        expires_at: 2026-12-31
```

You can't exclude a clause requirement. Declaring one `not_applicable` stops the run with exit
code `3`:

```text
Error: plan: project config: controls["C.9.2"]: "C.9.2" is a management-system requirement of iso27001 (Internal audit) and cannot be declared not_applicable — certification is granted against the management system, not against a subset of it
```

## 2. Record your applicability decisions

Under `controls:`, record per Annex A control why it is included or why it is excluded:

```yaml
controls:
  # Included, with your own reasoning. The SoA prints this text.
  A.5.7:
    justification: >-
      Threat intelligence is consumed from the CISA KEV feed and our cloud
      provider's security bulletins; findings are triaged weekly by the
      security engineer on rotation.
    approved_by: ciso@acme.com

  # Excluded. reason is required.
  A.7.4:
    applicability: not_applicable
    reason: >-
      Fully remote organization with no offices or datacenters in scope of the
      ISMS; all production infrastructure is AWS-managed.
    approved_by: ciso@acme.com
```

- `justification` is optional and only valid on an included control.
- `applicability: not_applicable` needs a `reason`, and applies `na` to every policy under the
  control, except a policy that also backs a control still in scope.
- `approved_by` is recommended for both and appears in the SoA.
- A control you don't list is applicable, with a justification the CLI derives from its checks.

Setting both `justification` and `not_applicable` on a control fails with
`justification records why a control is included; use reason for an exclusion` (exit `3`).

## 3. Generate the SoA

Run from the repository root, after a scheduled run:

```bash
sigcomply report --period 2026-Q4 --view soa
```

For the spreadsheet:

```bash
sigcomply report --period 2026-Q4 --view soa --format csv --out soa-2026-Q4.csv
```

The SoA reads your applicability decisions from `.sigcomply.yaml`. If you pass both `--vault`
and `--framework`, the CLI skips the config file and stops with `report: --view soa needs the
project config for its applicability decisions` (exit `3`). Drop one of them, or pass
`-c .sigcomply.yaml`.

## Verify

The SoA starts with a summary, then one row per Annex A control:

```text
93 catalog controls: 92 applicable, 1 excluded

Of the 92 applicable
   0 implemented           — every check that ran passed
   0 partially implemented — some checks passed, some did not
  67 not implemented       — no check that ran passed: each failed, errored or was skipped
  25 not evaluated         — no check ran this period

CONTROL  NAME                                APPLICABLE  STATUS           ASSURANCE  JUSTIFICATION
A.5.1    Policies for information security   yes         not implemented  manual     (derived) Applicable — no exclusion declared. Evidenced by 1 manual evidence item.
```

| Column | Meaning |
|---|---|
| `APPLICABLE` | `no` only where you declared `not_applicable`. |
| `STATUS` | From this period's results: `implemented`, `partially implemented`, `not implemented`, `not evaluated` (no check ran) or `excluded`. A waived policy counts as passed; an `na` policy counts for nothing. A skipped policy counts as not passed, so a control whose checks were all skipped (no source configured) reads `not implemented`. |
| `ASSURANCE` | `automated` (an automated check is mapped to the control; `STATUS` says whether it ran), `manual` (only document checks are mapped; a document's contents are never checked) or `none`. |
| `JUSTIFICATION` | Your `justification` or `reason`, or a derived text marked `(derived)`. |

The CSV adds `justification_derived`, `evaluated`, `policies`, `approved_by` and `risks`.

`not evaluated` is not a pass. Generate the SoA for a period that has at least one scheduled
run.

The 16 clause requirements are not SoA rows. Check them with the coverage view:

```bash
sigcomply report --period 2026-Q4 --view coverage
```

```text
93 of 93 catalog controls have a check
  26 automated  — an automated check is mapped; "This period" shows whether it ran
  67 manual     — only document checks are mapped; their contents are not inspected

16 management-system requirements (counted apart — they are not selectable)
  0 with evidence on file this period, 16 without
```

## Next steps

- [Upload manual evidence](manual-evidence.md).
- [Verify evidence](verify-evidence.md).
- [Frameworks reference](../reference/frameworks.md).
