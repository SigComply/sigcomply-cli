# Frameworks

The compliance frameworks the CLI ships, their counts, and the commands that list their
contents.

## Shipped frameworks

| ID | Standard | Coverage |
|---|---|---|
| `soc2` | SOC 2, 2017 Trust Services Criteria. The default. | 43 / 43 criteria have a check — 16 automated, 27 manual-only. 139 policies: 89 automated + 50 manual catalog entries. |
| `iso27001` | ISO/IEC 27001:2022 | 109 controls: 93 Annex A + 16 management-system. 93 / 93 Annex A controls have a check — 26 automated, 67 manual-only. 151 policies: 64 automated + 87 manual catalog entries. The 16 management-system requirements (clauses 4-10), all manual, are counted apart from Annex A and are covered only once you upload the documents. |

A control counts as automated when at least one automated policy stands behind it, and as
manual-only when only document uploads do. An automated check shows a control's configured
state, not that it was exercised: a backup that is enabled is not a restore that was tested.
Where a control needs both, the tested half is a separate manual entry, for example
`soc2.a1.3.recovery_procedures_tested` and `iso27001.5.30.ict_continuity_tested`.
`sigcomply report --view coverage` shows which kind of check backs each control, and how many
automated controls were inspected or only skipped in the period.

No other framework is registered. Any other value of `framework:` is a
configuration error (exit `3`).

## Selecting a framework

Set the framework in `.sigcomply.yaml` with the singular key `framework:`:

```yaml
framework: soc2
```

One project (one repository, one config, one vault) holds one framework. For SOC 2 and ISO
27001, use two repositories. `check` reads the framework only from the config; the commands that
take a `--framework` flag are listed in
[Commands](commands.md#framework-resolution).

`init-ci` scaffolds SOC 2 only. The workflows don't name a framework, so an ISO 27001 project can
use them; see [Commands](commands.md#sigcomply-init-ci).

## Evidence modes

Each policy has one `evidence_mode`:

| `evidence_mode` | Evidence | Evaluation |
|---|---|---|
| `automated` | Records from API sources (AWS, GCP, Azure, GitHub, GitLab, Okta, Active Directory), checked against an evidence-type schema | The policy's `pass_when` condition |
| `manual` | Files uploaded to the policy's folder in the `manual.pdf` storage | A supported file is present, is a valid PDF after merging, and was uploaded within the entry's period plus grace |

Each policy maps to one or more controls: SOC 2 criteria, or ISO 27001 Annex A controls and
clause 4-10 requirements. [Concepts](../concepts.md#the-two-evidence-flows) explains both
modes.

## ISO 27001 control IDs

| Prefix | What it is | Count | Can be declared not applicable | In the Statement of Applicability |
|---|---|---|---|---|
| `A.` | Annex A controls, for example `A.5.1`, `A.8.5` | 93 | Yes, with a `reason` | Yes, included or excluded |
| `C.` | Clause 4-10 management-system requirements, for example `C.4.3`, `C.9.2` | 16 | No (exit `3`) | No |

The prefix exists because the numbering overlaps: clause 5.2 and Annex A 5.2 are different
requirements, so they are `C.5.2` and `A.5.2`. All 16 `C.` requirements are annual document
uploads. [ISMS clauses and the SoA](../guides/isms-clauses.md) explains how to satisfy them and
generate the Statement of Applicability.

## Inspecting a framework

List the manual-evidence entries:

```sh
sigcomply evidence catalog -f soc2
sigcomply evidence catalog -f soc2 -o json
```

Text output shows the ID, control, type, frequency and name of each entry. JSON adds the
description, severity, temporal rule, grace period and `tsc` (the SOC 2 criterion).

The automated policies are Go code under `internal/frameworks/<framework>/` in this repository,
for example `internal/frameworks/soc2/`. Each policy carries its `pass_when` condition, so the
logic behind every check is readable.

## See also

- [Commands](commands.md): `check`, `report` and `evidence catalog`.
- [Configuration](../configuration.md): per-policy and per-control settings.
