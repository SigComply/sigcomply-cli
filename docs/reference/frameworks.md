# Frameworks

Reference for the compliance frameworks the CLI ships and how their policies map to controls.

Back to the [documentation hub](../README.md).

## Shipped frameworks

| ID | Standard | Status | Coverage |
|---|---|---|---|
| `soc2` | SOC 2 — 2017 Trust Services Criteria | Production-ready, **default** | 43 / 43 criteria have a check — 16 automated, 27 manual-only. 137 policies: 88 automated + 49 manual catalog entries. |
| `iso27001` | ISO/IEC 27001:2022 | Shipped | 109 controls: 93 Annex A + 16 management-system. 93 / 93 Annex A controls have a check — 26 automated, 67 manual-only. 150 policies: 64 automated + 86 manual catalog entries. The 16 management-system requirements (clauses 4-10), all manual, are counted apart from Annex A and are covered only once you upload the documents. |

Select a framework in `.sigcomply.yaml` with the singular key `framework:` (never `frameworks:`):

```yaml
framework: soc2
```

`init` and `evidence catalog` also accept `-f/--framework`; `check` reads the framework from config only.

### `init-ci` is SOC 2 only in v1-alpha

`init-ci` does not yet ship ISO 27001 cadence templates. Running it for any framework other than `soc2` exits `3` (`framework %q not supported in v1-alpha`). See [Commands](commands.md#sigcomply-init-ci).

## HIPAA is not available

HIPAA is **not** a registered framework — there is no package, no policies, and no `hipaa` entry in the framework registry. Selecting `hipaa` (or any other unregistered name) fails identically at runtime.

## How policies map to controls

Each framework is a set of policies, and every policy declares an `evidence_mode` — the flow it consumes:

| `evidence_mode` | Source of evidence | How it is evaluated |
|---|---|---|
| `automated` | API source plugins (AWS, GCP, Azure, GitHub, GitLab, Okta) collect JSON, validated against an evidence-type schema | The declarative `pass_when` DSL |
| `manual` | Files uploaded to a bucket folder, resolved from a manual-evidence catalog entry | A PDF-presence check (file present, in the temporal window, valid PDF) |

Each policy maps to one or more framework controls (SOC 2 TSC criteria, or ISO 27001 Annex A controls and clause 4-10 management-system requirements). Automated policies produce their result from live infrastructure state; manual policies attest that the required evidence file exists for the audit period. Both evidence flows are explained in [Concepts](../concepts.md#the-two-evidence-flows).

### ISO 27001 control IDs: `A.` versus `C.`

ISO 27001 controls carry one of two prefixes, and the difference is not cosmetic:

- **`A.` — Annex A controls** (`A.5.1`, `A.8.5`, …). The 93 controls an
  organization selects from. One can be declared `not_applicable` in
  `.sigcomply.yaml` with a `reason`, and every one of them — included or
  excluded — appears in the Statement of Applicability
  (`sigcomply report --view soa`).
- **`C.` — clause 4-10 management-system requirements** (`C.4.3`, `C.9.2`, …).
  The 16 requirements of the ISMS itself: its scope, its risk assessment and
  treatment processes, its internal audit program, its management review.
  Certification is granted against the management system, so an organization
  cannot decline one: `applicability: not_applicable` against a `C.` control is
  a config error (exit 3), and `C.` controls never appear in the Statement of
  Applicability.

The prefix exists because the numbering collides. Clause 5.2 (the information
security policy) and Annex A 5.2 (information security roles) are different
requirements an auditor checks separately, so they are `C.5.2` and `A.5.2`.

All 16 `C.` requirements are manual, annual document uploads — a scope
statement, a risk register, internal audit findings, management review minutes.
They are documents you produce and upload; until you do, they are not covered,
and `report --view coverage` counts them apart from Annex A so that never reads
as coverage you have. The one piece of ISO's mandatory documented information
SigComply produces rather than asks for is the Statement of Applicability itself
(clause 6.1.3 d) — see [`report --view soa`](commands.md#sigcomply-report).

## Inspecting a framework

- **Manual catalog** — list the manual-evidence entries for a framework (id, control, type, frequency, temporal rule, grace period, name, description, severity, TSC):

  ```bash
  sigcomply evidence catalog -f soc2
  sigcomply evidence catalog -f soc2 -o json
  ```

- **Automated policy definitions** — the open Go-native policy source lives under `internal/frameworks/<framework>/` in the [`sigcomply-cli`](https://github.com/SigComply/sigcomply-cli) repository (e.g. `internal/frameworks/soc2/`). Each policy is a Go builder carrying its `pass_when` clause, so the exact logic behind every check is readable.

## See also

- [Commands](commands.md) — the `evidence catalog` and `check` reference.
- [Concepts](../concepts.md) — the two evidence flows and the aggregation boundary.
- [Configuration](../configuration.md) — per-policy and per-control customization.
- [Documentation hub](../README.md).
