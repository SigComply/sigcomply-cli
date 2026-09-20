# 13 — ISMS Clauses and the Statement of Applicability

This document explains why ISO 27001 needed two things the framework did
not have — the management-system requirements of clauses 4–10, and a
generated Statement of Applicability — and how both are modeled.

It is the canonical reference for `core.Control.Kind`, for the rule that
a management-system requirement cannot be declared `not_applicable`, and
for how `sigcomply report --view soa` is assembled. The per-control
applicability keys it reads are specified in
[08-project-config.md](08-project-config.md); the customer-facing
walkthrough is [`../guides/isms-clauses.md`](../guides/isms-clauses.md).

---

## Annex A alone was not ISO readiness

The ISO 27001 framework shipped the 93 Annex A controls and nothing for
clauses 4–10. Every coverage surface — `--view coverage`, the published
figures, the compliance score — was computed over those 93, and reported
full coverage of them.

That is a claim the product could not back. Certification is granted
against the **management system**, not against Annex A. Annex A is
normative but it is a reference set of information security controls; the
requirements an organization must meet to be certified are clauses 4 to
10. A Stage 1 audit is, in practice, a documentation review of exactly
those clauses: is the scope defined, is there a risk assessment process,
were internal audits conducted, did top management review the ISMS.

So an organization could pass every SigComply check, read a clean
coverage report, and fail Stage 1 without the product ever having hinted
at the gap. Worse, the gap was invisible *by construction*: the universe
against which coverage was measured was itself missing a third of what
the auditor asks for, so nothing inside the measurement could reveal it.
This is the same failure shape as the scope blind spot in
[08-project-config.md](08-project-config.md#the-scope-model) — a score
computed over an under-declared universe reads better, not worse, for
being incomplete.

The fix is 16 new controls and 16 new policies. They are listed in
`ismsClauses` and `ismsClauseManualSpecs` in
`internal/frameworks/iso27001/`.

| Control | Clause | Catalog entry | Policy |
|---|---|---|---|
| `C.4.1-4.2` | 4.1 + 4.2 | `isms_context` | `iso27001.clause.4.1.isms_context` |
| `C.4.3` | 4.3 | `isms_scope` | `iso27001.clause.4.3.isms_scope` |
| `C.5.2` | 5.2 | `isms_policy` | `iso27001.clause.5.2.isms_policy` |
| `C.5.3` | 5.3 | `isms_roles` | `iso27001.clause.5.3.isms_roles` |
| `C.6.1.2` | 6.1.2 | `risk_assessment_process` | `iso27001.clause.6.1.2.risk_assessment_process` |
| `C.6.1.3` | 6.1.3 | `risk_treatment_process` | `iso27001.clause.6.1.3.risk_treatment_process` |
| `C.6.2` | 6.2 | `isms_objectives` | `iso27001.clause.6.2.isms_objectives` |
| `C.7.2` | 7.2 | `competence_records` | `iso27001.clause.7.2.competence_records` |
| `C.7.5` | 7.5 | `documented_information` | `iso27001.clause.7.5.documented_information` |
| `C.8.1` | 8.1 | `operational_planning` | `iso27001.clause.8.1.operational_planning` |
| `C.8.2` | 8.2 | `risk_assessment_results` | `iso27001.clause.8.2.risk_assessment_results` |
| `C.8.3` | 8.3 | `risk_treatment_results` | `iso27001.clause.8.3.risk_treatment_results` |
| `C.9.1` | 9.1 | `isms_monitoring` | `iso27001.clause.9.1.isms_monitoring` |
| `C.9.2` | 9.2 | `internal_audit` | `iso27001.clause.9.2.internal_audit` |
| `C.9.3` | 9.3 | `management_review` | `iso27001.clause.9.3.management_review` |
| `C.10.2` | 10.2 | `corrective_action` | `iso27001.clause.10.2.corrective_action` |

The ID carries a `C.` prefix so it can never be read as an Annex A
reference. Clause 5.2 (the information security policy that top
management establishes) and A.5.2 (information security roles and
responsibilities) are different requirements that an auditor tests
separately; two controls that differ only by an invisible namespace would
be a reporting bug waiting to happen.

Clause 6.1.3's own mandatory output — the Statement of Applicability — is
deliberately absent from that table. It is the one piece of ISO's
mandatory documented information SigComply can *produce* rather than
collect; see [Assembling the SoA](#assembling-the-soa). `C.6.1.3` covers
the risk treatment *process* and plan, which the SoA does not replace.

---

## Two kinds of control

The 16 are not ordinary controls, and modelling them as if they were
would break two things. So `core.Control` gained a `Kind`:

```go
type ControlKind string

const (
    ControlKindCatalog          ControlKind = "catalog"
    ControlKindManagementSystem ControlKind = "management_system"
)
```

- **`ControlKindCatalog`** — a control an organization *selects*. It may
  include it (with a justification) or exclude it (with a reason). ISO
  27001 Annex A and the SOC 2 Trust Services Criteria are both this. It
  is the zero value, so a framework with only catalog controls declares
  nothing and no existing framework changed.
- **`ControlKindManagementSystem`** — a requirement of the management
  system itself. It is not selectable. An organization cannot decline to
  have an internal audit program and remain certifiable.

`Control.IsManagementSystem()` is the predicate every consumer uses.

### Why `Kind`, and not an ID prefix

Reading `strings.HasPrefix(id, "C.")` — or, inversely, `"A."` — would
have worked for the shipped ISO catalog and been wrong everywhere else.

The reporting package is deliberately **framework-registry-free**. It
reads vault bytes plus whatever catalog the caller hands it; it must not
import `internal/frameworks` (see the `Input` doc comment in
`internal/report/report.go`). A prefix check would smuggle one
framework's ID convention into a package that is not allowed to know
which framework it is rendering, and would silently misclassify the
next framework whose management-system requirements are numbered
differently.

The second reason is extensibility. A project-local framework extension
([07-extensibility.md](07-extensibility.md)) authors its own controls
with its own IDs, which carry neither prefix. Under a prefix rule those
controls would fall out of the Statement of Applicability — the exact
opposite of correct, since a control an organization designed itself is
precisely the kind 6.1.3 b) NOTE 1 expects to see listed. So project-local
framework YAML carries the same field:

```yaml
controls:
  - id: ORG.1
    name: Board oversight of the ISMS
    kind: management_system      # catalog (default) | management_system
```

Decoding is strict, so an unrecognized `kind` is rejected rather than
being read as the default — the failure mode there is a management-system
requirement that silently becomes excludable.

### What the SoA covers is wider than Annex A

This is the nuance that makes the prefix approach not merely brittle but
incorrect. ISO/IEC 27001:2022 6.1.3 b) NOTE 1 is explicit that an
organization may design controls from any source; Annex A is a
cross-check list to make sure nothing necessary was overlooked, not the
menu from which controls must be drawn. So the SoA lists **the necessary
controls**, which can and often does include controls that never appear
in Annex A.

What the SoA never covers is the management-system clauses. The filter is
therefore `!IsManagementSystem()` — a statement about whether a control
is *selectable* — and never a test on where the control came from.

---

## A management-system requirement cannot be excluded

`validateApplicability` in `internal/planner/references.go` rejects any
project config that declares a management-system control
`not_applicable`, before the plan is built (exit 3):

```
project config: controls["C.9.2"]: "C.9.2" is a management-system requirement
of iso27001 (Internal audit) and cannot be declared not_applicable —
certification is granted against the management system, not against a subset
of it
```

Marking one `applicable` is a no-op and allowed; so is recording an
`approved_by` against it. Excluding an Annex A control remains exactly
what applicability is for and is untouched.

Without this check nothing would have *failed* — which is the problem.
Control-level applicability **cascades**: every policy mapping to a
`not_applicable` control is set to `na` in the run
([08-project-config.md](08-project-config.md#the-controls-section)). So
`controls: {C.9.2: {applicability: not_applicable}}` would quietly turn
the internal-audit requirement into a non-result, remove it from the
compliance-score denominator, and *raise* the score. Declining to have an
ISMS would improve the number the dashboard shows. That is the most
expensive way this could have failed, and it would have failed silently,
so it is refused at config-load time rather than reported afterwards.

---

## All sixteen are `document_upload`

Every one of the 16 is a manual policy with `evidence_mode: manual`, a
`document_upload` catalog entry, and an **annual** cadence.

`document_upload` rather than a declaration or checklist because these
are documents an auditor *reads*: a scope statement, a risk register,
internal audit findings, management review minutes, a corrective-action
log. The Evidence SPA renders declaration and checklist entries as
click-through forms, and rendering a management review as a set of
checkboxes someone ticks would reproduce, one layer down, the precise
overclaim these 16 exist to retire — a clean tick where the auditor needs
a document. The SPA filters `document_upload` entries out of its
dashboard already, so all 16 are correctly absent from it and no SPA
change was needed.

Annual throughout because every one of these sits on a yearly management
cycle in the standard. A quarterly cadence would demand, three quarters
out of four, evidence that does not legitimately exist yet — and, because
the audit period is derived from the HEAD commit's timestamp
([10-cadence-model.md](10-cadence-model.md#period-freeze-rule)), evidence
cannot be staged into a future period's folder to get ahead of it.

The CLI's check on them is the ordinary manual check and nothing more:
supported files present in the catalog-resolved folder, merged, valid,
and within the temporal window. It does not read the document. A
management review PDF that contains a shopping list passes. That is
stated plainly here for the same reason it is stated in
[`../guides/manual-evidence.md`](../guides/manual-evidence.md): the
presence-and-freshness check is what SigComply automates, and reviewing
what the document says is the auditor's job.

### Three of the sixteen are not strictly mandatory

ISO/IEC 27001:2022 requires a specific list of documented information.
Thirteen of the 16 are on it. Three are not, and the code says so in
`ismsClauses`:

- **`C.4.1-4.2`** — the context and interested-parties analysis. Clauses
  4.1 and 4.2 require the determination to be *made*, not documented; but
  6.1.1 and 9.3.2 b) consume its output, and every certification audit
  asks to see it.
- **`C.5.3`** — the assignment of ISMS roles, responsibilities and
  authorities. Clause 5.3 requires assignment and communication; auditors
  ask for the document that records it.
- **`C.7.5`** — the document register or document-control procedure.
  Clause 7.5 governs how documented information is controlled; a register
  evidencing that control is what an auditor samples.

They are included because an auditor will ask for them. They are labeled
here, and in the source, because a set advertised as "ISO's mandatory
documented information" that quietly exceeds it would be the same species
of overclaim this whole change exists to fix — smaller, but the same.

---

## Assembling the SoA

ISO/IEC 27001:2022 6.1.3 d) requires a Statement of Applicability, and it
is the first document a Stage 1 auditor asks for. It must state four
things per control: which controls are necessary, why each is included,
whether it is implemented, and the justification for excluding any
Annex A control that was left out.

SigComply already held all four, in three different places, with no
surface that joined them:

| What 6.1.3 d) asks | Where it lives |
|---|---|
| Which controls are necessary | The framework's control catalog, compiled into the binary |
| Why this one is included | `controls.<id>.justification` in `.sigcomply.yaml` |
| Why that one is excluded | `controls.<id>.applicability: not_applicable` + `reason` + `approved_by` |
| Whether it is implemented | The period's policy results in the vault |

`buildSoA` in `internal/report/soa.go` joins them. For each control that
is **not** a management-system requirement it emits an `SoARow` with
`ControlID`, `Name`, `Applicable`, `Justification`,
`JustificationDerived`, `Status`, `Assurance`, `Evaluated`, `Policies`
and `ApprovedBy`. The view counts the management-system requirements it
skipped in `SoAView.ManagementSystem` and names them in `SoAView.Note`,
so a reader can see what was deliberately left out rather than wondering.

Three properties are worth stating explicitly, because each is a decision
rather than an implementation detail.

**Status is derived, never asserted.** `soaStatus` rolls up this period's
results: `implemented` only when every check that ran passed, then
`partially implemented`, `not implemented`, and `not evaluated` when no
check ran at all. A control whose annual policy has not run this quarter
reports `not evaluated`; it never borrows a pass from the catalog. A
partially implemented control that reads as implemented is the failure
mode worth avoiding on this particular document.

**"That ran" decides the two awkward statuses.** A policy resolved to
`na` — by a policy-level `exceptions: [{state: na}]`, or by the cascade
from a `not_applicable` control onto a *different* control it also maps
to — never reached its rule. It is left out of the roll-up entirely
rather than counted as met, so a control with nothing but `na` policies
reports `not evaluated`. Counting it as met was the sharper version of
exactly the failure mode above: it turned the documented remedy for a
control you cannot satisfy into an assertion that you had implemented
it. A **carried-forward** policy is the mirror case — it did run, in an
earlier period, and it passed — so it counts as met, as it already does
in the compliance score and the coverage view.

**Assurance travels with the row.** Each row carries `automated`,
`manual` or `none` — the strongest kind of check behind the control, the
same classification `--view coverage` renders. An implemented control
evidenced only by a PDF on file is a weaker claim than one where
infrastructure was inspected, and a document handed to a certification
body should not flatten the two.

**A derived justification says that it is derived.** Where the operator
has written no `justification`, `defaultJustification` produces one from
the checks standing behind the control ("Applicable — no exclusion
declared. Verified by 3 automated checks and 1 manual evidence item.").
It is accurate and generic, it is flagged with `JustificationDerived`,
rendered as `(derived) …` in text and as a `justification_derived` column
in CSV, and counted in `SoAView.Derived` so the headline note can point
at it. An auditor can then tell a reasoned inclusion from a default one,
rather than reading boilerplate as deliberation.

Output is text, JSON and CSV. CSV is the form auditors actually work in —
one row per control, sortable, annotatable — and is why the view exists
in a tool rather than in a slide.

### Why it is generated rather than uploaded

The SoA could have been a seventeenth `document_upload` entry: ask the
customer to maintain the spreadsheet and drop it in a folder. That would
have been cheaper and worse.

The document is a join over data the CLI already owns authoritatively,
and a hand-maintained copy of a derived artifact drifts the moment a
control is excluded, a policy is added, or a check starts failing —
silently, because nothing compares the two. Generating it means the SoA
is a *rendering* of the configuration in git and the evidence in the
vault, both of which are reviewable, rather than a parallel assertion
about them. It is the same argument as
[06-aggregation.md](06-aggregation.md): derive the claim from the
evidence, do not accept a claim alongside it.

### Why the SoA requires the project config

`--view soa` is the one report view that refuses to run without the
project config:

```
report: --view soa needs the project config for its applicability decisions —
pass -c <path to .sigcomply.yaml>, or drop --vault/--framework so
.sigcomply.yaml is read
```

Every other view is a pure reader of vault bytes, so an auditor holding
only a vault path and a framework name can produce them without the
customer's `.sigcomply.yaml`. The SoA cannot, because the applicability
decisions are **authored, not observed** — there is nowhere in the vault
to read them from.

Degrading gracefully was the tempting alternative and is the wrong one.
Without the config every control would render as applicable, which turns
a deliberate, approved exclusion into a silent inclusion on the single
document a certification auditor reads first, and states it as the
organization's own position. Refusing is the honest answer; a footnote at
the bottom of a CSV nobody scrolls to is not.

This is also why `internal/report` imports `internal/spec` at all —
`Input.ControlConfigs` is the package's one exception to being a pure
reader of vault bytes. `spec` is a dependency-free leaf, so the coupling
is narrow and acyclic. `internal/frameworks` remains forbidden: the
control catalog is resolved in `cmd/sigcomply/report.go` and passed in.

---

## Coverage counts them apart

`--view coverage` gained a `KIND` column (`catalog` / `mgmt-system`) and
two counters, `CoverageView.ManagementSystem` and
`ManagementSystemOnFile`. Management-system requirements get rows — they
are the point of the change, not an appendix — but their own totals:

```
93 of 93 catalog controls have a check
  26 automated  — verified by inspecting your infrastructure
  67 manual     — satisfied by a document being on file

16 management-system requirements (counted apart — they are not selectable)
  4 with evidence on file this period, 12 without
```

Blending the two into one number would flatter the headline at exactly
the moment the honest gap is closed: "93 of 93 covered" would become "109
of 109 covered" on the day 16 requirements with no evidence on file were
added. A coverage view that improves when a gap is discovered is the
precise drift this view exists to catch, so the same split is enforced in
`measure` in `internal/manualcatalog/doc_figures_test.go`, which pins the
published figures to the compiled framework. **Never write a single
number that blends the 93 and the 16.** The framework has 93 Annex A
controls and 16 management-system requirements.

---

## See also

- [`../guides/isms-clauses.md`](../guides/isms-clauses.md) — the how-to:
  what to upload where, running `--view soa`, and what existing ISO
  projects should expect on their next annual run.
- [08-project-config.md](08-project-config.md#the-controls-section) —
  `controls.<id>.applicability`, `reason`, `approved_by`, `justification`
  and the cascade.
- [01-conceptual-model.md](01-conceptual-model.md) — the vocabulary; the
  Control entry names the two kinds.
- [07-extensibility.md](07-extensibility.md) — project-local framework
  extensions, which carry `kind:` on a control for the same reason.
- [10-cadence-model.md](10-cadence-model.md) — why annual cadences write
  no result in most periods, and the advisory `sigcomply evidence due`.
- [`../guides/manual-evidence.md`](../guides/manual-evidence.md) — the
  manual evidence flow these 16 policies use unchanged.
- `internal/core/framework.go` — `ControlKind`, `Control.Kind`,
  `Control.IsManagementSystem()`.
- `internal/report/soa.go` — `buildSoA` and the status/justification
  derivation.
- `internal/planner/references.go` — `validateApplicability`.
