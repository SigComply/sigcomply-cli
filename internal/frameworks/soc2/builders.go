// Package soc2 is the SOC 2 (TSC 2017) framework: the control catalog,
// the automated policy library expressed in the pass_when: DSL, the
// manual-evidence policies, and the handful of Go rules for checks the
// DSL cannot express (CloudWatch metric-filter substring matching).
//
// Policies are authored as Go values via the compact builders in this
// file. Most automated checks reduce to "every / no / some record in a
// slot satisfies a field condition" — exactly what the pass_when DSL
// expresses without a line of Go. The escape-hatch rules live in
// rules.go.
//
// Many policies reference evidence types whose source plugins are not
// yet registered (firewall_rule, password_policy, cloudwatch_alarm, …).
// Those policies plan cleanly and are skipped at evaluation until a
// matching source is configured — the deferred-source model. See
// docs/claude/implementation-plan-policy-library.md.
package soc2

import (
	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/manualcatalog"
)

// slotName is the single conventional slot name every automated SOC 2
// policy uses. Keeping it uniform lets the pass_when clause and the slot
// map share one constant.
const slotName = "evidence"

// controlRefs wraps a single SOC 2 control ID into the framework-
// namespaced ControlRef list every policy carries. The framework ID and
// version qualify the bare control ID (e.g. "CC6.1") so results and the
// cloud payload record which framework version the control belongs to.
// A check satisfying controls in more than one framework is authored
// with a hand-written multi-element Controls list instead.
func controlRefs(id string) []core.ControlRef {
	return []core.ControlRef{{
		Framework:        FrameworkID,
		FrameworkVersion: FrameworkVersion,
		ControlID:        id,
		Relationship:     core.RelationshipEqual,
	}}
}

// autoPolicy is the compact authoring shape for an automated pass_when
// policy. policy() expands it into a core.Policy with a single
// one-or-more slot and a single pass_when clause.
type autoPolicy struct {
	id       string
	control  string
	severity core.Severity
	category string
	cadence  string
	accepts  []string
	desc     string
	rem      string
	clause   core.PassWhenClause
}

//nolint:gocritic // hugeParam: one-time startup builder; value literals keep the policy tables legible.
func (a autoPolicy) policy() core.Policy {
	clause := a.clause
	clause.Slot = slotName
	return core.Policy{
		ID:           a.id,
		Controls:     controlRefs(a.control),
		Description:  a.desc,
		Remediation:  a.rem,
		Severity:     a.severity,
		Category:     a.category,
		Cadence:      a.cadence,
		OnPush:       true,
		EvidenceMode: core.EvidenceModeAutomated,
		Slots: map[string]core.Slot{
			slotName: {Accepts: a.accepts, Cardinality: core.SlotOneOrMore, Required: true, Description: "evidence records"},
		},
		PassWhen: &core.PassWhenSpec{Clauses: []core.PassWhenClause{clause}},
	}
}

// rulePolicy is the authoring shape for an automated policy that uses a
// Go rule: escape hatch instead of pass_when.
type rulePolicy struct {
	id       string
	control  string
	severity core.Severity
	category string
	cadence  string
	accepts  []string
	desc     string
	rem      string
	ruleRef  string
}

//nolint:gocritic // hugeParam: one-time startup builder; value literals keep the policy tables legible.
func (r rulePolicy) policy() core.Policy {
	return core.Policy{
		ID:           r.id,
		Controls:     controlRefs(r.control),
		Description:  r.desc,
		Remediation:  r.rem,
		Severity:     r.severity,
		Category:     r.category,
		Cadence:      r.cadence,
		OnPush:       true,
		EvidenceMode: core.EvidenceModeAutomated,
		Slots: map[string]core.Slot{
			slotName: {Accepts: r.accepts, Cardinality: core.SlotOneOrMore, Required: true, Description: "evidence records"},
		},
		RuleRef: r.ruleRef,
	}
}

// manualPolicy is the authoring shape for a manual-evidence policy. The
// presentation fields (name, etype, severity, items, declarationText,
// …) feed only the descriptive catalog export consumed by the Evidence
// SPA — the evaluator ignores them (every manual policy runs the same
// PDF-presence check). They default sensibly: etype → document_upload,
// name → TitleFromID(catalog), severity → "medium".
type manualPolicy struct {
	id      string
	control string
	cadence string
	catalog string
	desc    string
	rem     string

	// Catalog-export presentation metadata (optional).
	name            string
	etype           manualcatalog.EvidenceType
	severity        string
	items           []manualcatalog.ChecklistItem
	declarationText string
	category        string
	tsc             string
}

// entry expands the policy into its descriptive catalog entry for the
// `sigcomply evidence catalog` export.
//
//nolint:gocritic // hugeParam: one-time startup builder.
func (m manualPolicy) entry() manualcatalog.Entry {
	name := m.name
	if name == "" {
		name = manualcatalog.TitleFromID(m.catalog)
	}
	etype := m.etype
	if etype == "" {
		etype = manualcatalog.TypeDocumentUpload
	}
	severity := m.severity
	if severity == "" {
		severity = "medium"
	}
	return manualcatalog.Entry{
		ID:              m.catalog,
		Control:         m.control,
		Type:            etype,
		Frequency:       manualcatalog.FrequencyFromCadence(m.cadence),
		TemporalRule:    manualcatalog.TemporalRetrospective,
		GracePeriod:     manualcatalog.GraceForCadence(m.cadence),
		Name:            name,
		Description:     m.desc,
		Severity:        severity,
		Items:           m.items,
		DeclarationText: m.declarationText,
		Category:        m.category,
		TSC:             m.tsc,
	}
}

//nolint:gocritic // hugeParam: one-time startup builder; value literals keep the policy tables legible.
func (m manualPolicy) policy() core.Policy {
	return core.Policy{
		ID:           m.id,
		Controls:     controlRefs(m.control),
		Description:  m.desc,
		Remediation:  m.rem,
		Severity:     core.SeverityMedium,
		Category:     "governance",
		Cadence:      m.cadence,
		OnPush:       false,
		EvidenceMode: core.EvidenceModeManual,
		CatalogEntry: m.catalog,
	}
}

// --- pass_when clause builders -------------------------------------

// leaf builds a single comparison condition.
func leaf(field, op string, value any) *core.PassWhenCondition {
	return &core.PassWhenCondition{Op: op, Field: field, Value: value}
}

// allOf / anyOf build compound conditions.
func allOf(conds ...*core.PassWhenCondition) *core.PassWhenCondition {
	return &core.PassWhenCondition{Op: "all_of", Conditions: conds}
}

func anyOf(conds ...*core.PassWhenCondition) *core.PassWhenCondition {
	return &core.PassWhenCondition{Op: "any_of", Conditions: conds}
}

// all builds an "every record satisfies cond" clause.
func all(cond *core.PassWhenCondition, msg string) core.PassWhenClause {
	return core.PassWhenClause{Quantifier: core.QuantifierAll, Condition: cond, ViolationMsg: msg}
}

// none builds a "no record satisfies cond" clause.
func none(cond *core.PassWhenCondition, msg string) core.PassWhenClause {
	return core.PassWhenClause{Quantifier: core.QuantifierNone, Condition: cond, ViolationMsg: msg}
}

// anyRec builds an "at least one record satisfies cond" clause.
func anyRec(cond *core.PassWhenCondition, msg string) core.PassWhenClause {
	return core.PassWhenClause{Quantifier: core.QuantifierAny, Condition: cond, ViolationMsg: msg}
}

// allWhere builds an "every record matching filter satisfies cond" clause.
func allWhere(filter, cond *core.PassWhenCondition, msg string) core.PassWhenClause {
	return core.PassWhenClause{Quantifier: core.QuantifierAll, Filter: filter, Condition: cond, ViolationMsg: msg}
}

// noneWhere builds a "no record matching filter satisfies cond" clause.
func noneWhere(filter, cond *core.PassWhenCondition, msg string) core.PassWhenClause {
	return core.PassWhenClause{Quantifier: core.QuantifierNone, Filter: filter, Condition: cond, ViolationMsg: msg}
}

// anyWhere builds an "at least one record matching filter satisfies cond" clause.
func anyWhere(filter, cond *core.PassWhenCondition, msg string) core.PassWhenClause {
	return core.PassWhenClause{Quantifier: core.QuantifierAny, Filter: filter, Condition: cond, ViolationMsg: msg}
}
