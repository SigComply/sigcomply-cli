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

import "github.com/sigcomply/sigcomply-cli/internal/core"

// slotName is the single conventional slot name every automated SOC 2
// policy uses. Keeping it uniform lets the pass_when clause and the slot
// map share one constant.
const slotName = "evidence"

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
		Control:      a.control,
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
		Control:      r.control,
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

// manualPolicy is the authoring shape for a manual-evidence policy.
type manualPolicy struct {
	id      string
	control string
	cadence string
	catalog string
	desc    string
	rem     string
}

//nolint:gocritic // hugeParam: one-time startup builder; value literals keep the policy tables legible.
func (m manualPolicy) policy() core.Policy {
	return core.Policy{
		ID:           m.id,
		Control:      m.control,
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
