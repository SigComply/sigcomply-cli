// Package iso27001 is the ISO/IEC 27001:2022 framework: the Annex A
// control catalog, the automated technological-control policies in the
// pass_when: DSL, and the manual-evidence policies across the
// organizational, people, physical, and technological themes.
//
// ISO 27001 reuses the same cross-vendor evidence types as SOC 2 — it
// checks the same infrastructure, differing only in policy ID, control
// reference, and thresholds. The compact builders here mirror the SOC 2
// framework's; per the project's KISS-no-DRY convention each framework
// owns its helpers rather than sharing a package.
package iso27001

import (
	"fmt"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

const slotName = "evidence"

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

func leaf(field, op string, value any) *core.PassWhenCondition {
	return &core.PassWhenCondition{Op: op, Field: field, Value: value}
}

func allOf(conds ...*core.PassWhenCondition) *core.PassWhenCondition {
	return &core.PassWhenCondition{Op: "all_of", Conditions: conds}
}

func anyOf(conds ...*core.PassWhenCondition) *core.PassWhenCondition {
	return &core.PassWhenCondition{Op: "any_of", Conditions: conds}
}

func all(cond *core.PassWhenCondition, msg string) core.PassWhenClause {
	return core.PassWhenClause{Quantifier: core.QuantifierAll, Condition: cond, ViolationMsg: msg}
}

func none(cond *core.PassWhenCondition, msg string) core.PassWhenClause {
	return core.PassWhenClause{Quantifier: core.QuantifierNone, Condition: cond, ViolationMsg: msg}
}

func allWhere(filter, cond *core.PassWhenCondition, msg string) core.PassWhenClause {
	return core.PassWhenClause{Quantifier: core.QuantifierAll, Filter: filter, Condition: cond, ViolationMsg: msg}
}

func noneWhere(filter, cond *core.PassWhenCondition, msg string) core.PassWhenClause {
	return core.PassWhenClause{Quantifier: core.QuantifierNone, Filter: filter, Condition: cond, ViolationMsg: msg}
}

func anyWhere(filter, cond *core.PassWhenCondition, msg string) core.PassWhenClause {
	return core.PassWhenClause{Quantifier: core.QuantifierAny, Filter: filter, Condition: cond, ViolationMsg: msg}
}

// portCovers builds the condition matching a firewall rule whose range
// covers the target port (or opens all ports via from_port == -1).
func portCovers(port int) *core.PassWhenCondition {
	return anyOf(
		allOf(leaf("payload.from_port", "lte", port), leaf("payload.to_port", "gte", port)),
		leaf("payload.from_port", "eq", -1),
	)
}

// unrestrictedPortClause flags any open (0.0.0.0/0) ingress rule covering
// the target port.
func unrestrictedPortClause(port int) core.PassWhenClause {
	filter := allOf(
		leaf("payload.direction", "eq", "ingress"),
		leaf("payload.is_unrestricted_ipv4", "eq", true),
		leaf("payload.protocol", "in", []any{"tcp", "all"}),
	)
	return noneWhere(filter, portCovers(port), fmt.Sprintf("firewall rule {{.payload.id}} exposes port %d to 0.0.0.0/0", port))
}

// unrestrictedPortsClause flags any open ingress rule covering any of the
// target ports.
func unrestrictedPortsClause(ports ...int) core.PassWhenClause {
	filter := allOf(
		leaf("payload.direction", "eq", "ingress"),
		leaf("payload.is_unrestricted_ipv4", "eq", true),
		leaf("payload.protocol", "in", []any{"tcp", "all"}),
	)
	conds := make([]*core.PassWhenCondition, 0, len(ports))
	for _, p := range ports {
		conds = append(conds, portCovers(p))
	}
	return noneWhere(filter, anyOf(conds...), "firewall rule {{.payload.id}} exposes a restricted database port to 0.0.0.0/0")
}
