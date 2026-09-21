// Package soc2 is the SOC 2 (TSC 2017) framework: the control catalog,
// the automated policy library expressed in the pass_when: DSL, and the
// manual-evidence policies. Every shipped policy is pass_when: or manual
// — Rules() returns nil (no rule: escape hatch is used today; the
// infrastructure remains available for a future check the DSL cannot
// express).
//
// Policies are authored as Go values via the compact builders in this
// file. Most automated checks reduce to "every / no / some record in a
// slot satisfies a field condition" — exactly what the pass_when DSL
// expresses without a line of Go.
//
// Every evidence type a shipped policy accepts has a registered emitter
// (enforced at build time by internal/sources/builtin/coverage_test.go),
// so there are no inert "deferred-source" policies in-tree. A new
// evidence type added ahead of its source must ship a source in the same
// change or the coverage test fails.
package soc2

import (
	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/manualcatalog"
)

// slotName is the single conventional slot name every automated SOC 2
// policy uses. Keeping it uniform lets the pass_when clause and the slot
// map share one constant.
const slotName = "evidence"

// Cadences the policy tables schedule their checks on.
const (
	cadenceDaily     = "daily"
	cadenceQuarterly = "quarterly"
	cadenceAnnual    = "annual"
)

// Trust Services Criteria a manual catalog entry is filed under. This is
// the SPA-facing taxonomy, which is why tscAvailability and tscPrivacy
// repeat the spelling of the like-named control categories.
const (
	tscSecurity        = "security"
	tscAvailability    = "availability"
	tscConfidentiality = "confidentiality"
	tscPrivacy         = "privacy"
)

// Evidence-type IDs more than one policy accepts. A type a single policy
// accepts stays spelled out at its one call site.
const (
	etAuditLogTrail           = "audit_log_trail"
	etContainerRegistry       = "container_registry"
	etDirectoryUser           = "directory_user"
	etDirectoryUserV2         = "directory_user.v2"
	etFirewallRule            = "firewall_rule"
	etGitRepository           = "git_repository"
	etIAMAccessKey            = "iam_access_key"
	etIAMBinding              = "iam_binding"
	etManagedDatabaseInstance = "managed_database_instance"
	etNoSQLTable              = "nosql_table"
	etObjectStorageBucket     = "object_storage_bucket"
	etPasswordPolicy          = "password_policy"
	etPasswordPolicyV2        = "password_policy.v2"
	etPullRequest             = "pull_request"
	etSecurityService         = "security_service"
	etVulnerabilityFinding    = "vulnerability_finding"
)

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

// rosterSubjectTypes are the identity shapes a roster can vouch for: an
// account in another system, or a cloud IAM role granted to a principal.
//
// Deliberately wider than directoryUserTypes rather than an extension of
// it. The MFA and account-lifecycle policies that read directory_user
// records ask questions a grant cannot answer — a binding has no MFA
// state and no last-login — so widening the shared set would break them.
// Only the roster join is type-agnostic, because "does this identity
// belong to someone on the roster" is the same question either way.
var rosterSubjectTypes = []string{etDirectoryUser, etDirectoryUserV2, etIAMBinding}

// passwordPolicyTypes are the password_policy versions the four CC6.1
// password policies read. Both versions are accepted and the clauses are
// written to read either, because the two shipped emitters (aws.iam's
// account policy and Okta) moved to v2 while a project-local plugin may
// still emit v1 — and a slot that accepted only one of them would leave
// the other's records unbound, which skips the policy rather than failing
// it. v2 is listed first so that a source emitting both (none in tree,
// and none should) has its richer record grouped first in the envelope.
var passwordPolicyTypes = []string{etPasswordPolicyV2, etPasswordPolicy}

// rosterPolicy is the authoring shape for an access-lifecycle policy
// that checks identities in other systems against the designated roster
// (experimental.roster.source). The roster slot is never auto-bound, and
// the planner never binds the roster source to the accounts slot: a
// directory cannot vouch for its own accounts.
type rosterPolicy struct {
	id, control, desc, rem string
	severity               core.Severity
	clause                 core.PassWhenClause
}

//nolint:gocritic // hugeParam: one-time startup builder.
func (r rosterPolicy) policy() core.Policy {
	clause := r.clause
	clause.Slot, clause.IdentityKey = "accounts", "account.ref"
	return core.Policy{
		ID: r.id, Controls: controlRefs(r.control), Description: r.desc, Remediation: r.rem,
		Severity: r.severity, Category: catAccess, Cadence: cadenceDaily, OnPush: true,
		EvidenceMode: core.EvidenceModeAutomated,
		Slots: map[string]core.Slot{
			"roster":   {Accepts: []string{"roster_entry"}, Cardinality: core.SlotExactlyOne, Required: true, Role: core.SlotRoleRoster, Description: "people in the designated roster directory"},
			"accounts": {Accepts: rosterSubjectTypes, Cardinality: core.SlotOneOrMore, Required: true, Role: core.SlotRoleRosterSubject, Description: "accounts and cloud IAM grants in every other identity source"},
		},
		PassWhen: &core.PassWhenSpec{Clauses: []core.PassWhenClause{clause}},
	}
}

// inRoster matches an identity whose key (alias, else email, else IAM
// principal) equals the email of a roster entry satisfying where
// (nil: any entry).
func inRoster(where *core.PassWhenCondition) *core.PassWhenCondition {
	return &core.PassWhenCondition{Op: core.OpMatchesIn, Field: "account.key", InSlot: "roster", RemoteField: "payload.email", Normalize: core.NormalizeLowerTrim, Where: where}
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

	// fanOut names the set this entry's evidence multiplies over (see
	// the manual.FanOut* constants). It reaches the runtime catalog
	// only — the SPA-facing export stays a flat, config-independent
	// contract, because the members come from the project's config and
	// the export is framework-static.
	fanOut string
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
		Category:     catGovernance,
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

// isSet builds a presence guard. A clause filter that cannot be
// evaluated errors the policy, so a filter reading a schema-OPTIONAL
// field must say so explicitly: allOf(isSet(f), leaf(f, ...)). all_of
// short-circuits, so the comparison is never reached when f is absent.
func isSet(field string) *core.PassWhenCondition {
	return leaf(field, "is_set", nil)
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
