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
	"github.com/sigcomply/sigcomply-cli/internal/manualcatalog"
)

const slotName = "evidence"

// Cadences the policy tables schedule against.
const (
	cadenceDaily     = "daily"
	cadenceQuarterly = "quarterly"
	cadenceAnnual    = "annual"
)

// Policy categories — the grouping axis carried into results and the
// cloud payload.
const (
	catAccess           = "access"
	catAvailability     = "availability"
	catChangeManagement = "change-management"
	catDataProtection   = "data-protection"
	catGovernance       = "governance"
	catLogging          = "logging"
	catMonitoring       = "monitoring"
	catNetwork          = "network"
)

// Evidence-type IDs accepted by more than one policy. These are the
// registry's wire IDs — the only mediator between a policy and the
// source plugins that emit the type.
const (
	etAuditLogTrail           = "audit_log_trail"
	etComputeInstance         = "compute_instance"
	etFirewallRule            = "firewall_rule"
	etDirectoryUser           = "directory_user"
	etDirectoryUserV2         = "directory_user.v2"
	etGitRepository           = "git_repository"
	etIAMBinding              = "iam_binding"
	etManagedDatabaseInstance = "managed_database_instance"
	etObjectStorageBucket     = "object_storage_bucket"
	etPasswordPolicy          = "password_policy"
	etPasswordPolicyV2        = "password_policy.v2"
	etPullRequest             = "pull_request"
	etSourceControlOrgPolicy  = "source_control_org_policy"
)

// controlRefs wraps a single ISO 27001 Annex A control ID into the
// framework-namespaced ControlRef list every policy carries. The
// framework ID and version qualify the bare control ID (e.g. "A.8.9")
// so results and the cloud payload record the framework version. A
// check satisfying controls in more than one framework is authored with
// a hand-written multi-element Controls list instead.
func controlRefs(id string) []core.ControlRef {
	return []core.ControlRef{{
		Framework:        FrameworkID,
		FrameworkVersion: FrameworkVersion,
		ControlID:        id,
		Relationship:     core.RelationshipEqual,
	}}
}

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
// presentation fields feed only the descriptive catalog export consumed
// by the Evidence SPA — the evaluator ignores them. They default
// sensibly: etype → document_upload, name → TitleFromID(catalog),
// severity → "medium".
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

func leaf(field, op string, value any) *core.PassWhenCondition {
	return &core.PassWhenCondition{Op: op, Field: field, Value: value}
}

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

// --- password-policy clauses ---------------------------------------
//
// passwordPolicyTypes are the password_policy versions the two A.8.5
// password policies read. Both are accepted: the two shipped emitters
// (aws.iam's account policy and Okta) moved to v2, while a project-local
// plugin may still emit v1, and a slot accepting only one version would
// leave the other's records unbound — which skips the policy rather than
// failing it, and a skip leaves the score denominator.
//
// Every field these clauses touch is optional in v2, so every read is
// is_set-guarded: the evaluator errors on a reference to a field the
// record does not carry, in a filter as much as in a condition. A record
// that cannot answer a clause's question is filtered out of scope rather
// than failed — "the source could not see this setting" is not "the
// setting is off" — and a clause left with nothing to examine is reported
// as vacuous (core.DiagVacuousClauses) rather than passing quietly.
//
// These mirror the SOC 2 builders of the same names
// (internal/frameworks/soc2/policies_cc6.go), which carry the full
// rationale for the reframed strength clause. The two frameworks keep
// their own copies for the same reason they keep their own copies of
// unrestrictedPortClause: a framework package owns its policy library.
var passwordPolicyTypes = []string{etPasswordPolicyV2, etPasswordPolicy}

// passwordLengthClause builds "every password policy in force requires at
// least min characters", skipping policies whose platform exposes no
// minimum length at all. A configured 0 is an observed "no minimum" and
// fails; an absent one was never read and is not judged.
func passwordLengthClause(minLength int) core.PassWhenClause {
	return allWhere(isSet("payload.min_length"),
		leaf("payload.min_length", "gte", minLength),
		fmt.Sprintf("password policy {{.payload.id}} has a minimum length below %d", minLength))
}

// passwordStrengthEnforcedClause builds "a password-strength control is
// enforced": all four character classes for a per-class source, the
// platform's strongest rating for a source that rates passwords instead
// (Google's allowedStrength, which its own documentation says is
// deliberately not a character-class rule), or a platform-enforced rule
// the tenant cannot weaken. complexity_model "none" — an account with no
// password policy at all — matches nothing and fails. See the SOC 2 twin
// for why the clause was reframed rather than the source reinterpreted.
func passwordStrengthEnforcedClause() core.PassWhenClause {
	answerable := anyOf(isSet("payload.complexity_model"), isSet("payload.requires_uppercase"))
	perClass := allOf(
		isSet("payload.requires_uppercase"), isSet("payload.requires_lowercase"),
		isSet("payload.requires_numbers"), isSet("payload.requires_symbols"),
		leaf("payload.requires_uppercase", "eq", true),
		leaf("payload.requires_lowercase", "eq", true),
		leaf("payload.requires_numbers", "eq", true),
		leaf("payload.requires_symbols", "eq", true),
	)
	strengthEnum := allOf(
		isSet("payload.password_strength"),
		leaf("payload.password_strength", "eq", "strong"),
	)
	platformFixed := allOf(
		isSet("payload.complexity_model"),
		leaf("payload.complexity_model", "eq", "fixed"),
	)
	return allWhere(answerable, anyOf(perClass, strengthEnum, platformFixed),
		"password policy {{.payload.id}} enforces no password-strength requirement")
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
