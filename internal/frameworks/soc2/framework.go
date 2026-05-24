// Package soc2 is the SOC 2 framework skeleton: a Framework
// implementation, the control catalog, and the seed policies that
// demonstrate every L0–L9 seam works end-to-end. The full ~300-policy
// catalog is post-M6 work; M6 ships 3 representative policies — one
// automated, one manual, one cross-source.
//
// See docs/architecture/09-implementation-roadmap.md §What's in
// v1-alpha.
package soc2

import (
	"context"
	"encoding/json"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

// FrameworkID is the registered identifier.
const FrameworkID = "soc2"

// FrameworkVersion stamps every PolicyRef returned by this framework.
const FrameworkVersion = "soc2-2017@0.1.0"

// PolicyMFAEnforced is the automated policy demonstrating
// aws.iam → user_record consumption.
const PolicyMFAEnforced = "soc2.cc6.1.mfa_enforced"

// PolicyAccessReview is the manual policy demonstrating
// manual.pdf → signed_document consumption.
const PolicyAccessReview = "soc2.cc6.3.access_review_quarterly"

// PolicyMFAUnion is the cross-source policy demonstrating slot union:
// the user_directory slot binds multiple sources (in M6's fixture,
// only aws.iam is registered, but the slot's cardinality is
// `one-or-more` so a second source can be added without policy
// change).
const PolicyMFAUnion = "soc2.cc6.1.mfa_enforced_all_sources"

// Framework is the in-process SOC 2 framework.
type Framework struct{}

// New returns a fresh Framework value.
func New() *Framework { return &Framework{} }

// ID implements core.Framework.
func (*Framework) ID() string { return FrameworkID }

// Version implements core.Framework.
func (*Framework) Version() string { return FrameworkVersion }

// Controls implements core.Framework.
func (*Framework) Controls() []core.Control { return Controls() }

// Policies implements core.Framework.
func (*Framework) Policies() []core.PolicyRef {
	return []core.PolicyRef{
		{PolicyID: PolicyMFAEnforced},
		{PolicyID: PolicyAccessReview},
		{PolicyID: PolicyMFAUnion},
	}
}

// Register populates the rule and policy registries with the SOC 2
// skeleton's rules and seed policies. Sources and evidence types are
// registered by the orchestrator alongside this call.
//
// Errors here surface as exit-3 configuration errors at startup.
func Register(set *registry.Set) error {
	if err := set.Frameworks.Register(New()); err != nil {
		return err
	}
	for _, r := range Rules() {
		if err := set.Rules.Register(r); err != nil {
			return err
		}
	}
	policies := Policies()
	for i := range policies {
		if err := set.Policies.Register(policies[i]); err != nil {
			return err
		}
	}
	return nil
}

// ManualCatalog returns the catalog entries the manual.pdf plugin
// needs to resolve manual-evidence paths. M6 ships one entry; full
// catalog YAML loading is post-M6.
func ManualCatalog() map[string]manual.CatalogEntry {
	return map[string]manual.CatalogEntry{
		"access_review_quarterly": {
			EvidenceID:   "access_review_quarterly",
			Filename:     "evidence.pdf",
			Cadence:      "quarterly",
			TemporalRule: "retrospective",
			GracePeriod:  15 * 24 * time.Hour,
		},
	}
}

// Policies returns the seed policies. Authoring them as Go values
// (rather than embedded YAML) keeps the walking skeleton legible; the
// L0 YAML loader is exercised in internal/spec's own tests.
func Policies() []core.Policy {
	return []core.Policy{
		{
			ID:          PolicyMFAEnforced,
			Control:     "SOC2.CC6.1",
			Description: "All IAM users have MFA enabled.",
			Remediation: "Enable MFA on the listed users via the AWS Console or `aws iam enable-mfa-device`.",
			Severity:    core.SeverityHigh,
			Category:    "access",
			Cadence:     "daily",
			OnPush:      true,
			Slots: map[string]core.Slot{
				"user_directory": {Type: "user_record", Cardinality: core.SlotExactlyOne, Required: true, Description: "IAM users"},
			},
			RuleRef: ruleIDMFAEnforced,
		},
		{
			ID:          PolicyAccessReview,
			Control:     "SOC2.CC6.3",
			Description: "Quarterly user access review has been performed and signed.",
			Remediation: "Conduct the quarterly access review and upload the signed PDF to the configured manual-evidence bucket.",
			Severity:    core.SeverityMedium,
			Category:    "access",
			Cadence:     "quarterly",
			OnPush:      false,
			Slots: map[string]core.Slot{
				"review_document": {Type: "signed_document", Cardinality: core.SlotExactlyOne, Required: true},
			},
			RuleRef: ruleIDManualPresence,
		},
		{
			ID:          PolicyMFAUnion,
			Control:     "SOC2.CC6.1",
			Description: "All human users across every bound user directory have MFA enabled.",
			Remediation: "Enable MFA for the listed users in each user-directory source.",
			Severity:    core.SeverityHigh,
			Category:    "access",
			Cadence:     "daily",
			OnPush:      true,
			Slots: map[string]core.Slot{
				"user_directory": {Type: "user_record", Cardinality: core.SlotOneOrMore, Required: true},
			},
			RuleRef: ruleIDMFAEnforced,
		},
	}
}

// Rules returns the rule implementations. Two rules cover the three
// policies (the two MFA policies share a rule).
func Rules() []core.Rule {
	return []core.Rule{
		mfaEnforcedRule(),
		manualPresenceRule(),
	}
}

const (
	ruleIDMFAEnforced    = "rules.soc2.mfa_enforced.v1"
	ruleIDManualPresence = "rules.soc2.manual_presence.v1"
)

// mfaEnforcedRule is a Go rule: passes iff every user_record in the
// user_directory slot has payload.mfa_enabled == true.
func mfaEnforcedRule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDMFAEnforced,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := in.Slots["user_directory"]
			deduped := dedupeByIdentity(records)
			violations := make([]core.Violation, 0)
			for i := range deduped {
				r := &deduped[i]
				mfa, err := payloadBool(r.Payload, "mfa_enabled")
				if err != nil {
					return core.RuleResult{}, err
				}
				if !mfa {
					name, nameErr := payloadString(r.Payload, "user_name")
					if nameErr != nil {
						return core.RuleResult{}, nameErr
					}
					violations = append(violations, core.Violation{
						ResourceID: r.ID,
						Reason:     "MFA disabled for user " + name,
					})
				}
			}
			status := core.StatusPass
			if len(violations) > 0 {
				status = core.StatusFail
			}
			return core.RuleResult{Status: status, Violations: violations}, nil
		},
	}
}

// manualPresenceRule is a Rego rule: passes iff the signed_document
// payload has file_present == true and in_temporal_window == true.
func manualPresenceRule() core.Rule {
	const module = `
package rules.soc2.manual_presence.v1
import rego.v1

result := {"status": "pass", "violations": []} if {
	rec := input.slots.review_document[0]
	rec.payload.file_present == true
	rec.payload.in_temporal_window == true
} else := {"status": "fail", "violations": [{
	"resource_id": input.slots.review_document[0].id,
	"reason": "manual evidence missing or outside temporal window — see expected_uri in vault"
}]}
`
	r, err := evaluator.NewRegoRule(ruleIDManualPresence, module, "data.rules.soc2.manual_presence.v1.result")
	if err != nil {
		// Compile-time bug in the framework's own rule — panic at
		// package init so the test suite surfaces it loudly.
		panic("soc2: manual presence rule failed to prepare: " + err.Error())
	}
	return r
}

func dedupeByIdentity(records []core.EvidenceRecord) []core.EvidenceRecord {
	seen := make(map[string]struct{}, len(records))
	out := make([]core.EvidenceRecord, 0, len(records))
	for i := range records {
		r := records[i]
		key := r.IdentityKey
		if key == "" {
			out = append(out, r)
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}
	return out
}

func payloadBool(payload json.RawMessage, key string) (bool, error) {
	if len(payload) == 0 {
		return false, nil
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return false, err
	}
	v, ok := m[key].(bool)
	if !ok {
		return false, nil
	}
	return v, nil
}

func payloadString(payload json.RawMessage, key string) (string, error) {
	if len(payload) == 0 {
		return "", nil
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return "", err
	}
	if v, ok := m[key].(string); ok {
		return v, nil
	}
	return "", nil
}
