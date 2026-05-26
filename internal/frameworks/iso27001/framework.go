// Package iso27001 is the ISO/IEC 27001:2022 framework skeleton.
// It mirrors the SOC 2 skeleton's shape (framework.go + controls.go +
// representative policies) and is deliberately small: 5 representative
// policies tied to 5 Annex A controls, reusing the existing aws.iam
// and manual.pdf plugins so the skeleton lands without depending on
// future plugin work.
//
// The full ~30+ ISO 27001 policy catalog and an ISO 27001 manual
// catalog are post-M6 work; see
// docs/architecture/09-implementation-roadmap.md §Post-M6 work plan.
package iso27001

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
)

// FrameworkID is the registered identifier.
const FrameworkID = "iso27001"

// FrameworkVersion stamps every PolicyRef returned by this framework.
const FrameworkVersion = "iso27001-2022@0.1.0"

// Policy identifiers. ISO 27001 Annex A controls use lowercase
// dotted form for the policy ID prefix; the Control field on each
// Policy carries the canonical "ISO27001.A.X.Y" identifier.
const (
	PolicyMFAEnforced            = "iso27001.a.8.5.mfa_enforced"
	PolicyAccessReview           = "iso27001.a.5.18.access_review"
	PolicyPrivilegedAccessReview = "iso27001.a.8.2.privileged_access_review"
	PolicyEvidenceSigned         = "iso27001.a.8.24.evidence_signed"

	// PolicyCloudTrailLogging is the iso27001.a.8.16.cloudtrail_logging
	// policy. SKIPPED in this skeleton: the aws.cloudtrail plugin does
	// not yet exist (it lands with the post-M6 plugin set). When that
	// plugin arrives, this constant + a corresponding Policy/Rule pair
	// can be added without disturbing the rest of the framework. The
	// constant is exported only for documentation purposes so callers
	// know the policy ID is reserved.
	PolicyCloudTrailLogging = "iso27001.a.8.16.cloudtrail_logging"
)

// Framework is the in-process ISO 27001 framework.
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
		{PolicyID: PolicyPrivilegedAccessReview},
		{PolicyID: PolicyEvidenceSigned},
	}
}

// Register populates the rule and policy registries with the ISO
// 27001 skeleton's rules and policies. Sources and evidence types are
// registered by the orchestrator alongside this call (the same way
// the SOC 2 skeleton is wired).
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
// needs for ISO 27001. The skeleton ships one entry — the A.5.18
// access review — to match the single manual policy. Full ISO 27001
// manual-catalog coverage is post-M6 work.
func ManualCatalog() map[string]manual.CatalogEntry {
	return map[string]manual.CatalogEntry{
		"iso27001_access_review": {
			EvidenceID:   "iso27001_access_review",
			Filename:     "evidence.pdf",
			Cadence:      "quarterly",
			TemporalRule: "retrospective",
			GracePeriod:  15 * 24 * time.Hour,
		},
	}
}

// Policies returns the seed policies. Each policy maps to an Annex A
// control. The two MFA-related policies (A.8.5 and A.8.2) share the
// aws.iam → user_record evidence stream but apply different rules.
func Policies() []core.Policy {
	return []core.Policy{
		{
			ID:           PolicyMFAEnforced,
			Control:      "ISO27001.A.8.5",
			Description:  "Secure authentication: every active user across every bound directory has MFA enabled.",
			Remediation:  "Enable MFA for the listed users in each affected directory source.",
			Severity:     core.SeverityHigh,
			Category:     "access",
			Cadence:      "daily",
			OnPush:       true,
			EvidenceMode: core.EvidenceModeAutomated,
			Slots: map[string]core.Slot{
				"user_directory": {Accepts: []string{"directory_user"}, Cardinality: core.SlotOneOrMore, Required: true, Description: "Directory users across all bound sources"},
			},
			RuleRef: ruleIDMFAEnforced,
		},
		{
			ID:           PolicyAccessReview,
			Control:      "ISO27001.A.5.18",
			Description:  "Quarterly access-rights review has been performed and signed.",
			Remediation:  "Conduct the quarterly access-rights review and upload the signed PDF to the configured manual-evidence bucket.",
			Severity:     core.SeverityMedium,
			Category:     "access",
			Cadence:      "quarterly",
			OnPush:       false,
			EvidenceMode: core.EvidenceModeManual,
			CatalogEntry: "iso27001_access_review",
		},
		{
			ID:           PolicyPrivilegedAccessReview,
			Control:      "ISO27001.A.8.2",
			Description:  "Privileged (admin) users across every bound directory have MFA enabled.",
			Remediation:  "For each listed admin user, either enable MFA or revoke admin access.",
			Severity:     core.SeverityHigh,
			Category:     "access",
			Cadence:      "daily",
			OnPush:       true,
			EvidenceMode: core.EvidenceModeAutomated,
			Slots: map[string]core.Slot{
				"user_directory": {Accepts: []string{"directory_user"}, Cardinality: core.SlotOneOrMore, Required: true},
			},
			RuleRef: ruleIDPrivilegedMFA,
		},
		{
			ID:           PolicyEvidenceSigned,
			Control:      "ISO27001.A.8.24",
			Description:  "Use of cryptography: the CLI's per-run signing infrastructure is operational (self-attestation — a synthetic manifest is signed and verified each run).",
			Remediation:  "Investigate the failing Ed25519 signing path. If this rule fails, the build is broken — open an issue against sigcomply-cli.",
			Severity:     core.SeverityMedium,
			Category:     "crypto",
			Cadence:      "daily",
			OnPush:       true,
			EvidenceMode: core.EvidenceModeAutomated,
			// No slots: this is a meta-policy. The rule exercises
			// sign.Manifest + sign.VerifyManifest against a synthetic
			// manifest to prove the signing path is intact for this
			// run. It does not consume any collected evidence.
			Slots:   map[string]core.Slot{},
			RuleRef: ruleIDEvidenceSigned,
		},
	}
}

// Rules returns the rule implementations registered by Register.
func Rules() []core.Rule {
	return []core.Rule{
		mfaEnforcedRule(),
		manualPresenceRule(),
		privilegedMFARule(),
		evidenceSignedRule(),
	}
}

const (
	ruleIDMFAEnforced    = "rules.iso27001.mfa_enforced.v1"
	ruleIDManualPresence = "rules.iso27001.manual_presence.v1"
	ruleIDPrivilegedMFA  = "rules.iso27001.privileged_mfa.v1"
	ruleIDEvidenceSigned = "rules.iso27001.evidence_signed.v1"
)

// mfaEnforcedRule is the A.8.5 rule: every active directory_user in
// the user_directory slot must have payload.mfa_enabled == true.
// Non-active accounts (is_active explicitly false) are skipped — they
// cannot sign in, so flagging their MFA state would be noise. Mirrors
// the SOC 2 source-agnostic MFA rule shape.
func mfaEnforcedRule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDMFAEnforced,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := dedupeByIdentity(in.Slots["user_directory"])
			violations := make([]core.Violation, 0)
			for i := range records {
				r := &records[i]
				if !isActiveOrUnknown(r.Payload) {
					continue
				}
				mfa, err := payloadBool(r.Payload, "mfa_enabled")
				if err != nil {
					return core.RuleResult{}, err
				}
				if mfa {
					continue
				}
				label, err := payloadString(r.Payload, "display_name")
				if err != nil {
					return core.RuleResult{}, err
				}
				if label == "" {
					label = r.ID
				}
				violations = append(violations, core.Violation{
					ResourceID: r.ID,
					Reason:     "MFA disabled for " + label,
				})
			}
			status := core.StatusPass
			if len(violations) > 0 {
				status = core.StatusFail
			}
			return core.RuleResult{Status: status, Violations: violations}, nil
		},
	}
}

// privilegedMFARule is the A.8.2 rule: every directory_user marked
// `is_admin: true` must also have `mfa_enabled: true`. Non-admin
// users are ignored — A.8.5 covers them. Inactive admins are skipped
// for the same reason as A.8.5 (cannot sign in → no MFA risk today).
func privilegedMFARule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDPrivilegedMFA,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			records := dedupeByIdentity(in.Slots["user_directory"])
			violations := make([]core.Violation, 0)
			for i := range records {
				r := &records[i]
				if !isActiveOrUnknown(r.Payload) {
					continue
				}
				isAdmin, err := payloadBool(r.Payload, "is_admin")
				if err != nil {
					return core.RuleResult{}, err
				}
				if !isAdmin {
					continue
				}
				mfa, err := payloadBool(r.Payload, "mfa_enabled")
				if err != nil {
					return core.RuleResult{}, err
				}
				if mfa {
					continue
				}
				label, err := payloadString(r.Payload, "display_name")
				if err != nil {
					return core.RuleResult{}, err
				}
				if label == "" {
					label = r.ID
				}
				violations = append(violations, core.Violation{
					ResourceID: r.ID,
					Reason:     "admin user " + label + " has MFA disabled",
				})
			}
			status := core.StatusPass
			if len(violations) > 0 {
				status = core.StatusFail
			}
			return core.RuleResult{Status: status, Violations: violations}, nil
		},
	}
}

// isActiveOrUnknown returns true when the directory_user payload omits
// is_active or sets it true. Explicit false → skip the record.
// Duplicated across frameworks per the KISS-no-DRY axiom; sharing
// would couple the two frameworks via a helper package.
func isActiveOrUnknown(payload json.RawMessage) bool {
	if len(payload) == 0 {
		return true
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return true
	}
	raw, present := m["is_active"]
	if !present {
		return true
	}
	v, ok := raw.(bool)
	if !ok {
		return true
	}
	return v
}

// manualPresenceRule is the A.5.18 rule (Rego): passes iff the
// signed_document payload reports file_present, in_temporal_window,
// and file_valid all true. file_valid is set by the manual.pdf plugin
// from cheap sanity checks (size + PDF magic bytes); validation_failures
// in the payload names the specific check that failed. Mirrors the
// SOC 2 manual-presence rule shape exactly.
func manualPresenceRule() core.Rule {
	const module = `
package rules.iso27001.manual_presence.v1
import rego.v1

result := {"status": "pass", "violations": []} if {
	rec := input.slots.review_document[0]
	rec.payload.file_present == true
	rec.payload.in_temporal_window == true
	rec.payload.file_valid == true
} else := {"status": "fail", "violations": [{
	"resource_id": input.slots.review_document[0].id,
	"reason": "manual evidence missing, invalid, or outside temporal window — see expected_uri and validation_failures in vault"
}]}
`
	r, err := evaluator.NewRegoRule(ruleIDManualPresence, module, "data.rules.iso27001.manual_presence.v1.result")
	if err != nil {
		// Compile-time bug in the framework's own rule — panic at
		// package init so the test suite surfaces it loudly.
		panic("iso27001: manual presence rule failed to prepare: " + err.Error())
	}
	return r
}

// evidenceSignedRule is the A.8.24 meta-policy rule. It produces a
// tiny synthetic manifest, signs it with the same sign.Manifest path
// the orchestrator uses for the per-run manifest, then verifies it
// with sign.VerifyManifest. A passing result asserts that the
// Ed25519 signing infrastructure is intact for this run.
//
// This is a self-attestation: the policy does not read any collected
// evidence, and it always passes unless the signing path is broken
// (in which case the build would fail elsewhere too).
func evidenceSignedRule() core.Rule {
	return &evaluator.GoRule{
		IDValue: ruleIDEvidenceSigned,
		Fn: func(_ context.Context, in core.RuleInput) (core.RuleResult, error) {
			now := in.Now
			if now.IsZero() {
				now = time.Now().UTC()
			}
			m := &core.Manifest{
				SchemaVersion: "manifest.v1",
				RunID:         "iso27001-a-8-24-self-attest",
				StartedAt:     now,
				CompletedAt:   now,
				FileHashes:    map[string]string{},
			}
			if err := sign.Manifest(m); err != nil {
				// Sign failure is an evaluator-level error, not a
				// policy fail: it means the signing infrastructure is
				// broken (not that the customer's environment is
				// non-compliant). Surface as an error so the evaluator
				// marks status=error.
				return core.RuleResult{}, fmt.Errorf("self-attest: sign.Manifest: %w", err)
			}
			if err := sign.VerifyManifest(m); err != nil {
				return core.RuleResult{}, fmt.Errorf("self-attest: sign.VerifyManifest: %w", err)
			}
			return core.RuleResult{Status: core.StatusPass, Violations: []core.Violation{}}, nil
		},
	}
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
