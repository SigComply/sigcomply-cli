package iso27001

import "github.com/sigcomply/sigcomply-cli/internal/core"

// changeEvidencePolicies — A.8.32 change management, evidenced from the
// changes themselves rather than from the guardrail configured around
// them. The A.8.32 policies in policies_8_technological.go read
// git_repository: they answer "is review required?". These read
// pull_request and deployment: they answer "did the changes that actually
// shipped get reviewed?". Both are needed — a protection setting can be
// bypassed by an admin, disabled and re-enabled between runs, or simply
// not apply to everyone, none of which a configuration snapshot shows.
//
// Deliberate KISS-no-DRY duplicate of the soc2 package's equivalent: the
// two frameworks are kept independently readable.
func changeEvidencePolicies() []core.Policy {
	return []core.Policy{
		autoPolicy{
			id: "iso27001.8.32.changes_independently_approved", control: ctrlChangeManagement, severity: core.SeverityHigh, category: catChangeManagement, cadence: cadenceDaily,
			accepts: []string{etPullRequest},
			desc:    "Every change merged during the period was approved by someone other than its author.",
			rem:     "Require an independent approval before merge. For a change that legitimately merged without one (a production hotfix, an automated dependency bump), record a scoped exception naming the change.",
			clause:  all(leaf("payload.independent_approval_count", "gte", 1), "change {{.payload.repository}}#{{.payload.number}} by {{.payload.author}} was merged without an independent approval"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.32.changes_passed_checks", control: ctrlChangeManagement, severity: core.SeverityMedium, category: catChangeManagement, cadence: cadenceDaily,
			accepts: []string{etPullRequest},
			desc:    "Every change merged during the period passed its automated checks.",
			rem:     "Require status checks to pass before merge, and ensure each repository runs at least one check.",
			clause:  all(leaf("payload.checks_passed", "eq", true), "change {{.payload.repository}}#{{.payload.number}} was merged without passing automated checks"),
		}.policy(),
		autoPolicy{
			id: "iso27001.8.32.approval_precedes_merge", control: ctrlChangeManagement, severity: core.SeverityHigh, category: catChangeManagement, cadence: cadenceDaily,
			accepts: []string{etPullRequest},
			desc:    "Approvals were recorded before the merge, not after it.",
			rem:     "Approve changes before merging them. An approval added after the fact does not evidence review of what shipped.",
			// Scoped to changes carrying an independent approval; one with
			// none is already reported by changes_independently_approved.
			clause: allWhere(leaf("payload.independent_approval_count", "gte", 1), leaf("payload.approved_before_merge", "eq", true), "change {{.payload.repository}}#{{.payload.number}} was approved only after it had already been merged"),
		}.policy(),
		{
			ID:           "iso27001.8.32.production_deploys_from_approved_changes",
			Controls:     controlRefs(ctrlChangeManagement),
			Description:  "Every production deployment during the period shipped an independently approved change.",
			Remediation:  "Deploy to production only from the reviewed branch, so each release traces back to an approved change. A deployment of a commit with no corresponding approved change is an unreviewed production release.",
			Severity:     core.SeverityHigh,
			Category:     catChangeManagement,
			Cadence:      cadenceDaily,
			OnPush:       true,
			EvidenceMode: core.EvidenceModeAutomated,
			Slots: map[string]core.Slot{
				"deployments": {Accepts: []string{"deployment"}, Cardinality: core.SlotOneOrMore, Required: true, Description: "deployments performed during the period"},
				"changes":     {Accepts: []string{etPullRequest}, Cardinality: core.SlotOneOrMore, Required: true, Description: "changes merged during the period"},
			},
			// Traceability, not segregation of duties between merger and
			// deployer: comparing two fields across two slots is not
			// expressible in the DSL, and matches_in tests membership only.
			// An empty join key is skipped rather than matched loosely, so a
			// vendor reporting no merge commit fails closed.
			PassWhen: &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
				Slot:       "deployments",
				Quantifier: core.QuantifierAll,
				Filter:     leaf("payload.is_production", "eq", true),
				Condition: &core.PassWhenCondition{
					Op:          core.OpMatchesIn,
					Field:       "payload.commit_sha",
					InSlot:      "changes",
					RemoteField: "payload.merge_commit_sha",
					Where:       leaf("payload.independent_approval_count", "gte", 1),
				},
				ViolationMsg: "production deployment {{.payload.deployment_id}} of {{.payload.repository}} shipped commit {{.payload.commit_sha}}, which does not trace to an independently approved change",
			}}},
		},
	}
}
