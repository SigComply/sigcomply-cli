package planner

import (
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// resolveException returns the first non-expired exception declared for a
// policy (the entries already belong to one policy — the map key in
// PolicyConfig — so there is no policy matching here). Expired exceptions
// are skipped, so the policy goes back to failing normally once a waiver
// lapses. Returns nil when the policy has no live exception.
func resolveException(exceptions []spec.PolicyException, now time.Time) *Exception {
	for i := range exceptions {
		e := &exceptions[i]
		if exceptionExpired(e.ExpiresAt, now) {
			continue
		}
		return toException(e)
	}
	return nil
}

// resolveControlException returns a whole-policy N/A exception when any
// control the policy maps to is marked not_applicable in the project
// config. This is the control-level cascade: one Statement-of-
// Applicability exclusion at the control level applies to every policy
// under it. Control applicability takes precedence over policy-level
// waivers (the caller resolves this first). Returns nil when no mapped
// control is excluded.
func resolveControlException(policy *core.Policy, controls map[string]spec.ControlConfig) *Exception {
	if len(controls) == 0 {
		return nil
	}
	for i := range policy.Controls {
		cc, ok := controls[policy.Controls[i].ControlID]
		if !ok || cc.Applicability != "not_applicable" {
			continue
		}
		return &Exception{
			State:      core.StatusNA,
			Reason:     cc.Reason,
			ApprovedBy: cc.ApprovedBy,
		}
	}
	return nil
}

// exceptionExpired reports whether an ISO 8601 expiry date is in the
// past. An empty date never expires. The expiry day is inclusive — the
// exception is valid through 23:59:59 of expiresAt.
func exceptionExpired(expiresAt string, now time.Time) bool {
	if expiresAt == "" {
		return false
	}
	expires, err := time.Parse("2006-01-02", expiresAt)
	if err != nil {
		// The project_config validator already accepted the date; an
		// error here would be a programmer bug. Treat as not-expired so
		// the exception still applies.
		return false
	}
	// End of the expiry day is inclusive — valid through 23:59:59.
	endOfDay := expires.Add(24*time.Hour - time.Nanosecond)
	return now.After(endOfDay)
}

func toException(e *spec.PolicyException) *Exception {
	return &Exception{
		State:           core.PolicyStatus(e.State), // validated to be waived|na
		Reason:          e.Reason,
		ResourceID:      e.Scope.ResourceID,
		ResourcePattern: e.Scope.ResourcePattern,
		ApprovedBy:      e.ApprovedBy,
		ApprovedAt:      e.ApprovedAt,
		ExpiresAt:       e.ExpiresAt,
	}
}
