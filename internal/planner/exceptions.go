package planner

import (
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// resolveExceptions returns every non-expired exception declared for a
// policy, in declared order (the entries already belong to one policy —
// the map key in PolicyConfig — so there is no policy matching here).
// Each scoped entry waives its own resources, so a policy can carry one
// waiver per legacy resource. An entry with no scope decides the whole
// result, so the first such entry is returned alone. Expired exceptions
// are skipped, so the policy goes back to failing normally once a waiver
// lapses. Returns nil when the policy has no live exception.
func resolveExceptions(exceptions []spec.PolicyException, now time.Time) []*Exception {
	var live []*Exception
	for i := range exceptions {
		e := &exceptions[i]
		if exceptionExpired(e.ExpiresAt, now) {
			continue
		}
		if e.Scope.ResourceID == "" && e.Scope.ResourcePattern == "" {
			return []*Exception{toException(e)}
		}
		live = append(live, toException(e))
	}
	return live
}

// resolveControlException returns a whole-policy N/A exception when
// every control the policy maps to is marked not_applicable in the
// project config. This is the control-level cascade: one Statement-of-
// Applicability exclusion applies to every policy that serves only
// excluded controls. A policy filed under two controls still runs while
// one of them is in scope, since that control relies on it. Control
// applicability takes precedence over policy-level waivers (the caller
// resolves this first). The reason and approver come from the first
// mapped control. Returns nil when any mapped control is in scope.
func resolveControlException(policy *core.Policy, controls map[string]spec.ControlConfig) *Exception {
	if len(controls) == 0 || len(policy.Controls) == 0 {
		return nil
	}
	var first *spec.ControlConfig
	for i := range policy.Controls {
		cc, ok := controls[policy.Controls[i].ControlID]
		if !ok || cc.Applicability != "not_applicable" {
			return nil
		}
		if first == nil {
			first = &cc
		}
	}
	return &Exception{
		State:      core.StatusNA,
		Reason:     first.Reason,
		ApprovedBy: first.ApprovedBy,
	}
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
