package planner

import (
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// resolveException returns the first non-expired exception whose
// policy field matches policyID. Wildcard suffixes (`soc2.cc8.*`)
// match by prefix. Expired exceptions are skipped; a caller wanting
// the warning surface can re-scan with the same logic.
func resolveException(policyID string, exceptions []spec.ExceptionConfig, now time.Time) *Exception {
	for i := range exceptions {
		e := &exceptions[i]
		if !exceptionMatchesPolicy(e.Policy, policyID) {
			continue
		}
		if exceptionExpired(e, now) {
			continue
		}
		return toException(e)
	}
	return nil
}

func exceptionMatchesPolicy(pattern, policyID string) bool {
	if pattern == policyID {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(policyID, prefix)
	}
	return false
}

func exceptionExpired(e *spec.ExceptionConfig, now time.Time) bool {
	if e.ExpiresAt == "" {
		return false
	}
	expires, err := time.Parse("2006-01-02", e.ExpiresAt)
	if err != nil {
		// The project_config validator already accepted the date; an
		// error here would be a programmer bug. Treat as not-expired so
		// the exception still applies; the configuration error would
		// have been caught upstream.
		return false
	}
	// End of the expiry day is inclusive — the exception is valid
	// through 23:59:59 of expires_at.
	endOfDay := expires.Add(24*time.Hour - time.Nanosecond)
	return now.After(endOfDay)
}

func toException(e *spec.ExceptionConfig) *Exception {
	state := core.PolicyStatus(e.State) // already validated to be waived|na
	return &Exception{
		State:           state,
		Reason:          e.Reason,
		ResourceID:      e.Scope.ResourceID,
		ResourcePattern: e.Scope.ResourcePattern,
		ApprovedBy:      e.ApprovedBy,
		ApprovedAt:      e.ApprovedAt,
		ExpiresAt:       e.ExpiresAt,
	}
}
