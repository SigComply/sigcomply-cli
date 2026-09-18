package core

import (
	"fmt"
	"strings"
)

// maxReasonLen caps the inline reason shown under a policy in the check
// summary and in a report row.
const maxReasonLen = 240

// ResultReason returns a concise, single-line reason for a fail or
// error result, suitable for inline display under the policy in the
// check summary and in the report's REASON column. Returns "" for any
// other status (pass/skip/na/…), so the caller prints nothing. It reads
// the first violation's reason (the manual-evidence "not found; expected
// files in: <path>" message lands here) or, for errors, the diagnostic
// recorded by the collector/evaluator. The full detail always remains in
// the vault result.json.
//
// This lives in core rather than in the orchestrator because two
// surfaces need the identical projection: `check`, which holds results
// in memory, and `sigcomply report`, which reads them back out of the
// vault. A report that explained an error differently from the run that
// produced it would be worse than one that stayed silent.
func ResultReason(r *PolicyResult) string {
	switch r.Status {
	case StatusError:
		for _, k := range []string{"collect_error", "rule_error", "reason"} {
			if v, ok := r.Diag[k].(string); ok && v != "" {
				return truncateReason(v)
			}
		}
		return "evaluation error (see the run's result.json in the vault)"
	case StatusPass:
		// A pass whose clauses examined nothing is the one pass worth
		// explaining: `all`/`none` are true of the empty set, so this
		// reads as green while having checked no resource at all.
		if slots := diagStrings(r.Diag, "vacuous_clauses"); len(slots) > 0 {
			return truncateReason(fmt.Sprintf("passed without examining any resource (slot(s) %s matched nothing) — verify this control is really in scope", strings.Join(slots, ", ")))
		}
		return ""
	case StatusFail:
		if len(r.Violations) > 0 && r.Violations[0].Reason != "" {
			reason := r.Violations[0].Reason
			if r.ResourcesFailed > 1 {
				return truncateReason(fmt.Sprintf("%d of %d resources failed, e.g. %s", r.ResourcesFailed, r.ResourcesEvaluated, reason))
			}
			return truncateReason(reason)
		}
		if r.ResourcesFailed > 0 {
			return fmt.Sprintf("%d of %d resources failed", r.ResourcesFailed, r.ResourcesEvaluated)
		}
		return "policy failed"
	default:
		return ""
	}
}

// diagStrings reads a string-list diagnostic out of Diag, tolerating
// both shapes the value legitimately takes.
//
// In-process (what `check` sees) the evaluator writes a real []string.
// Read back from the vault's result.json, Diag is map[string]any and the
// same value decodes as []any. Asserting only []string would work in
// `check` and silently produce nothing in `report` — the failure mode
// this helper exists to prevent.
func diagStrings(diag map[string]any, key string) []string {
	switch v := diag[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// truncateReason clamps a reason string to maxReasonLen runes, appending an
// ellipsis when it overflows, so one pathological violation message
// can't blow up the summary.
func truncateReason(s string) string {
	r := []rune(s)
	if len(r) <= maxReasonLen {
		return s
	}
	return string(r[:maxReasonLen]) + "…"
}
