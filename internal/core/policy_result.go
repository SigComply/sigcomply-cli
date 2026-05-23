package core

// PolicyResult is the per-policy outcome with full fidelity — includes
// violation details and resource IDs. This shape is what L7 (vault)
// persists. L6 (aggregator) projects it into the privacy-bounded
// AggregatedPolicy before any cloud submission.
//
// PolicyResult is vault-side; nothing in this struct crosses the
// aggregation boundary directly.
type PolicyResult struct {
	PolicyID           string
	ControlID          string
	Status             PolicyStatus
	Severity           Severity
	Category           string
	EffectiveParams    map[string]any
	Violations         []Violation
	ResourcesEvaluated int
	ResourcesFailed    int
	EvidenceEnvelopes  []string
	RuleVersion        string
	Diag               map[string]any
}
