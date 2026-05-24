// Package report implements `sigcomply report`: the read-only,
// auditor-facing snapshot tool. It walks a vault's
// {framework}/{period_id}/run_*/ tree and produces deterministic
// views of the data — no collection, no evaluation, no cloud calls.
//
// Three views ship in v1-alpha (see docs/architecture/09-implementation-
// roadmap.md §`sigcomply report`):
//
//   - latest: per-policy roll-up using the latest run that produced a
//     result for each policy. Answers "what was the state at period close?"
//   - exceptions: every waiver/NA in effect during the period,
//     pulled from each run manifest's exceptions_applied table.
//   - integrity: per-run signature + file-hash verification.
//
// Each view is independently structured and independently formattable
// (text, json, csv). PDF is deferred to v1.x — the formatter layer
// returns a clear error rather than emit a half-rendered document.
//
// Determinism is a hard requirement: the same vault state must produce
// byte-identical output across invocations, modulo any "generated_at"
// timestamp the CLI command stamps outside the snapshot's content.
// Snapshot views sort every list by a stable key (policy_id, run path,
// etc.) before serializing.
package report

import "time"

// View names the requested snapshot kind. Surfaced as the --view flag
// on the CLI.
type View string

// Supported views. See package doc for the auditor question each
// answers.
const (
	ViewLatest     View = "latest"
	ViewExceptions View = "exceptions"
	ViewIntegrity  View = "integrity"
)

// Snapshot is the top-level result of Build. Exactly one of the
// per-view sub-structs is populated based on the requested view;
// the other fields are zero-valued.
//
// GeneratedAt is excluded from the formatted body — it lives on the
// header that the CLI command stamps separately so tests can assert
// byte-identical content across invocations.
type Snapshot struct {
	View      View
	Framework string
	PeriodID  string

	Latest     *LatestView     `json:",omitempty"`
	Exceptions *ExceptionsView `json:",omitempty"`
	Integrity  *IntegrityView  `json:",omitempty"`
}

// LatestView is the latest-wins per-policy roll-up for the period. One
// row per policy that appears in any run in the period folder; for
// policies that appear in multiple runs, the row reflects the latest
// run (by manifest.completed_at) that produced a result for that policy.
type LatestView struct {
	Policies []LatestPolicy
}

// LatestPolicy is one row of the latest-wins view.
type LatestPolicy struct {
	PolicyID      string
	ControlID     string
	Status        string
	Severity      string
	Category      string
	LastEvaluated time.Time
	RunID         string
	// ExceptionID, when non-empty, points at the policy_id of the
	// exception that suppressed this result (waived/na). The free-CLI
	// design uses the policy_id as the exception's primary key — the
	// exceptions view is the place to look up details.
	ExceptionID string
}

// ExceptionsView is the centralized register of every waiver/NA in
// effect during the period, deduplicated across runs by policy_id +
// resource_id + resource_pattern. The order of runs is preserved so
// readers can trace which run first/last applied a given exception.
type ExceptionsView struct {
	Exceptions []ExceptionEntry
}

// ExceptionEntry is one row of the exceptions register. Fields mirror
// core.AppliedException — duplicated here so the report's data model
// is self-contained and not coupled to the manifest schema.
type ExceptionEntry struct {
	PolicyID       string
	State          string
	Scope          string // resource_id, resource_pattern, or "policy"
	ApprovedBy     string
	ApprovedAt     string
	ExpiresAt      string
	Reason         string
	FirstSeenRunID string
	LastSeenRunID  string
}

// IntegrityView is the per-run signature + file-hash verification
// table. Rows are sorted by run path (which sorts by timestamp in
// ISO 8601 basic form) so the output is reproducible.
type IntegrityView struct {
	Runs []IntegrityRow
}

// IntegrityRow records the outcome of integrity verification for one
// run folder.
type IntegrityRow struct {
	RunPath           string
	RunID             string
	CompletedAt       time.Time
	SignatureValid    bool
	FilesVerified     int
	FilesTotal        int
	FirstMismatchPath string
	Error             string // populated when SignatureValid is false or a file is missing
}

// Status returns "pass" if the run's signature verifies and every
// file_hashes entry matched its recomputed SHA-256; "fail" otherwise.
// Centralizing the boolean → label mapping lets every formatter render
// the same word.
func (r *IntegrityRow) Status() string {
	if r.SignatureValid && r.FirstMismatchPath == "" && r.Error == "" {
		return "pass"
	}
	return "fail"
}
