// Package report implements `sigcomply report`: the read-only,
// auditor-facing snapshot tool. It walks a vault's
// {framework}/{period_id}/run_*/ tree and produces deterministic
// views of the data — no collection, no evaluation, no cloud calls.
//
// Five views ship today:
//
//   - latest: per-policy roll-up using the latest run that produced a
//     result for each policy. Answers "what was the state at period close?"
//   - exceptions: every waiver/NA in effect during the period,
//     pulled from each run manifest's exceptions_applied table.
//   - integrity: per-run signature + file-hash verification.
//   - scope: the declared estate and how it fared, plus every control the
//     run did not evaluate. Answers "did this run look at everything?"
//   - coverage: per control, whether it is verified by inspecting
//     infrastructure or merely by a document being on file, and whether
//     that evidence exists this period. Answers "what is behind the green?"
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
	ViewScope      View = "scope"
	ViewCoverage   View = "coverage"
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
	Scope      *ScopeView      `json:",omitempty"`
	Coverage   *CoverageView   `json:",omitempty"`
}

// CoverageView answers the question a compliance score cannot: what is
// actually behind the green?
//
// The score is a pass rate over the policies that ran, and a policy
// satisfied by a document sitting in a folder counts exactly as much as
// one that inspected live infrastructure. That arithmetic is defensible;
// as a headline it is not, because the two are not the same claim. This
// view separates them.
//
// It is framework-scoped, not run-scoped, and deliberately so. Cadences
// are independent of the audit period: a framework whose manual policies
// are annual produces no result at all for those controls in three
// quarters out of four. A view built only from what the period folder
// contains would show those controls as neither passing nor failing but
// simply absent — reproducing, in a new place, the exact blind spot it
// exists to close. So every declared control gets a row, and the row says
// what happened to it in this period, including "nothing".
type CoverageView struct {
	// Controls/Automated/Manual/Uncovered describe the framework itself
	// and do not vary by period.
	Controls  int
	Automated int
	Manual    int
	Uncovered int

	// Evaluated counts controls with at least one policy result in this
	// period. NotEvaluated is the rest — see the type doc for why that
	// is routine rather than alarming for a supra-period cadence.
	Evaluated    int
	NotEvaluated int

	// ManualOnFile and ManualMissing split the manual-assurance controls
	// by whether their document actually exists for this period.
	ManualOnFile  int
	ManualMissing int

	// Overridden counts controls a project reconfigured away from the
	// framework's declared evidence mode — nearly always an automated
	// check downgraded to a document upload.
	Overridden int

	// Rows is one entry per declared control, sorted by control ID.
	Rows []CoverageRow
}

// CoverageRow is one control and what stands behind it.
type CoverageRow struct {
	ControlID string
	// Assurance is "automated", "manual" or "none" — the strongest check
	// behind this control. Where a run recorded its own evidence mode,
	// that wins over the framework's declaration, so a project override
	// is reflected rather than papered over.
	Assurance string
	// AutomatedPolicies and ManualPolicies give the mix the single
	// Assurance label hides: one automated check plus four documents is
	// "automated", and a reader deciding where to spend the next month
	// deserves to see the four.
	AutomatedPolicies int
	ManualPolicies    int
	// Evaluated is how many of this control's policies produced a result
	// in this period; Policies is how many exist.
	Evaluated int
	Policies  int
	// Status is the roll-up over this period's results — the worst of
	// them, or "not evaluated" when there are none.
	Status string
	// Overridden marks a control whose evidence mode the project changed.
	Overridden bool
	// Note explains a row that needs it: why nothing ran, or what an
	// error said.
	Note string
}

// ScopeView answers "what was this run supposed to cover, and did it?"
//
// Two independent things live here because they answer the same auditor
// question from opposite ends. Sources is the estate the operator
// declared and how each declared entry actually fared — present only for
// projects that opted in by declaring one. Skipped is every control the
// run did not evaluate, with the reason, which is available for every
// project whether or not an estate was declared.
//
// The second matters on its own: a skipped control leaves the
// compliance-score denominator entirely, so a run can go green while
// quietly evaluating nothing.
type ScopeView struct {
	// Declared reports whether the run carried an estate declaration.
	// False for runs written before scope existed, and for projects that
	// have not opted in.
	Declared bool
	// Status is the run-level verdict: complete, incomplete, or empty
	// when nothing was declared.
	Status string
	// DeclaredBy/DeclaredAt are the operator's audit trail.
	DeclaredBy string
	DeclaredAt string
	// RunID is the run this verdict came from — the latest in the period.
	RunID string

	// Sources is one row per declared source, sorted by ID.
	Sources []ScopeSource
	// Skipped is one row per unevaluated control, sorted by policy ID.
	Skipped []SkippedPolicy
}

// ScopeSource is one declared source and how it fared.
type ScopeSource struct {
	SourceID string
	State    string
}

// SkippedPolicy is one control the run did not evaluate.
type SkippedPolicy struct {
	PolicyID string
	Status   string
	Reason   string
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
	// Reason is the one-line explanation for a fail or error, the same
	// projection `check` prints inline. Empty for a plain pass. Without
	// it this view showed a bare "error" with the diagnostic stranded in
	// the vault's result.json, which is the least useful place for it.
	// Full detail still lives there.
	Reason string
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
