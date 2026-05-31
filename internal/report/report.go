package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
)

// ErrUnknownView is returned by Build when an unknown view string is
// passed. Sentinel so callers can distinguish "configuration error" from
// "vault read error".
var ErrUnknownView = fmt.Errorf("report: unknown view")

// Input is the parameter bundle for Build. Vault is read-only; Build
// never writes.
type Input struct {
	Vault     core.Vault
	Framework string
	PeriodID  string
	View      View
}

// Build walks the vault for the requested {framework}/{period_id}
// subtree and returns a Snapshot for the chosen view.
//
// Build is strictly read-only: it lists run folders, parses each
// manifest, and (for the latest view) reads per-policy result.json
// files. It never writes, never opens network connections, and never
// requires OIDC.
func Build(ctx context.Context, in *Input) (*Snapshot, error) {
	if in == nil {
		return nil, fmt.Errorf("report: nil Input")
	}
	if in.Vault == nil {
		return nil, fmt.Errorf("report: nil Vault")
	}
	if in.Framework == "" {
		return nil, fmt.Errorf("report: Framework required")
	}
	if in.PeriodID == "" {
		return nil, fmt.Errorf("report: PeriodID required")
	}

	view := in.View
	if view == "" {
		view = ViewLatest
	}

	runs, err := loadRuns(ctx, in.Vault, in.Framework, in.PeriodID)
	if err != nil {
		return nil, err
	}

	snap := &Snapshot{View: view, Framework: in.Framework, PeriodID: in.PeriodID}
	switch view {
	case ViewLatest:
		v, err := buildLatest(ctx, in.Vault, runs)
		if err != nil {
			return nil, err
		}
		snap.Latest = v
	case ViewExceptions:
		snap.Exceptions = buildExceptions(runs)
	case ViewIntegrity:
		snap.Integrity = buildIntegrity(ctx, in.Vault, runs)
	default:
		return nil, fmt.Errorf("%w: %q (want latest|exceptions|integrity)", ErrUnknownView, in.View)
	}
	return snap, nil
}

// runRecord is the internal per-run bundle: the manifest and the run's
// vault path (key prefix). A manifest that failed to parse leaves the
// Manifest field zero-valued — the integrity view treats that as a
// per-run failure rather than dropping the row entirely.
type runRecord struct {
	Path     string // e.g. "soc2/2026-Q1/run_20260215T140000Z_a3f8b2c1"
	Manifest core.Manifest
}

// loadRuns lists the period folder, parses each run's manifest, and
// returns the runs sorted by manifest.completed_at ascending (then by
// path for stability). A run with a missing or malformed manifest is
// retained with a zero-valued Manifest so the integrity view can still
// report it.
func loadRuns(ctx context.Context, v core.Vault, framework, periodID string) ([]runRecord, error) {
	prefix := fmt.Sprintf("%s/%s/", framework, periodID)
	keys, err := v.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("report: list %s: %w", prefix, err)
	}
	runPaths := uniqueRunFolders(keys, prefix)

	out := make([]runRecord, 0, len(runPaths))
	for _, runPath := range runPaths {
		manifestKey := runPath + "/manifest.json"
		body, err := v.GetBinary(ctx, manifestKey)
		if err != nil {
			out = append(out, runRecord{Path: runPath})
			continue
		}
		var manifest core.Manifest
		if err := json.Unmarshal(body, &manifest); err != nil {
			out = append(out, runRecord{Path: runPath})
			continue
		}
		out = append(out, runRecord{Path: runPath, Manifest: manifest})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Manifest.CompletedAt.Equal(out[j].Manifest.CompletedAt) {
			return out[i].Manifest.CompletedAt.Before(out[j].Manifest.CompletedAt)
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

// uniqueRunFolders extracts the unique run-folder paths (under the
// given period prefix) from a flat list of vault keys. Vault.List
// returns leaf objects under a prefix, so we deduplicate to the
// `run_XXX` directory level here.
func uniqueRunFolders(keys []string, periodPrefix string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, k := range keys {
		rest := strings.TrimPrefix(k, periodPrefix)
		if rest == k {
			continue
		}
		slash := strings.Index(rest, "/")
		if slash < 0 {
			continue
		}
		folder := rest[:slash]
		if !strings.HasPrefix(folder, "run_") {
			continue
		}
		full := periodPrefix + folder
		if _, dup := seen[full]; dup {
			continue
		}
		seen[full] = struct{}{}
		out = append(out, full)
	}
	sort.Strings(out)
	return out
}

// buildLatest implements the latest-wins roll-up. For each policy_id
// appearing across any run, the row reflects the latest run (by
// manifest.completed_at, ties broken by run path) that produced a
// result.json for that policy.
func buildLatest(ctx context.Context, v core.Vault, runs []runRecord) (*LatestView, error) {
	type latestEntry struct {
		policy      core.PolicyResult
		completedAt time.Time
		runID       string
	}
	byPolicy := map[string]latestEntry{}

	for i := range runs {
		r := &runs[i]
		if r.Manifest.RunID == "" {
			continue
		}
		policyResults, err := listPolicyResults(ctx, v, r.Path)
		if err != nil {
			return nil, err
		}
		for policyID, body := range policyResults {
			var pr core.PolicyResult
			if err := json.Unmarshal(body, &pr); err != nil {
				continue
			}
			prev, exists := byPolicy[policyID]
			if !exists || r.Manifest.CompletedAt.After(prev.completedAt) || r.Manifest.CompletedAt.Equal(prev.completedAt) {
				byPolicy[policyID] = latestEntry{
					policy:      pr,
					completedAt: r.Manifest.CompletedAt,
					runID:       r.Manifest.RunID,
				}
			}
		}
	}

	// Any exception ever applied to a policy gets flagged on its latest
	// row — the exceptions view is the lookup table for details.
	exceptionsByPolicy := map[string]struct{}{}
	for i := range runs {
		excs := runs[i].Manifest.ExceptionsApplied
		for j := range excs {
			exceptionsByPolicy[excs[j].PolicyID] = struct{}{}
		}
	}

	out := &LatestView{Policies: make([]LatestPolicy, 0, len(byPolicy))}
	for policyID := range byPolicy {
		e := byPolicy[policyID]
		row := LatestPolicy{
			PolicyID:      policyID,
			ControlID:     core.PrimaryControlID(e.policy.Controls),
			Status:        string(e.policy.Status),
			Severity:      string(e.policy.Severity),
			Category:      e.policy.Category,
			LastEvaluated: e.completedAt.UTC(),
			RunID:         e.runID,
		}
		if _, hasExc := exceptionsByPolicy[policyID]; hasExc {
			row.ExceptionID = policyID
		}
		out.Policies = append(out.Policies, row)
	}
	sort.Slice(out.Policies, func(i, j int) bool { return out.Policies[i].PolicyID < out.Policies[j].PolicyID })
	return out, nil
}

// listPolicyResults returns policy_id → raw result.json bytes for every
// policy folder under <runPath>/policies/. Missing files are skipped
// (a run that errored out before writing some results is still readable).
func listPolicyResults(ctx context.Context, v core.Vault, runPath string) (map[string][]byte, error) {
	prefix := runPath + "/policies/"
	keys, err := v.List(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("report: list %s: %w", prefix, err)
	}
	out := map[string][]byte{}
	for _, k := range keys {
		if !strings.HasSuffix(k, "/result.json") {
			continue
		}
		rest := strings.TrimPrefix(k, prefix)
		slash := strings.Index(rest, "/")
		if slash < 0 {
			continue
		}
		policyID := rest[:slash]
		body, err := v.GetBinary(ctx, k)
		if err != nil {
			continue
		}
		out[policyID] = body
	}
	return out, nil
}

// buildExceptions assembles the exception register, deduplicating
// across runs by (policy_id, resource_id, resource_pattern). The first
// and last run that reference each exception are recorded so an
// auditor can see the activation/last-seen window.
func buildExceptions(runs []runRecord) *ExceptionsView {
	type key struct {
		policy   string
		resource string
		pattern  string
	}
	seen := map[key]*ExceptionEntry{}
	order := make([]key, 0)

	for i := range runs {
		r := &runs[i]
		excs := r.Manifest.ExceptionsApplied
		for j := range excs {
			e := &excs[j]
			k := key{policy: e.PolicyID, resource: e.ResourceID, pattern: e.ResourcePattern}
			if entry, ok := seen[k]; ok {
				entry.LastSeenRunID = r.Manifest.RunID
				continue
			}
			entry := &ExceptionEntry{
				PolicyID:       e.PolicyID,
				State:          e.State,
				Scope:          exceptionScopeLabel(e),
				ApprovedBy:     e.ApprovedBy,
				ApprovedAt:     e.ApprovedAt,
				ExpiresAt:      e.ExpiresAt,
				Reason:         e.Reason,
				FirstSeenRunID: r.Manifest.RunID,
				LastSeenRunID:  r.Manifest.RunID,
			}
			seen[k] = entry
			order = append(order, k)
		}
	}

	out := &ExceptionsView{Exceptions: make([]ExceptionEntry, 0, len(order))}
	for _, k := range order {
		out.Exceptions = append(out.Exceptions, *seen[k])
	}
	sort.Slice(out.Exceptions, func(i, j int) bool {
		if out.Exceptions[i].PolicyID != out.Exceptions[j].PolicyID {
			return out.Exceptions[i].PolicyID < out.Exceptions[j].PolicyID
		}
		return out.Exceptions[i].Scope < out.Exceptions[j].Scope
	})
	return out
}

func exceptionScopeLabel(e *core.AppliedException) string {
	if e.ResourceID != "" {
		return e.ResourceID
	}
	if e.ResourcePattern != "" {
		return e.ResourcePattern
	}
	return "policy"
}

// buildIntegrity verifies every run's manifest signature, then
// recomputes SHA-256 of each file under file_hashes and compares. Output
// is one row per run, sorted by run path (which sorts by timestamp in
// ISO 8601 basic form so the output is reproducible).
func buildIntegrity(ctx context.Context, v core.Vault, runs []runRecord) *IntegrityView {
	out := &IntegrityView{Runs: make([]IntegrityRow, 0, len(runs))}
	for i := range runs {
		r := &runs[i]
		row := IntegrityRow{
			RunPath:     r.Path,
			RunID:       r.Manifest.RunID,
			CompletedAt: r.Manifest.CompletedAt.UTC(),
			FilesTotal:  len(r.Manifest.FileHashes),
		}
		if r.Manifest.RunID == "" {
			row.Error = "manifest missing or unparseable"
			out.Runs = append(out.Runs, row)
			continue
		}
		if err := sign.VerifyManifest(&r.Manifest); err != nil {
			row.SignatureValid = false
			row.Error = "signature verification failed: " + err.Error()
			out.Runs = append(out.Runs, row)
			continue
		}
		row.SignatureValid = true
		// Sort hash table keys so the first mismatch we report is
		// deterministic across runs.
		paths := make([]string, 0, len(r.Manifest.FileHashes))
		for p := range r.Manifest.FileHashes {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, rel := range paths {
			want := r.Manifest.FileHashes[rel]
			body, err := v.GetBinary(ctx, r.Path+"/"+rel)
			if err != nil {
				row.FirstMismatchPath = rel
				row.Error = "file missing: " + err.Error()
				break
			}
			got := "sha256:" + sha256Hex(body)
			if got != want {
				row.FirstMismatchPath = rel
				row.Error = "hash mismatch"
				break
			}
			row.FilesVerified++
		}
		out.Runs = append(out.Runs, row)
	}
	sort.Slice(out.Runs, func(i, j int) bool { return out.Runs[i].RunPath < out.Runs[j].RunPath })
	return out
}

func sha256Hex(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}
