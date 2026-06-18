// Package sourcetest is the shared test harness every source plugin's
// tests run through, so adding a plugin never means re-inventing test
// scaffolding. A plugin author feeds canned API responses in (via the
// plugin's own transport/fake seam) and gets schema-conformance,
// completeness, determinism, and metadata checks for free.
//
// It backs test layers L1, L2, and L4a described in
// docs/architecture/11-testing-strategy.md. WU-1.1 builds the conformance
// checks below; WU-1.2 adds go-vcr cassette wiring; WU-4.1 the live-gating
// helper. The harness has no network access of its own — it only drives a
// caller-built plugin (fake or cassette-backed).
package sourcetest

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

// Options configures a RunConformance run.
type Options struct {
	// Plugin is the source plugin under test, already constructed with its
	// canned API/cassette transport wired in by the caller.
	Plugin core.SourcePlugin

	// Request is the SlotRequest passed to Collect. When AcceptedTypes is
	// empty it defaults to Plugin.Emits() (collect everything the plugin can
	// produce).
	Request core.SlotRequest

	// EvidenceTypes resolves each emitted record's Type to its JSON Schema
	// for the conformance + completeness checks. Pass BuiltinEvidenceTypes(t)
	// to use the embedded production schemas, or a custom registry in the
	// harness's own tests. Required.
	EvidenceTypes *registry.Registry[core.EvidenceType]

	// OptionalFields exempts schema-declared fields from the completeness
	// check when a scenario legitimately leaves them absent. Each entry is a
	// bare field name ("description") or type-qualified ("git_repository.topics").
	OptionalFields []string

	// AllowEmpty permits a Collect that emits zero records. By default an
	// empty result is a failure — a conformance run should exercise records.
	AllowEmpty bool
}

// RunConformance collects from opts.Plugin and asserts, via t, that every
// emitted record: validates against its evidence-type JSON Schema; is
// complete (no schema-defined field silently dropped); is produced
// deterministically (two runs → identical, ID-sorted output); and carries
// the required metadata (Type, ID, SourceID, CollectedAt). It returns the
// first run's records so callers can make additional scenario assertions.
func RunConformance(t *testing.T, opts *Options) []core.EvidenceRecord {
	t.Helper()
	records, errs := checkConformance(context.Background(), opts)
	for _, e := range errs {
		t.Error(e)
	}
	return records
}

// checkConformance is the pure core of RunConformance: it returns the errors
// it would report rather than failing a *testing.T, so the harness's own
// tests can assert that a deliberately-broken plugin is rejected.
func checkConformance(ctx context.Context, opts *Options) ([]core.EvidenceRecord, []error) {
	switch {
	case opts == nil:
		return nil, []error{fmt.Errorf("sourcetest: Options is nil")}
	case opts.Plugin == nil:
		return nil, []error{fmt.Errorf("sourcetest: Options.Plugin is nil")}
	case opts.EvidenceTypes == nil:
		return nil, []error{fmt.Errorf("sourcetest: Options.EvidenceTypes is nil (pass BuiltinEvidenceTypes(t) or a custom registry)")}
	}

	req := opts.Request
	if len(req.AcceptedTypes) == 0 {
		req.AcceptedTypes = opts.Plugin.Emits()
	}

	records, err := opts.Plugin.Collect(ctx, req)
	if err != nil {
		return nil, []error{fmt.Errorf("sourcetest: Collect: %w", err)}
	}

	var errs []error

	// Determinism: a second identical Collect must produce identical output.
	// A plugin that stamps time.Now() (instead of an injected clock) trips here.
	again, err := opts.Plugin.Collect(ctx, req)
	if err != nil {
		errs = append(errs, fmt.Errorf("sourcetest: second Collect: %w", err))
	} else if !reflect.DeepEqual(records, again) {
		errs = append(errs, fmt.Errorf("sourcetest: non-deterministic Collect: two runs produced different output (inject a fixed clock instead of time.Now)"))
	}

	if len(records) == 0 {
		if !opts.AllowEmpty {
			errs = append(errs, fmt.Errorf("sourcetest: Collect emitted no records (set Options.AllowEmpty to test an empty scenario)"))
		}
		return records, errs
	}

	if !sort.SliceIsSorted(records, func(i, j int) bool { return records[i].ID < records[j].ID }) {
		errs = append(errs, fmt.Errorf("sourcetest: records not sorted by ID ascending (plugins must sort before returning)"))
	}

	emits := toSet(opts.Plugin.Emits())
	exempt := toSet(opts.OptionalFields)
	for i := range records {
		errs = append(errs, checkRecord(i, &records[i], emits, exempt, opts.EvidenceTypes)...)
	}
	return records, errs
}

// checkRecord runs the metadata + schema-conformance + completeness checks for
// a single emitted record.
func checkRecord(i int, r *core.EvidenceRecord, emits, exempt map[string]bool, types *registry.Registry[core.EvidenceType]) []error {
	prefix := fmt.Sprintf("record[%d] (id=%q type=%q)", i, r.ID, r.Type)
	var errs []error

	switch {
	case r.Type == "":
		errs = append(errs, fmt.Errorf("%s: empty Type", prefix))
	case !emits[r.Type]:
		errs = append(errs, fmt.Errorf("%s: Type not in plugin.Emits()", prefix))
	}
	if r.ID == "" {
		errs = append(errs, fmt.Errorf("%s: empty ID", prefix))
	}
	if r.SourceID == "" {
		errs = append(errs, fmt.Errorf("%s: empty SourceID", prefix))
	}
	if r.CollectedAt.IsZero() {
		errs = append(errs, fmt.Errorf("%s: zero CollectedAt", prefix))
	}

	et, ok := types.Lookup(r.Type)
	if !ok {
		return append(errs, fmt.Errorf("%s: no registered evidence type/schema", prefix))
	}
	if verr := evidencetypes.Validate(et.Schema, r.Payload); verr != nil {
		errs = append(errs, fmt.Errorf("%s: schema validation: %w", prefix, verr))
	}
	return append(errs, checkCompleteness(prefix, r.Type, et.Schema, r.Payload, exempt)...)
}

// checkCompleteness asserts every property declared in the schema's top-level
// "properties" is present as a key in the payload object — catching a mapper
// that silently drops a field. (Schema Validate already enforces required
// fields and types; this is the extra CloudQuery-style "no dropped column"
// guard over optional fields too.) Fields named in exempt may be absent.
func checkCompleteness(prefix, typeID string, schema, payload json.RawMessage, exempt map[string]bool) []error {
	var doc struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schema, &doc); err != nil {
		return []error{fmt.Errorf("%s: parse schema properties: %w", prefix, err)}
	}
	if len(doc.Properties) == 0 {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(payload, &obj); err != nil {
		return []error{fmt.Errorf("%s: payload is not a JSON object: %w", prefix, err)}
	}

	fields := make([]string, 0, len(doc.Properties))
	for f := range doc.Properties {
		fields = append(fields, f)
	}
	sort.Strings(fields) // deterministic error ordering

	var errs []error
	for _, f := range fields {
		if _, present := obj[f]; present {
			continue
		}
		if exempt[f] || exempt[typeID+"."+f] {
			continue
		}
		errs = append(errs, fmt.Errorf("%s: payload missing schema-defined field %q (incomplete mapping; add to Options.OptionalFields if legitimately absent)", prefix, f))
	}
	return errs
}

// BuiltinEvidenceTypes loads the embedded production evidence-type schemas
// into a fresh registry for use as Options.EvidenceTypes.
func BuiltinEvidenceTypes(t *testing.T) *registry.Registry[core.EvidenceType] {
	t.Helper()
	set := registry.NewSet()
	if err := evidencetypes.Register(set); err != nil {
		t.Fatalf("sourcetest: load builtin evidence types: %v", err)
	}
	return set.EvidenceTypes
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
