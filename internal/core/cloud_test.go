package core

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// TestSubmissionPayload_StructurallyCountsOnly walks SubmissionPayload's
// type graph and rejects fields that could carry resource identity.
// This is the structural enforcement of the aggregation boundary —
// it is the gate referenced in cloud.go's SECURITY block (Sacred
// Invariant #1, the non-custodial aggregation boundary).
//
// What is rejected:
//   - any interface{} / any field (lets through arbitrary identities)
//   - json.RawMessage (lets through arbitrary identities as bytes)
//   - map[string]X where X is interface{} (a freeform escape hatch)
//   - maps with non-string keys (defensive)
//   - chan / func / unsafe.Pointer / complex (not serializable counts)
//
// What is allowed:
//   - scalar kinds (string/bool/int*/uint*/float*)
//   - named string types (enums like Severity, PolicyStatus)
//   - time.Time
//   - structs (recursed into)
//   - slices (element recursed into)
//   - maps where both key and value are concrete (recursed into)
//   - pointers (target recursed into)
//
// The walker recurses through every nested struct, slice, array, map,
// and pointer in the graph, so a freeform field added ANYWHERE — not
// just at the top level — fails the build.
func TestSubmissionPayload_StructurallyCountsOnly(t *testing.T) {
	if errs := freeformViolations(reflect.TypeOf(SubmissionPayload{}), "SubmissionPayload"); len(errs) != 0 {
		for _, e := range errs {
			t.Error(e)
		}
	}
}

var (
	timeType       = reflect.TypeOf(time.Time{})
	rawMessageType = reflect.TypeOf(json.RawMessage{})
)

var allowedScalarKinds = map[reflect.Kind]bool{
	reflect.String:  true,
	reflect.Bool:    true,
	reflect.Int:     true,
	reflect.Int8:    true,
	reflect.Int16:   true,
	reflect.Int32:   true,
	reflect.Int64:   true,
	reflect.Uint:    true,
	reflect.Uint8:   true,
	reflect.Uint16:  true,
	reflect.Uint32:  true,
	reflect.Uint64:  true,
	reflect.Float32: true,
	reflect.Float64: true,
}

// freeformViolations walks ty's full type graph and returns one message
// per field that could carry freeform identity. An empty result means
// the type is structurally counts-only.
//
// Returning the violations (rather than calling t.Errorf inline) lets
// the walker itself be unit-tested against deliberately-bad mirror types
// (see TestFreeformWalker_*), which proves the guard actually catches
// regressions instead of silently passing everything.
func freeformViolations(ty reflect.Type, path string) []string {
	return walkType(ty, path, map[reflect.Type]bool{})
}

func walkType(ty reflect.Type, path string, seen map[reflect.Type]bool) []string {
	if ty == timeType {
		return nil
	}
	if ty == rawMessageType {
		return []string{path + ": json.RawMessage forbidden — would carry arbitrary identity bytes"}
	}

	// Cycle guard: a self-referential type (e.g. a tree node pointing at
	// itself) would otherwise recurse forever and hang the test. We only
	// need to inspect each named composite type once.
	if seen[ty] {
		return nil
	}
	switch ty.Kind() {
	case reflect.Struct, reflect.Map, reflect.Slice, reflect.Array, reflect.Ptr:
		seen[ty] = true
	}

	var out []string
	switch ty.Kind() {
	case reflect.Interface:
		out = append(out, path+": interface type "+ty.String()+" forbidden — would carry arbitrary identity payloads")
	case reflect.Struct:
		for i := 0; i < ty.NumField(); i++ {
			f := ty.Field(i)
			out = append(out, walkType(f.Type, path+"."+f.Name, seen)...)
		}
	case reflect.Slice, reflect.Array:
		out = append(out, walkType(ty.Elem(), path+"[]", seen)...)
	case reflect.Map:
		if ty.Key().Kind() != reflect.String {
			out = append(out, path+": map key kind "+ty.Key().Kind().String()+" forbidden — must be string")
		}
		if ty.Elem().Kind() == reflect.Interface {
			out = append(out, path+": map[string]interface{} forbidden — freeform identity escape hatch")
			return out
		}
		out = append(out, walkType(ty.Elem(), path+"[*]", seen)...)
	case reflect.Ptr:
		out = append(out, walkType(ty.Elem(), "*"+path, seen)...)
	default:
		if !allowedScalarKinds[ty.Kind()] {
			out = append(out, path+": kind "+ty.Kind().String()+" not allowed in SubmissionPayload")
		}
	}
	return out
}

// --- Meta-tests proving the walker actually catches regressions. ---
//
// A guard that silently passes everything is worse than no guard. These
// tests feed the SAME walker deliberately-bad mirror types and assert it
// flags them — and a clean mirror and assert it does not. If a future
// edit weakens walkType into a no-op, these fail.

type cleanMirror struct {
	Count  int
	Name   string
	Nested struct {
		Score    float64
		Statuses []PolicyStatus
	}
}

type topLevelAnyMirror struct {
	Count int
	Leak  any // freeform escape hatch at top level
}

type nestedStructAnyMirror struct {
	Count  int
	Nested struct {
		Inner struct {
			Leak interface{} // buried two structs deep
		}
	}
}

type sliceElemAnyMirror struct {
	Items []any // freeform inside a slice element
}

type mapValueAnyMirror struct {
	Attrs map[string]any // the classic freeform map
}

type mapNonStringKeyMirror struct {
	ByID map[int]string // non-string key
}

type rawMessageMirror struct {
	Blob json.RawMessage
}

type sliceOfStructWithAnyMirror struct {
	Rows []struct {
		Leak any
	}
}

type pointerToAnyStructMirror struct {
	Ptr *struct {
		Leak any
	}
}

func TestFreeformWalker_AcceptsCleanType(t *testing.T) {
	if errs := freeformViolations(reflect.TypeOf(cleanMirror{}), "cleanMirror"); len(errs) != 0 {
		t.Errorf("clean type flagged as freeform: %v", errs)
	}
}

func TestFreeformWalker_DetectsFreeformFields(t *testing.T) {
	cases := []struct {
		name string
		typ  reflect.Type
	}{
		{"top-level any", reflect.TypeOf(topLevelAnyMirror{})},
		{"nested struct interface{}", reflect.TypeOf(nestedStructAnyMirror{})},
		{"slice element any", reflect.TypeOf(sliceElemAnyMirror{})},
		{"map[string]any", reflect.TypeOf(mapValueAnyMirror{})},
		{"map non-string key", reflect.TypeOf(mapNonStringKeyMirror{})},
		{"json.RawMessage", reflect.TypeOf(rawMessageMirror{})},
		{"slice of struct with any", reflect.TypeOf(sliceOfStructWithAnyMirror{})},
		{"pointer to struct with any", reflect.TypeOf(pointerToAnyStructMirror{})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := freeformViolations(c.typ, c.typ.Name())
			if len(errs) == 0 {
				t.Errorf("walker missed a freeform field in %s — the privacy guard would not catch this regression", c.name)
			}
		})
	}
}

// recursiveNode is a self-referential type; it must not hang the walker.
type recursiveNode struct {
	Name     string
	Children []recursiveNode
	Parent   *recursiveNode
}

func TestFreeformWalker_HandlesCyclesWithoutHanging(t *testing.T) {
	// If the cycle guard regresses this test deadlocks rather than
	// failing, which the `go test` timeout still surfaces. A clean
	// recursive type of only counts/strings must report no violations.
	if errs := freeformViolations(reflect.TypeOf(recursiveNode{}), "recursiveNode"); len(errs) != 0 {
		t.Errorf("clean recursive type flagged: %v", errs)
	}
}

type recursiveLeakNode struct {
	Children []recursiveLeakNode
	Leak     any
}

func TestFreeformWalker_DetectsLeakInRecursiveType(t *testing.T) {
	errs := freeformViolations(reflect.TypeOf(recursiveLeakNode{}), "recursiveLeakNode")
	if len(errs) == 0 {
		t.Error("walker missed a freeform field in a self-referential type")
	}
}

type chanMirror struct {
	Ch chan int
}

type funcMirror struct {
	Fn func()
}

func TestFreeformWalker_RejectsUnserializableKinds(t *testing.T) {
	for _, c := range []struct {
		name string
		typ  reflect.Type
	}{
		{"chan", reflect.TypeOf(chanMirror{})},
		{"func", reflect.TypeOf(funcMirror{})},
	} {
		t.Run(c.name, func(t *testing.T) {
			if errs := freeformViolations(c.typ, c.typ.Name()); len(errs) == 0 {
				t.Errorf("walker accepted unserializable kind in %s", c.name)
			}
		})
	}
}

// TestSubmissionPayload_NoViolationsSlice asserts the structural absence
// of a Violations-style field by name — a belt-and-suspenders companion
// to the kind-based walker. The non-custodial model forbids a per-policy
// list of violation records (which would carry resource identity); the
// aggregator emits ResourcesEvaluated/ResourcesFailed counts instead.
func TestSubmissionPayload_NoViolationsSlice(t *testing.T) {
	forbiddenFieldNames := map[string]bool{
		"violations":  true,
		"violation":   true,
		"resources":   true, // the literal resource list, vs. ResourcesEvaluated/Failed counts
		"identifiers": true,
		"details":     true,
		"raw":         true,
	}
	seen := map[reflect.Type]bool{}
	var walk func(ty reflect.Type)
	walk = func(ty reflect.Type) {
		if ty == timeType || seen[ty] {
			return
		}
		switch ty.Kind() {
		case reflect.Struct, reflect.Map, reflect.Slice, reflect.Array, reflect.Ptr:
			seen[ty] = true
		}
		switch ty.Kind() {
		case reflect.Struct:
			for i := 0; i < ty.NumField(); i++ {
				f := ty.Field(i)
				if forbiddenFieldNames[normalizeFieldName(f.Name)] {
					t.Errorf("forbidden field %q in %s — counts-only payload must not carry identity lists", f.Name, ty.Name())
				}
				walk(f.Type)
			}
		case reflect.Slice, reflect.Array, reflect.Ptr:
			walk(ty.Elem())
		case reflect.Map:
			walk(ty.Elem())
		}
	}
	walk(reflect.TypeOf(SubmissionPayload{}))
}

func normalizeFieldName(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		out = append(out, r)
	}
	return string(out)
}

// TestSubmissionPayload_JSONRoundTrip ensures the wire shape encodes
// and decodes losslessly via JSON — the wire format is the contract
// auditors and self-hosted backends rely on.
func TestSubmissionPayload_JSONRoundTrip(t *testing.T) {
	in := SubmissionPayload{
		Schema:     "sigcomply.cloud.v3",
		RunID:      "run-1",
		Framework:  "soc2",
		PeriodID:   "2026-Q1",
		CommitSHA:  "deadbeef",
		CommitTime: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Branch:     "main",
		Repository: Repository{Provider: "github", NameSlug: "acme/infra"},
		Summary:    RunSummary{PoliciesTotal: 1, PoliciesPassed: 1, ComplianceScore: 1.0},
		Policies: []AggregatedPolicy{{
			PolicyID:           "soc2.cc6.1.mfa_enforced",
			Controls:           []ControlRef{{ControlID: "SOC2.CC6.1"}},
			Status:             StatusPass,
			Severity:           SeverityHigh,
			ResourcesEvaluated: 42,
			ResourcesFailed:    0,
			Message:            "All 42 resources passed.",
		}},
	}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var out SubmissionPayload
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !reflect.DeepEqual(in, out) {
		t.Errorf("round-trip mismatch\n in: %#v\nout: %#v", in, out)
	}
}
