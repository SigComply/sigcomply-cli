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
// it is the gate referenced in cloud.go's SECURITY block.
//
// What is rejected:
//   - any interface{} / any field (lets through arbitrary identities)
//   - json.RawMessage (lets through arbitrary identities as bytes)
//   - map[string]X where X is interface{} (a freeform escape hatch)
//   - maps with non-string keys (defensive)
//
// What is allowed:
//   - scalar kinds (string/bool/int*/uint*/float*)
//   - named string types (enums like Severity, PolicyStatus)
//   - time.Time
//   - structs (recursed into)
//   - slices (element recursed into)
//   - maps where both key and value are concrete (recursed into)
//   - pointers (target recursed into)
func TestSubmissionPayload_StructurallyCountsOnly(t *testing.T) {
	walkType(t, reflect.TypeOf(SubmissionPayload{}), "SubmissionPayload")
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

func walkType(t *testing.T, ty reflect.Type, path string) {
	t.Helper()

	if ty == timeType {
		return
	}
	if ty == rawMessageType {
		t.Errorf("%s: json.RawMessage forbidden — would carry arbitrary identity bytes", path)
		return
	}

	switch ty.Kind() {
	case reflect.Interface:
		t.Errorf("%s: interface type %q forbidden — would carry arbitrary identity payloads", path, ty.String())
	case reflect.Struct:
		for i := 0; i < ty.NumField(); i++ {
			f := ty.Field(i)
			walkType(t, f.Type, path+"."+f.Name)
		}
	case reflect.Slice, reflect.Array:
		walkType(t, ty.Elem(), path+"[]")
	case reflect.Map:
		if ty.Key().Kind() != reflect.String {
			t.Errorf("%s: map key kind %s forbidden — must be string", path, ty.Key().Kind())
		}
		if ty.Elem().Kind() == reflect.Interface {
			t.Errorf("%s: map[string]interface{} forbidden — freeform identity escape hatch", path)
			return
		}
		walkType(t, ty.Elem(), path+"[*]")
	case reflect.Ptr:
		walkType(t, ty.Elem(), "*"+path)
	default:
		if !allowedScalarKinds[ty.Kind()] {
			t.Errorf("%s: kind %s not allowed in SubmissionPayload", path, ty.Kind())
		}
	}
}

// TestSubmissionPayload_JSONRoundTrip ensures the wire shape encodes
// and decodes losslessly via JSON — the wire format is the contract
// auditors and self-hosted backends rely on.
func TestSubmissionPayload_JSONRoundTrip(t *testing.T) {
	in := SubmissionPayload{
		Schema:     "sigcomply.cloud.v1",
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
