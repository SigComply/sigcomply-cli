package sourcetest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

// --- in-package fake plugin + synthetic evidence type ----------------------

const widgetType = "test_widget"

var fixedTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

type widget struct {
	Name    string `json:"name"`
	Region  string `json:"region"`
	Enabled bool   `json:"enabled"`
}

func widgetSchema() json.RawMessage {
	return json.RawMessage(`{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"title": "test_widget",
		"type": "object",
		"additionalProperties": false,
		"required": ["name", "region"],
		"properties": {
			"name": {"type": "string"},
			"region": {"type": "string"},
			"enabled": {"type": "boolean"}
		}
	}`)
}

func testTypes(t *testing.T) *registry.Registry[core.EvidenceType] {
	t.Helper()
	reg := registry.New(func(et core.EvidenceType) string { return et.ID })
	if err := reg.Register(core.EvidenceType{ID: widgetType, Version: 1, Schema: widgetSchema()}); err != nil {
		t.Fatalf("register evidence type: %v", err)
	}
	return reg
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// widgetRecord builds a fully-populated, schema-valid record.
func widgetRecord(name, region string, enabled bool) core.EvidenceRecord {
	return core.EvidenceRecord{
		Type:        widgetType,
		ID:          name,
		Payload:     mustJSON(widget{Name: name, Region: region, Enabled: enabled}),
		SourceID:    "test",
		CollectedAt: fixedTime,
	}
}

// rawRecord builds a record from an arbitrary payload (for malformed cases).
func rawRecord(id, typeID, payload string) core.EvidenceRecord {
	return core.EvidenceRecord{
		Type:        typeID,
		ID:          id,
		Payload:     json.RawMessage(payload),
		SourceID:    "test",
		CollectedAt: fixedTime,
	}
}

type fakePlugin struct {
	emits   []string
	records []core.EvidenceRecord
	err     error
	// mutate, if set, rewrites the per-run output to model non-determinism.
	mutate func(run int, recs []core.EvidenceRecord)
	runs   int
}

func (f *fakePlugin) ID() string                                 { return "test" }
func (f *fakePlugin) Emits() []string                            { return f.emits }
func (f *fakePlugin) Init(context.Context, map[string]any) error { return nil }

func (f *fakePlugin) Collect(context.Context, core.SlotRequest) ([]core.EvidenceRecord, error) {
	f.runs++
	if f.err != nil {
		return nil, f.err
	}
	recs := cloneRecords(f.records)
	if f.mutate != nil {
		f.mutate(f.runs, recs)
	}
	return recs, nil
}

func cloneRecords(in []core.EvidenceRecord) []core.EvidenceRecord {
	out := make([]core.EvidenceRecord, len(in))
	copy(out, in)
	for i := range out {
		if out[i].Payload != nil {
			p := make(json.RawMessage, len(out[i].Payload))
			copy(p, out[i].Payload)
			out[i].Payload = p
		}
	}
	return out
}

func newPlugin(records ...core.EvidenceRecord) *fakePlugin {
	return &fakePlugin{emits: []string{widgetType}, records: records}
}

// --- tests -----------------------------------------------------------------

// TestRunConformance_GoodPluginPasses also exercises the *testing.T wrapper.
func TestRunConformance_GoodPluginPasses(t *testing.T) {
	opts := Options{
		Plugin:        newPlugin(widgetRecord("a", "us-east", true), widgetRecord("b", "eu-west", false)),
		EvidenceTypes: testTypes(t),
	}
	recs := RunConformance(t, &opts)
	if len(recs) != 2 {
		t.Fatalf("RunConformance returned %d records; want 2", len(recs))
	}
}

func TestCheckConformance_Failures(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		want string // substring expected in at least one returned error
	}{
		{
			name: "nil plugin",
			opts: Options{EvidenceTypes: testTypes(t)},
			want: "Options.Plugin is nil",
		},
		{
			name: "nil evidence types",
			opts: Options{Plugin: newPlugin(widgetRecord("a", "us", true))},
			want: "Options.EvidenceTypes is nil",
		},
		{
			name: "collect error",
			opts: Options{Plugin: &fakePlugin{emits: []string{widgetType}, err: errBoom}, EvidenceTypes: testTypes(t)},
			want: "sourcetest: Collect:",
		},
		{
			name: "empty result not allowed",
			opts: Options{Plugin: newPlugin(), EvidenceTypes: testTypes(t)},
			want: "emitted no records",
		},
		{
			name: "unsorted records",
			opts: Options{Plugin: newPlugin(widgetRecord("b", "eu", true), widgetRecord("a", "us", true)), EvidenceTypes: testTypes(t)},
			want: "not sorted by ID",
		},
		{
			name: "schema violation (wrong type)",
			opts: Options{Plugin: newPlugin(rawRecord("w1", widgetType, `{"name":123,"region":"us","enabled":true}`)), EvidenceTypes: testTypes(t)},
			want: "schema validation",
		},
		{
			name: "incomplete payload (dropped optional field)",
			opts: Options{Plugin: newPlugin(rawRecord("w1", widgetType, `{"name":"w1","region":"us"}`)), EvidenceTypes: testTypes(t)},
			want: `missing schema-defined field "enabled"`,
		},
		{
			name: "unknown type",
			opts: Options{Plugin: &fakePlugin{emits: []string{widgetType}, records: []core.EvidenceRecord{rawRecord("g", "ghost_type", `{}`)}}, EvidenceTypes: testTypes(t)},
			want: "Type not in plugin.Emits()",
		},
		{
			name: "missing metadata",
			opts: Options{
				Plugin: &fakePlugin{emits: []string{widgetType}, records: []core.EvidenceRecord{{
					Type: widgetType, ID: "w1", Payload: json.RawMessage(`{"name":"w1","region":"us","enabled":true}`),
					// SourceID + CollectedAt deliberately unset.
				}}},
				EvidenceTypes: testTypes(t),
			},
			want: "empty SourceID",
		},
		{
			name: "non-deterministic output",
			opts: Options{
				Plugin: &fakePlugin{
					emits:   []string{widgetType},
					records: []core.EvidenceRecord{widgetRecord("a", "us", true)},
					mutate: func(run int, recs []core.EvidenceRecord) {
						if run == 2 {
							recs[0].CollectedAt = recs[0].CollectedAt.Add(time.Second)
						}
					},
				},
				EvidenceTypes: testTypes(t),
			},
			want: "non-deterministic",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, errs := checkConformance(context.Background(), &tc.opts)
			if !errsContain(errs, tc.want) {
				t.Fatalf("expected an error containing %q; got %v", tc.want, errs)
			}
		})
	}
}

func TestCheckConformance_OptionalFieldsExempted(t *testing.T) {
	rec := rawRecord("w1", widgetType, `{"name":"w1","region":"us"}`) // no "enabled"
	for _, exempt := range [][]string{{"enabled"}, {widgetType + ".enabled"}} {
		opts := Options{Plugin: newPlugin(rec), EvidenceTypes: testTypes(t), OptionalFields: exempt}
		if _, errs := checkConformance(context.Background(), &opts); len(errs) != 0 {
			t.Errorf("OptionalFields=%v: expected no errors, got %v", exempt, errs)
		}
	}
}

func TestCheckConformance_AllowEmpty(t *testing.T) {
	opts := Options{Plugin: newPlugin(), EvidenceTypes: testTypes(t), AllowEmpty: true}
	if _, errs := checkConformance(context.Background(), &opts); len(errs) != 0 {
		t.Errorf("AllowEmpty: expected no errors, got %v", errs)
	}
}

func TestCheckConformance_DefaultsAcceptedTypesToEmits(t *testing.T) {
	// Request left zero — AcceptedTypes should default to Emits() and the run
	// should still pass for a good plugin.
	opts := Options{Plugin: newPlugin(widgetRecord("a", "us", true)), EvidenceTypes: testTypes(t)}
	if _, errs := checkConformance(context.Background(), &opts); len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestBuiltinEvidenceTypes(t *testing.T) {
	reg := BuiltinEvidenceTypes(t)
	if reg.Len() == 0 {
		t.Fatal("BuiltinEvidenceTypes loaded no schemas")
	}
	if _, ok := reg.Lookup("directory_user"); !ok {
		t.Error("expected a registered directory_user schema")
	}
}

func errsContain(errs []error, sub string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), sub) {
			return true
		}
	}
	return false
}

var errBoom = errBoomType("boom")

type errBoomType string

func (e errBoomType) Error() string { return string(e) }
