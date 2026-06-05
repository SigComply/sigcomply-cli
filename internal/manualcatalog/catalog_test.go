package manualcatalog

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestEntry_JSONTagsMatchSPAContract pins every json tag on Entry to the
// exact field name the Evidence SPA's src/types/catalog.ts CatalogEntry
// interface depends on. Changing a tag here silently breaks the SPA's
// build (scripts/fetch-catalogs.ts consumes this shape verbatim), so the
// contract is asserted field-by-field rather than via a fragile snapshot.
func TestEntry_JSONTagsMatchSPAContract(t *testing.T) {
	want := map[string]string{
		"ID":              "id",
		"Control":         "control",
		"Type":            "type",
		"Frequency":       "frequency",
		"TemporalRule":    "temporal_rule",
		"GracePeriod":     "grace_period",
		"Name":            "name",
		"Description":     "description",
		"Severity":        "severity",
		"AcceptedFormats": "accepted_formats,omitempty",
		"Items":           "items,omitempty",
		"DeclarationText": "declaration_text,omitempty",
		"Category":        "category,omitempty",
		"TSC":             "tsc,omitempty",
		"Optional":        "optional,omitempty",
	}
	assertJSONTags(t, reflect.TypeOf(Entry{}), want)
}

func TestCatalog_JSONTagsMatchSPAContract(t *testing.T) {
	want := map[string]string{
		"Framework": "framework",
		"Version":   "version",
		"Entries":   "entries",
	}
	assertJSONTags(t, reflect.TypeOf(Catalog{}), want)
}

func TestChecklistItem_JSONTagsMatchSPAContract(t *testing.T) {
	want := map[string]string{
		"ID":       "id",
		"Text":     "text",
		"Required": "required",
	}
	assertJSONTags(t, reflect.TypeOf(ChecklistItem{}), want)
}

func assertJSONTags(t *testing.T, ty reflect.Type, want map[string]string) {
	t.Helper()
	if ty.NumField() != len(want) {
		t.Fatalf("%s has %d fields; SPA contract expects %d — a field was added or removed",
			ty.Name(), ty.NumField(), len(want))
	}
	for i := 0; i < ty.NumField(); i++ {
		f := ty.Field(i)
		got := f.Tag.Get("json")
		w, ok := want[f.Name]
		if !ok {
			t.Errorf("%s.%s: unexpected field not in SPA contract", ty.Name(), f.Name)
			continue
		}
		if got != w {
			t.Errorf("%s.%s json tag = %q; SPA contract wants %q", ty.Name(), f.Name, got, w)
		}
	}
}

// TestEnumValues_MatchSPAUnions pins the string values of the descriptive
// enums to the SPA's TypeScript string-literal unions.
func TestEnumValues_MatchSPAUnions(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"TypeDocumentUpload", string(TypeDocumentUpload), "document_upload"},
		{"TypeChecklist", string(TypeChecklist), "checklist"},
		{"TypeDeclaration", string(TypeDeclaration), "declaration"},
		{"FrequencyDaily", string(FrequencyDaily), "daily"},
		{"FrequencyWeekly", string(FrequencyWeekly), "weekly"},
		{"FrequencyMonthly", string(FrequencyMonthly), "monthly"},
		{"FrequencyQuarterly", string(FrequencyQuarterly), "quarterly"},
		{"FrequencyYearly", string(FrequencyYearly), "yearly"},
		{"TemporalRetrospective", string(TemporalRetrospective), "retrospective"},
		{"TemporalAnytime", string(TemporalAnytime), "anytime"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q; SPA union wants %q", c.name, c.got, c.want)
		}
	}
}

// TestEntry_JSONRoundTrip verifies the exact key set emitted for a fully
// populated entry — including that omitempty fields appear when set and
// vanish when zero. This is the wire shape the SPA parses.
func TestEntry_JSONRoundTrip(t *testing.T) {
	full := Entry{
		ID:              "access_review_quarterly",
		Control:         "CC6.3",
		Type:            TypeChecklist,
		Frequency:       FrequencyQuarterly,
		TemporalRule:    TemporalRetrospective,
		GracePeriod:     "15d",
		Name:            "Access Review Quarterly",
		Description:     "A quarterly user access review.",
		Severity:        "high",
		AcceptedFormats: []string{"pdf"},
		Items:           []ChecklistItem{{ID: "a", Text: "Did the thing", Required: true}},
		DeclarationText: "I confirm.",
		Category:        "governance",
		TSC:             "security",
		Optional:        true,
	}
	b, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{
		"id", "control", "type", "frequency", "temporal_rule", "grace_period",
		"name", "description", "severity", "accepted_formats", "items",
		"declaration_text", "category", "tsc", "optional",
	} {
		if _, ok := generic[k]; !ok {
			t.Errorf("populated entry missing key %q", k)
		}
	}

	// A minimal entry must omit the omitempty keys entirely.
	minimal := Entry{
		ID:           "x",
		Control:      "CC1.1",
		Type:         TypeDocumentUpload,
		Frequency:    FrequencyYearly,
		TemporalRule: TemporalRetrospective,
		GracePeriod:  "30d",
		Name:         "X",
		Description:  "d",
		Severity:     "medium",
	}
	mb, err := json.Marshal(minimal)
	if err != nil {
		t.Fatalf("marshal minimal: %v", err)
	}
	var mgeneric map[string]json.RawMessage
	if err := json.Unmarshal(mb, &mgeneric); err != nil {
		t.Fatalf("unmarshal minimal: %v", err)
	}
	for _, k := range []string{"accepted_formats", "items", "declaration_text", "category", "tsc", "optional"} {
		if _, ok := mgeneric[k]; ok {
			t.Errorf("minimal entry should omit %q but it is present", k)
		}
	}
	// Required (non-omitempty) keys must always be present.
	for _, k := range []string{"id", "control", "type", "frequency", "temporal_rule", "grace_period", "name", "description", "severity"} {
		if _, ok := mgeneric[k]; !ok {
			t.Errorf("minimal entry missing required key %q", k)
		}
	}
}

func TestTitleFromID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"security_awareness_training", "Security Awareness Training"},
		{"nda_policy", "NDA Policy"},
		{"pii_handling", "PII Handling"},
		{"soc2_readiness", "SOC 2 Readiness"},
		{"iso_controls", "ISO Controls"},
		{"sdlc_process", "SDLC Process"},
		{"bcp_test", "BCP Test"},
		{"ict_continuity", "ICT Continuity"},
		{"single", "Single"},
		{"", ""},
		{"a__b", "A  B"}, // empty middle segment yields a double space (segments joined by " ")
	}
	for _, c := range cases {
		if got := TitleFromID(c.in); got != c.want {
			t.Errorf("TitleFromID(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestFrequencyFromCadence(t *testing.T) {
	cases := []struct {
		cadence string
		want    Frequency
	}{
		{"annual", FrequencyYearly},
		{"yearly", FrequencyYearly},
		{"quarterly", FrequencyQuarterly},
		{"monthly", FrequencyMonthly},
		{"weekly", FrequencyWeekly},
		{"daily", FrequencyDaily},
		{"hourly", FrequencyDaily},
		{"continuous", FrequencyDaily},
		{"every:6h", FrequencyYearly},
		{"nonsense", FrequencyYearly},
		{"", FrequencyYearly},
	}
	for _, c := range cases {
		if got := FrequencyFromCadence(c.cadence); got != c.want {
			t.Errorf("FrequencyFromCadence(%q) = %q; want %q", c.cadence, got, c.want)
		}
	}
}

// TestFrequencyFromCadence_AlwaysSPAValid guards the "always validates"
// promise: every output must be one of the SPA's Frequency union members.
func TestFrequencyFromCadence_AlwaysSPAValid(t *testing.T) {
	valid := map[Frequency]bool{
		FrequencyDaily: true, FrequencyWeekly: true, FrequencyMonthly: true,
		FrequencyQuarterly: true, FrequencyYearly: true,
	}
	for _, cadence := range []string{
		"continuous", "hourly", "daily", "weekly", "monthly", "quarterly",
		"annual", "yearly", "every:5m", "every:24h", "", "garbage",
	} {
		if got := FrequencyFromCadence(cadence); !valid[got] {
			t.Errorf("FrequencyFromCadence(%q) = %q is not a valid SPA Frequency", cadence, got)
		}
	}
}

func TestGraceForCadence(t *testing.T) {
	if got := GraceForCadence("quarterly"); got != "15d" {
		t.Errorf("GraceForCadence(quarterly) = %q; want 15d", got)
	}
	for _, cadence := range []string{"annual", "monthly", "weekly", "daily", "", "every:6h"} {
		if got := GraceForCadence(cadence); got != "30d" {
			t.Errorf("GraceForCadence(%q) = %q; want 30d", cadence, got)
		}
	}
}
