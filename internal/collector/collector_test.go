package collector

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
)

// stubSource lets us drive Collect with canned records / errors.
type stubSource struct {
	id      string
	emits   []string
	records []core.EvidenceRecord
	err     error
	calls   int
	lastReq core.SlotRequest
}

func (s *stubSource) ID() string                                 { return s.id }
func (s *stubSource) Emits() []string                            { return s.emits }
func (s *stubSource) Init(context.Context, map[string]any) error { return nil }
func (s *stubSource) Collect(_ context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	s.calls++
	s.lastReq = req
	if s.err != nil {
		return nil, s.err
	}
	return s.records, nil
}

// memVault stores writes in-memory; it satisfies core.Vault.
type memVault struct {
	envelopes map[string]*core.Envelope
	jsons     map[string]any
	bins      map[string][]byte
}

func newMemVault() *memVault {
	return &memVault{
		envelopes: make(map[string]*core.Envelope),
		jsons:     make(map[string]any),
		bins:      make(map[string][]byte),
	}
}

func (v *memVault) Init(context.Context) error { return nil }
func (v *memVault) PutEnvelope(_ context.Context, key string, e *core.Envelope) error {
	cp := *e
	v.envelopes[key] = &cp
	return nil
}
func (v *memVault) PutJSON(_ context.Context, key string, body any) error {
	v.jsons[key] = body
	return nil
}
func (v *memVault) PutBinary(_ context.Context, key string, body []byte, _ map[string]string) error {
	v.bins[key] = body
	return nil
}
func (v *memVault) GetBinary(_ context.Context, key string) ([]byte, error) {
	if b, ok := v.bins[key]; ok {
		return b, nil
	}
	return nil, errors.New("not found")
}
func (v *memVault) List(_ context.Context, _ string) ([]string, error) { return nil, nil }

func TestCollect_NilInputErrors(t *testing.T) {
	if _, err := Collect(context.Background(), nil); err == nil {
		t.Fatal("want error on nil")
	}
	if _, err := Collect(context.Background(), &Input{}); err == nil {
		t.Fatal("want error on nil plan")
	}
	if _, err := Collect(context.Background(), &Input{Plan: &planner.RunPlan{}}); err == nil {
		t.Fatal("want error on nil sources")
	}
}

func makePolicy(id, slot, evType string, sourceIDs ...string) planner.PlannedPolicy { //nolint:unparam // slot is fixed by callers today but kept for symmetry with the planner.PlannedPolicy shape
	bindings := make([]planner.Binding, 0, len(sourceIDs))
	for _, s := range sourceIDs {
		bindings = append(bindings, planner.Binding{SourceID: s})
	}
	return planner.PlannedPolicy{
		Spec: core.Policy{
			ID:    id,
			Slots: map[string]core.Slot{slot: {Type: evType, Cardinality: core.SlotOneOrMore, Required: true}},
		},
		Bindings: map[string][]planner.Binding{slot: bindings},
	}
}

func TestCollect_WritesSignedEnvelopePerSlotSource(t *testing.T) {
	src := &stubSource{
		id:    "aws.iam",
		emits: []string{"user_record"},
		records: []core.EvidenceRecord{
			{Type: "user_record", ID: "AID2", SourceID: "aws.iam"},
			{Type: "user_record", ID: "AID1", SourceID: "aws.iam"},
		},
	}
	reg := registry.NewSet()
	if err := reg.Sources.Register(src); err != nil {
		t.Fatalf("Register: %v", err)
	}
	pp := makePolicy("soc2.cc6.1.mfa", "u", "user_record", "aws.iam")
	vault := newMemVault()
	out, err := Collect(context.Background(), &Input{
		Plan:    &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Sources: reg.Sources,
		Vault:   vault,
		RunRoot: "soc2/2026-Q1/run_x",
		Now:     time.Date(2026, 2, 15, 14, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if out.CollectErrorsByPolicy["soc2.cc6.1.mfa"] != nil {
		t.Errorf("unexpected collect error: %v", out.CollectErrorsByPolicy["soc2.cc6.1.mfa"])
	}
	// Two records, sorted by ID: AID1 before AID2.
	got := out.RecordsByPolicy["soc2.cc6.1.mfa"]["u"]
	if len(got) != 2 || got[0].ID != "AID1" {
		t.Errorf("records not sorted: got %v", recordIDs(got))
	}
	if len(vault.envelopes) != 1 {
		t.Fatalf("envelope count = %d; want 1", len(vault.envelopes))
	}
	for _, env := range vault.envelopes {
		if err := sign.VerifyEnvelope(env); err != nil {
			t.Errorf("envelope did not verify: %v", err)
		}
		if env.FormatVersion != EnvelopeFormatVersion {
			t.Errorf("FormatVersion = %q; want %q", env.FormatVersion, EnvelopeFormatVersion)
		}
	}
}

func TestCollect_UnionsMultipleBindingsForOneSlot(t *testing.T) {
	srcA := &stubSource{id: "aws.iam", emits: []string{"user_record"},
		records: []core.EvidenceRecord{{Type: "user_record", ID: "AID1"}}}
	srcB := &stubSource{id: "okta", emits: []string{"user_record"},
		records: []core.EvidenceRecord{{Type: "user_record", ID: "OKT1"}}}
	reg := registry.NewSet()
	mustRegister(t, reg.Sources.Register(srcA))
	mustRegister(t, reg.Sources.Register(srcB))
	pp := makePolicy("p1", "u", "user_record", "aws.iam", "okta")
	vault := newMemVault()
	out, err := Collect(context.Background(), &Input{
		Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}}, Sources: reg.Sources, Vault: vault, RunRoot: "r",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(out.RecordsByPolicy["p1"]["u"]) != 2 {
		t.Errorf("expected unioned records; got %v", recordIDs(out.RecordsByPolicy["p1"]["u"]))
	}
	if len(vault.envelopes) != 2 {
		t.Errorf("want 2 envelopes (one per source); got %d", len(vault.envelopes))
	}
}

func TestCollect_SourceErrorTagsPolicy(t *testing.T) {
	src := &stubSource{id: "aws.iam", emits: []string{"user_record"}, err: errors.New("api down")}
	reg := registry.NewSet()
	mustRegister(t, reg.Sources.Register(src))
	pp := makePolicy("p1", "u", "user_record", "aws.iam")
	out, err := Collect(context.Background(), &Input{
		Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}}, Sources: reg.Sources, Vault: newMemVault(), RunRoot: "r",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if out.CollectErrorsByPolicy["p1"] == nil {
		t.Errorf("expected collect error tag")
	}
}

func TestCollect_UnregisteredSourceTagsPolicy(t *testing.T) {
	reg := registry.NewSet()
	pp := makePolicy("p1", "u", "user_record", "aws.iam")
	out, err := Collect(context.Background(), &Input{
		Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}}, Sources: reg.Sources, Vault: newMemVault(), RunRoot: "r",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := out.CollectErrorsByPolicy["p1"]
	if got == nil || !strings.Contains(got.Error(), "not registered") {
		t.Errorf("want not-registered error; got %v", got)
	}
}

func TestCollect_WholePolicyExceptionSkipsFetch(t *testing.T) {
	src := &stubSource{id: "aws.iam", emits: []string{"user_record"}}
	reg := registry.NewSet()
	mustRegister(t, reg.Sources.Register(src))
	pp := makePolicy("p1", "u", "user_record", "aws.iam")
	pp.Exception = &planner.Exception{State: core.StatusNA}
	_, err := Collect(context.Background(), &Input{
		Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}}, Sources: reg.Sources, Vault: newMemVault(), RunRoot: "r",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if src.calls != 0 {
		t.Errorf("expected no Collect calls for NA policy; got %d", src.calls)
	}
}

func TestCollect_KISSNoDRY_TwoPoliciesSameSourceTwoFetches(t *testing.T) {
	src := &stubSource{id: "aws.iam", emits: []string{"user_record"},
		records: []core.EvidenceRecord{{Type: "user_record", ID: "AID1"}}}
	reg := registry.NewSet()
	mustRegister(t, reg.Sources.Register(src))
	p1 := makePolicy("p1", "u", "user_record", "aws.iam")
	p2 := makePolicy("p2", "u", "user_record", "aws.iam")
	_, err := Collect(context.Background(), &Input{
		Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{p1, p2}}, Sources: reg.Sources, Vault: newMemVault(), RunRoot: "r",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if src.calls != 2 {
		t.Errorf("Collect calls = %d; want 2 (KISS-no-DRY: per-policy fetch)", src.calls)
	}
}

func TestCollect_PassesSlotParamsAndExtras(t *testing.T) {
	src := &stubSource{id: "manual.pdf", emits: []string{"signed_document"},
		records: []core.EvidenceRecord{{Type: "signed_document", ID: "e/p"}}}
	reg := registry.NewSet()
	mustRegister(t, reg.Sources.Register(src))
	pp := planner.PlannedPolicy{
		Spec: core.Policy{
			ID: "p1",
			Slots: map[string]core.Slot{
				"doc": {Type: "signed_document", Cardinality: core.SlotExactlyOne, Required: true},
			},
		},
		Bindings: map[string][]planner.Binding{
			"doc": {{SourceID: "manual.pdf", CatalogID: "access_review_quarterly", SlotParams: map[string]any{"custom": 42}}},
		},
	}
	_, err := Collect(context.Background(), &Input{
		Plan:             &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Sources:          reg.Sources,
		Vault:            newMemVault(),
		RunRoot:          "r",
		SlotParamsExtras: map[string]any{"period_id": "2026-Q1"},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := src.lastReq.Params
	if got["catalog_id"] != "access_review_quarterly" {
		t.Errorf("catalog_id missing: %v", got)
	}
	if got["period_id"] != "2026-Q1" {
		t.Errorf("period_id missing: %v", got)
	}
	if got["custom"] != 42 {
		t.Errorf("custom slot param dropped: %v", got)
	}
	if src.lastReq.EvidenceType != "signed_document" {
		t.Errorf("EvidenceType = %q", src.lastReq.EvidenceType)
	}
}

func TestEnvelopePath_FormatsConsistently(t *testing.T) {
	got := envelopePath("soc2/2026-Q1/run_x", "p1", "user_record", "aws.iam", "")
	want := "soc2/2026-Q1/run_x/policies/p1/envelopes/user_record__aws.iam.json"
	if got != want {
		t.Errorf("envelopePath = %q; want %q", got, want)
	}
	got = envelopePath("r", "p1", "signed_document", "manual.pdf", "access_review_quarterly")
	want = "r/policies/p1/envelopes/signed_document__manual.pdf_access_review_quarterly.json"
	if got != want {
		t.Errorf("envelopePath catalog = %q; want %q", got, want)
	}
}

func mustRegister(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
}

func recordIDs(rs []core.EvidenceRecord) []string {
	out := make([]string, len(rs))
	for i := range rs {
		out[i] = rs[i].ID
	}
	return out
}
