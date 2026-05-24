package iam

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	crm "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI lets tests drive the plugin without real GCP calls.
type fakeAPI struct {
	policy *crm.Policy
	err    error

	getCount int
}

func (f *fakeAPI) GetIamPolicy(_ context.Context, _ string) (*crm.Policy, error) {
	f.getCount++
	if f.err != nil {
		return nil, f.err
	}
	return f.policy, nil
}

func TestPlugin_IDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{policy: &crm.Policy{}}, ProjectID: "p"})
	if p.ID() != SourceID {
		t.Errorf("ID = %q; want %q", p.ID(), SourceID)
	}
	em := p.Emits()
	if len(em) != 1 || em[0] != EvidenceTypeID {
		t.Errorf("Emits = %v; want [%s]", em, EvidenceTypeID)
	}
}

func TestPlugin_InitNoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{policy: &crm.Policy{}}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

func TestCollect_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{policy: &crm.Policy{
		Bindings: []*crm.Binding{
			{Role: "roles/viewer", Members: []string{"user:alice@acme.com", "user:bob@acme.com"}},
			{Role: "roles/owner", Members: []string{"user:carol@acme.com"}},
		},
	}}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "proj-1", Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID, PolicyID: "p1", SlotName: "bindings"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("len(records) = %d; want 3", len(records))
	}
	// Sorted: roles/owner|... < roles/viewer|...
	if !strings.HasPrefix(records[0].ID, "roles/owner|") {
		t.Errorf("records[0].ID = %q; want roles/owner first", records[0].ID)
	}
	if !strings.HasPrefix(records[1].ID, "roles/viewer|user:alice") {
		t.Errorf("records[1].ID = %q", records[1].ID)
	}
	for i := range records {
		if records[i].CollectedAt != now {
			t.Errorf("record[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("record[%d].SourceID = %q", i, records[i].SourceID)
		}
	}

	var owner bindingPayload
	if err := json.Unmarshal(records[0].Payload, &owner); err != nil {
		t.Fatalf("Unmarshal owner: %v", err)
	}
	if owner.Role != "roles/owner" || owner.Member != "user:carol@acme.com" {
		t.Errorf("owner payload = %+v", owner)
	}
	if owner.MemberType != "user" {
		t.Errorf("MemberType = %q; want user", owner.MemberType)
	}
	if owner.ProjectID != "proj-1" {
		t.Errorf("ProjectID = %q", owner.ProjectID)
	}
	if records[0].IdentityKey != "carol@acme.com" {
		t.Errorf("IdentityKey = %q; want carol@acme.com", records[0].IdentityKey)
	}
}

func TestCollect_NoBindings(t *testing.T) {
	p := New(Options{API: &fakeAPI{policy: &crm.Policy{}}})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("len(records) = %d; want 0", len(records))
	}
}

func TestCollect_NilBindingsSkipped(t *testing.T) {
	fake := &fakeAPI{policy: &crm.Policy{Bindings: []*crm.Binding{nil}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("len(records) = %d; want 0", len(records))
	}
}

func TestCollect_ConditionFlagged(t *testing.T) {
	fake := &fakeAPI{policy: &crm.Policy{
		Bindings: []*crm.Binding{
			{Role: "roles/editor", Members: []string{"user:dave@acme.com"}, Condition: &crm.Expr{Expression: "true"}},
		},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d", len(records))
	}
	var payload bindingPayload
	if err := json.Unmarshal(records[0].Payload, &payload); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !payload.HasCondition {
		t.Errorf("HasCondition = false; want true")
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{policy: &crm.Policy{}}})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: "s3_bucket"})
	if err == nil || !strings.Contains(err.Error(), "unsupported evidence type") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_GetIamPolicyError(t *testing.T) {
	p := New(Options{API: &fakeAPI{err: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err == nil || !strings.Contains(err.Error(), "get iam policy") {
		t.Errorf("want get iam policy error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsedWhenNotInjected(t *testing.T) {
	fake := &fakeAPI{policy: &crm.Policy{
		Bindings: []*crm.Binding{{Role: "roles/viewer", Members: []string{"user:a@b.com"}}},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero; want default-now-injected value")
	}
}

func TestMemberType_KnownPrefixes(t *testing.T) {
	cases := map[string]string{
		"user:alice@acme.com":        "user",
		"serviceAccount:sa@proj.iam": "serviceAccount",
		"group:admins@acme.com":      "group",
		"domain:acme.com":            "domain",
		"allUsers":                   "",
		"allAuthenticatedUsers":      "",
	}
	for in, want := range cases {
		if got := memberType(in); got != want {
			t.Errorf("memberType(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestIdentityKey_StripsPrefix(t *testing.T) {
	if got := identityKey("user:alice@acme.com"); got != "alice@acme.com" {
		t.Errorf("identityKey = %q", got)
	}
	if got := identityKey("allUsers"); got != "allUsers" {
		t.Errorf("identityKey = %q", got)
	}
}

func TestNewFromGCP_SmokeTest(t *testing.T) {
	// We can't reliably test the success path without GCP credentials,
	// but we exercise the constructor. Some environments will succeed
	// (Application Default Credentials present), others will error —
	// both outcomes are acceptable for the smoke test.
	p, err := NewFromGCP(context.Background(), "proj-1")
	if err != nil {
		t.Logf("NewFromGCP errored (acceptable in CI without ADC): %v", err)
		return
	}
	if p.ID() != SourceID {
		t.Errorf("ID = %q", p.ID())
	}
}

func TestCollect_KISSNoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{policy: &crm.Policy{
		Bindings: []*crm.Binding{{Role: "roles/viewer", Members: []string{"user:a@b.com"}}},
	}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.getCount != 3 {
		t.Errorf("getCount = %d; want 3 (no caching across Collect calls per KISS-no-DRY)", fake.getCount)
	}
}
