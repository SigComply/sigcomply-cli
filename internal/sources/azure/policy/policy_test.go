package policy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	armpolicy "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

var fixedNow = time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

func mustUnmarshal(t *testing.T, raw json.RawMessage, dst any) {
	t.Helper()
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

// fakeAPI records calls and returns staged assignments.
type fakeAPI struct {
	assignments []*armpolicy.Assignment
	err         error
	calls       int
}

func (f *fakeAPI) ListAssignments(context.Context) ([]*armpolicy.Assignment, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.assignments, nil
}

func req() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}
}

// assignment builds a policy assignment with the given scope and enforcement
// mode (mode nil → the Azure "Default" enforced behavior).
func assignment(name, scope string, mode *armpolicy.EnforcementMode) *armpolicy.Assignment {
	return &armpolicy.Assignment{
		ID:   to.Ptr("/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/" + name),
		Name: to.Ptr(name),
		Properties: &armpolicy.AssignmentProperties{
			Scope:           to.Ptr(scope),
			EnforcementMode: mode,
		},
	}
}

const (
	subScope = "/subscriptions/sub-1"
	rgScope  = "/subscriptions/sub-1/resourceGroups/rg1"
)

func TestIDAndEmits(t *testing.T) {
	p := New(Options{})
	if got := p.ID(); got != "azure.policy" {
		t.Errorf("ID() = %q, want azure.policy", got)
	}
	got := p.Emits()
	if len(got) != 1 || got[0] != EvidenceTypeID {
		t.Errorf("Emits() = %v, want [config_change_tracking]", got)
	}
}

func TestCollect_RejectsNonEmittedType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "config_change_tracking") {
		t.Fatalf("expected rejection error, got %v", err)
	}
}

func TestCollect_MapsFullPayload(t *testing.T) {
	donot := to.Ptr(armpolicy.EnforcementModeDoNotEnforce)
	deflt := to.Ptr(armpolicy.EnforcementModeDefault)
	f := &fakeAPI{assignments: []*armpolicy.Assignment{
		assignment("sub-enforced", subScope, deflt),  // subscription-scoped, enforced
		assignment("rg-audit", rgScope, donot),       // rg-scoped, audit-only
		assignment("sub-default", subScope+"/", nil), // subscription-scoped (trailing slash), nil mode → enforced
	}}
	p := New(Options{API: f, SubscriptionID: "sub-1", Now: func() time.Time { return fixedNow }})

	recs, err := p.Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1 (subscription singleton)", len(recs))
	}
	r := recs[0]
	if r.Type != EvidenceTypeID || r.SourceID != SourceID || !r.CollectedAt.Equal(fixedNow) {
		t.Errorf("record Type/SourceID/CollectedAt = %s/%s/%v", r.Type, r.SourceID, r.CollectedAt)
	}
	if r.Scope == nil || r.Scope.Account != "sub-1" {
		t.Errorf("scope = %+v, want Account=sub-1", r.Scope)
	}
	if r.IdentityKey != "" {
		t.Errorf("unexpected IdentityKey %q", r.IdentityKey)
	}
	if r.ID != "subscriptions/sub-1/configChangeTracking" {
		t.Errorf("ID = %q", r.ID)
	}

	var got trackingPayload
	mustUnmarshal(t, r.Payload, &got)
	want := trackingPayload{
		ID:                      "subscriptions/sub-1/configChangeTracking",
		Name:                    "sub-1",
		Provider:                "azure",
		IsRecording:             true,
		AllResourceTypes:        true,
		AssignmentCount:         3,
		EnforcedCount:           2, // sub-enforced + sub-default(nil)
		SubscriptionScopedCount: 2, // sub-enforced + sub-default
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("payload mismatch:\n got  %+v\n want %+v", got, want)
	}
}

func TestCollect_NoAssignments(t *testing.T) {
	f := &fakeAPI{assignments: nil}
	p := New(Options{API: f, SubscriptionID: "sub-1", Now: func() time.Time { return fixedNow }})
	recs, err := p.Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got trackingPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	want := trackingPayload{
		ID:       "subscriptions/sub-1/configChangeTracking",
		Name:     "sub-1",
		Provider: "azure",
		// is_recording / all_resource_types honestly false on a fresh subscription.
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("empty-subscription payload mismatch:\n got  %+v\n want %+v", got, want)
	}
}

func TestCollect_OnlyRGScoped_AllResourceTypesFalse(t *testing.T) {
	f := &fakeAPI{assignments: []*armpolicy.Assignment{
		assignment("rg-only", rgScope, nil),
	}}
	recs, err := New(Options{API: f, SubscriptionID: "sub-1"}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got trackingPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if !got.IsRecording {
		t.Errorf("is_recording should be true (an assignment exists)")
	}
	if got.AllResourceTypes || got.SubscriptionScopedCount != 0 {
		t.Errorf("all_resource_types should be false for rg-only scope, got %+v", got)
	}
}

func TestCollect_NilEntriesSkipped(t *testing.T) {
	f := &fakeAPI{assignments: []*armpolicy.Assignment{
		nil,
		assignment("ok", subScope, nil),
		nil,
	}}
	recs, err := New(Options{API: f, SubscriptionID: "sub-1"}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got trackingPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if got.AssignmentCount != 1 {
		t.Errorf("nil assignments should be skipped, assignment_count = %d, want 1", got.AssignmentCount)
	}
}

func TestCollect_ErrorPropagation(t *testing.T) {
	_, err := New(Options{API: &fakeAPI{err: errors.New("list boom")}}).Collect(context.Background(), req())
	if err == nil || !strings.Contains(err.Error(), "list boom") {
		t.Fatalf("list error should surface, got %v", err)
	}
}

func TestCollect_NoScopeWhenSubscriptionEmpty(t *testing.T) {
	recs, err := New(Options{API: &fakeAPI{}}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if recs[0].Scope != nil {
		t.Errorf("scope should be nil when subscription id is empty, got %+v", recs[0].Scope)
	}
}

// TestCollect_ReFetch asserts the KISS-no-DRY contract: each Collect re-lists,
// caching nothing across calls.
func TestCollect_ReFetch(t *testing.T) {
	f := &fakeAPI{assignments: []*armpolicy.Assignment{assignment("a", subScope, nil)}}
	p := New(Options{API: f, SubscriptionID: "sub-1"})
	for i := 0; i < 3; i++ {
		if _, err := p.Collect(context.Background(), req()); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
	}
	if f.calls != 3 {
		t.Errorf("ListAssignments called %d times, want 3", f.calls)
	}
}

func TestAssignmentEnforced(t *testing.T) {
	donot := to.Ptr(armpolicy.EnforcementModeDoNotEnforce)
	deflt := to.Ptr(armpolicy.EnforcementModeDefault)
	enroll := to.Ptr(armpolicy.EnforcementModeEnroll)
	cases := []struct {
		name string
		a    *armpolicy.Assignment
		want bool
	}{
		{"nil mode → enforced (Azure default)", assignment("x", subScope, nil), true},
		{"Default → enforced", assignment("x", subScope, deflt), true},
		{"DoNotEnforce → not enforced", assignment("x", subScope, donot), false},
		{"Enroll → not enforced", assignment("x", subScope, enroll), false},
		{"nil properties → enforced", &armpolicy.Assignment{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := assignmentEnforced(tc.a); got != tc.want {
				t.Errorf("assignmentEnforced = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAssignmentSubscriptionScoped(t *testing.T) {
	want := strings.ToLower("/subscriptions/sub-1")
	cases := []struct {
		name string
		a    *armpolicy.Assignment
		ok   bool
	}{
		{"exact subscription scope", assignment("x", subScope, nil), true},
		{"subscription scope trailing slash", assignment("x", subScope+"/", nil), true},
		{"mixed-case subscription scope", assignment("x", "/subscriptions/SUB-1", nil), true},
		{"rg scope", assignment("x", rgScope, nil), false},
		{"nil scope", &armpolicy.Assignment{Properties: &armpolicy.AssignmentProperties{}}, false},
		{"nil properties", &armpolicy.Assignment{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := assignmentSubscriptionScoped(tc.a, want); got != tc.ok {
				t.Errorf("assignmentSubscriptionScoped = %v, want %v", got, tc.ok)
			}
		})
	}
}

func TestBuild_RequiresSubscriptionID(t *testing.T) {
	_, err := sources.Build(context.Background(), SourceID, sources.Env{Config: map[string]any{}})
	if err == nil || !strings.Contains(err.Error(), "subscription_id") {
		t.Fatalf("expected subscription_id required error, got %v", err)
	}
}

// --- real adapter (httptest) ---

type fakeCred struct{}

func (fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func realPolicyPointedAt(t *testing.T, srv *httptest.Server) *realPolicy {
	t.Helper()
	opts := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.azure.com"},
		}},
		Transport: srv.Client(),
	}}
	rp, err := newRealPolicy("sub-1", fakeCred{}, opts)
	if err != nil {
		t.Fatalf("newRealPolicy: %v", err)
	}
	return rp
}

func TestRealPolicy_ListAssignments_HappyPath(t *testing.T) {
	body := mustMarshal(t, armpolicy.AssignmentListResult{Value: []*armpolicy.Assignment{
		assignment("a1", subScope, to.Ptr(armpolicy.EnforcementModeDefault)),
	}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/policyAssignments") {
			_, _ = w.Write(body) //nolint:errcheck // test handler
			return
		}
		t.Errorf("unexpected path: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rp := realPolicyPointedAt(t, srv)
	got, err := rp.ListAssignments(context.Background())
	if err != nil || len(got) != 1 || deref(got[0].Name) != "a1" {
		t.Fatalf("ListAssignments = %+v, err %v", got, err)
	}
	if !assignmentEnforced(got[0]) {
		t.Errorf("expected enforced assignment to round-trip, got %+v", got[0])
	}
}

func TestRealPolicy_ListError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	rp := realPolicyPointedAt(t, srv)
	if _, err := rp.ListAssignments(context.Background()); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
