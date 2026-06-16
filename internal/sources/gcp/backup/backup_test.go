package backup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	backupdr "google.golang.org/api/backupdr/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI drives the plugin without hitting GCP. It records the project
// argument and call count to assert plumbing and the KISS-no-DRY axiom.
type fakeAPI struct {
	plans   []*backupdr.BackupPlan
	listErr error
	calls   int
	project string
}

func (f *fakeAPI) ListBackupPlans(_ context.Context, project string) ([]*backupdr.BackupPlan, error) {
	f.calls++
	f.project = project
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.plans, nil
}

func backupReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1"}
}

func decodePayload(t *testing.T, r *core.EvidenceRecord) planPayload {
	t.Helper()
	var p planPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	return p
}

func ptrInt64(v int64) *int64 { return &v }

func TestIDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != "gcp.backup" {
		t.Errorf("ID = %q; want gcp.backup", p.ID())
	}
	emits := p.Emits()
	if len(emits) != 1 || emits[0] != "backup_plan" {
		t.Errorf("Emits = %v; want [backup_plan]", emits)
	}
}

func TestInit_NoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// TestCollect_SortsAndPopulates covers the happy path: an active
// multi-rule compute plan (retention max 30d) and an inactive single-rule
// SQL plan (retention 14d) emit two records sorted by ID, exercising
// is_active and has_retention_rule independently.
func TestCollect_SortsAndPopulates(t *testing.T) {
	fake := &fakeAPI{
		plans: []*backupdr.BackupPlan{
			{ // inactive SQL plan, sorts second by Name (us-east1 > us-central1).
				Name:         "projects/p/locations/us-east1/backupPlans/sql-plan",
				State:        "INACTIVE",
				ResourceType: "sqladmin.googleapis.com/Instance",
				BackupRules: []*backupdr.BackupRule{
					{RuleId: "r1", BackupRetentionDays: 14},
				},
			},
			{ // active compute plan, sorts first by Name.
				Name:         "projects/p/locations/us-central1/backupPlans/daily-compute",
				State:        "ACTIVE",
				ResourceType: "compute.googleapis.com/Instance",
				BackupVault:  "projects/p/locations/us-central1/backupVaults/v1",
				BackupRules: []*backupdr.BackupRule{
					{RuleId: "r1", BackupRetentionDays: 7},
					{RuleId: "r2", BackupRetentionDays: 30},
				},
			},
		},
	}
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "proj-1", Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), backupReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.project != "proj-1" {
		t.Errorf("project = %q; want proj-1", fake.project)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	// Sorted by ID (full resource name): "...us-central1.../daily-compute"
	// sorts before "...us-east1.../sql-plan" ('c' < 'e').
	if n0, n1 := decodePayload(t, &records[0]).Name, decodePayload(t, &records[1]).Name; n0 != "daily-compute" || n1 != "sql-plan" {
		t.Fatalf("order = %q,%q; want daily-compute before sql-plan", n0, n1)
	}
	for i := range records {
		if records[i].Type != EvidenceTypeID || records[i].SourceID != SourceID {
			t.Errorf("records[%d] meta = %q/%q; want %q/%q", i, records[i].Type, records[i].SourceID, EvidenceTypeID, SourceID)
		}
		if !records[i].CollectedAt.Equal(now) {
			t.Errorf("records[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].IdentityKey != "" {
			t.Errorf("records[%d].IdentityKey = %q; want empty (plans have no identity)", i, records[i].IdentityKey)
		}
	}

	wantActive := planPayload{
		ID:   "projects/p/locations/us-central1/backupPlans/daily-compute",
		Name: "daily-compute", Provider: "gcp",
		IsActive: true, HasRetentionRule: true, RetentionDays: ptrInt64(30),
		CoversResourceTypes: []string{"compute.googleapis.com/Instance"},
		State:               "ACTIVE",
		BackupVault:         "projects/p/locations/us-central1/backupVaults/v1",
		RuleCount:           2,
	}
	if got := decodePayload(t, &records[0]); !reflect.DeepEqual(got, wantActive) {
		t.Errorf("active payload = %+v; want %+v", got, wantActive)
	}

	wantInactive := planPayload{
		ID:   "projects/p/locations/us-east1/backupPlans/sql-plan",
		Name: "sql-plan", Provider: "gcp",
		IsActive: false, HasRetentionRule: true, RetentionDays: ptrInt64(14),
		CoversResourceTypes: []string{"sqladmin.googleapis.com/Instance"},
		State:               "INACTIVE",
		RuleCount:           1,
	}
	if got := decodePayload(t, &records[1]); !reflect.DeepEqual(got, wantInactive) {
		t.Errorf("inactive payload = %+v; want %+v", got, wantInactive)
	}
}

// TestBuildPayload_NoRetention verifies a plan with no rules maps to
// has_retention_rule=false with retention_days omitted, and an empty
// rule list leaves rule_count zero.
func TestBuildPayload_NoRetention(t *testing.T) {
	got := buildPayload(&backupdr.BackupPlan{
		Name:  "projects/p/locations/us-central1/backupPlans/empty",
		State: "ACTIVE",
	})
	if got.ID != "projects/p/locations/us-central1/backupPlans/empty" || got.Name != "empty" {
		t.Errorf("id/name = %q/%q; want full-name / empty", got.ID, got.Name)
	}
	if !got.IsActive {
		t.Error("ACTIVE plan should map is_active true")
	}
	if got.HasRetentionRule {
		t.Error("plan with no rules should map has_retention_rule false")
	}
	if got.RetentionDays != nil {
		t.Errorf("retention_days should be nil/omitted; got %v", *got.RetentionDays)
	}
	if got.RuleCount != 0 || len(got.CoversResourceTypes) != 0 {
		t.Errorf("bare plan should leave rule_count/covers empty: %+v", got)
	}

	// Confirm retention_days is actually omitted from the JSON.
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, present := jsonKeys(t, body)["retention_days"]; present {
		t.Errorf("retention_days should be omitted when no rule; body = %s", body)
	}
}

func jsonKeys(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("Unmarshal keys: %v", err)
	}
	return m
}

// TestRetention covers the max-across-rules aggregation and the >0 gate.
func TestRetention(t *testing.T) {
	cases := map[string]struct {
		rules   []*backupdr.BackupRule
		wantHas bool
		wantMax *int64
	}{
		"no rules":         {nil, false, nil},
		"one rule":         {[]*backupdr.BackupRule{{BackupRetentionDays: 7}}, true, ptrInt64(7)},
		"max across rules": {[]*backupdr.BackupRule{{BackupRetentionDays: 7}, {BackupRetentionDays: 30}, {BackupRetentionDays: 14}}, true, ptrInt64(30)},
		"zero-day ignored": {[]*backupdr.BackupRule{{BackupRetentionDays: 0}}, false, nil},
		"nil rule skipped": {[]*backupdr.BackupRule{nil, {BackupRetentionDays: 5}}, true, ptrInt64(5)},
		"negative ignored": {[]*backupdr.BackupRule{{BackupRetentionDays: -1}, {BackupRetentionDays: 3}}, true, ptrInt64(3)},
		"all zero no rule": {[]*backupdr.BackupRule{{BackupRetentionDays: 0}, {BackupRetentionDays: 0}}, false, nil},
	}
	for name, c := range cases {
		has, maxDays := retention(&backupdr.BackupPlan{BackupRules: c.rules})
		if has != c.wantHas {
			t.Errorf("%s: has = %v; want %v", name, has, c.wantHas)
		}
		if !reflect.DeepEqual(maxDays, c.wantMax) {
			t.Errorf("%s: maxDays = %v; want %v", name, deref(maxDays), deref(c.wantMax))
		}
	}
}

func deref(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// TestBackupPlanShortName covers the trailing-id parse and the fallback.
func TestBackupPlanShortName(t *testing.T) {
	cases := map[string]string{
		"projects/p/locations/us-central1/backupPlans/daily": "daily",
		"daily": "daily",
		"":      "",
	}
	for in, want := range cases {
		if got := backupPlanShortName(in); got != want {
			t.Errorf("backupPlanShortName(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestCollect_NilPlanSkipped(t *testing.T) {
	fake := &fakeAPI{plans: []*backupdr.BackupPlan{nil, {Name: "projects/p/locations/us-central1/backupPlans/real"}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), backupReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1 (nil plan skipped)", len(records))
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"kms_key"}})
	if err == nil {
		t.Fatal("want error for unaccepted type; got nil")
	}
}

func TestCollect_PropagatesListError(t *testing.T) {
	wantErr := errors.New("boom")
	p := New(Options{API: &fakeAPI{listErr: wantErr}})
	_, err := p.Collect(context.Background(), backupReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_KISS_NoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{plans: []*backupdr.BackupPlan{{Name: "projects/p/locations/us-central1/backupPlans/d"}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), backupReq()); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.calls != 3 {
		t.Errorf("calls = %d; want 3 (no caching per KISS-no-DRY)", fake.calls)
	}
}

// TestRealBackupDR_ListBackupPlans exercises the production adapter against
// an httptest server, verifying it lists plans via the all-locations
// wildcard.
func TestRealBackupDR_ListBackupPlans(t *testing.T) {
	body := mustMarshal(t, backupdr.ListBackupPlansResponse{
		BackupPlans: []*backupdr.BackupPlan{
			{Name: "projects/p/locations/us-central1/backupPlans/a"},
			{Name: "projects/p/locations/us-east1/backupPlans/b"},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r := &realBackupDR{svc: newTestService(t, srv)}
	plans, err := r.ListBackupPlans(context.Background(), "p")
	if err != nil {
		t.Fatalf("ListBackupPlans: %v", err)
	}
	if len(plans) != 2 {
		t.Fatalf("len = %d; want 2", len(plans))
	}
}

// TestRealBackupDR_UnreachableErrors verifies the adapter refuses a partial
// result: any unreachable location is an error, not a silent drop.
func TestRealBackupDR_UnreachableErrors(t *testing.T) {
	body := mustMarshal(t, backupdr.ListBackupPlansResponse{
		BackupPlans: []*backupdr.BackupPlan{{Name: "projects/p/locations/us-central1/backupPlans/a"}},
		Unreachable: []string{"us-west4"},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r := &realBackupDR{svc: newTestService(t, srv)}
	if _, err := r.ListBackupPlans(context.Background(), "p"); err == nil {
		t.Fatal("want error when a location is unreachable; got nil")
	}
}

// TestRealBackupDR_Error verifies the adapter surfaces HTTP errors.
func TestRealBackupDR_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	r := &realBackupDR{svc: newTestService(t, srv)}
	if _, err := r.ListBackupPlans(context.Background(), "p"); err == nil {
		t.Fatal("want error from 403; got nil")
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return b
}

func newTestService(t *testing.T, srv *httptest.Server) *backupdr.Service {
	t.Helper()
	svc, err := backupdr.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}
