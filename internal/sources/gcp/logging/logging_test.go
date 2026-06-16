package logging

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

	logging "google.golang.org/api/logging/v2"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI drives the plugin without hitting GCP. It records the project
// argument and call count to assert plumbing and the KISS-no-DRY axiom.
type fakeAPI struct {
	buckets []*logging.LogBucket
	err     error
	calls   int
	project string
}

func (f *fakeAPI) ListLogBuckets(_ context.Context, project string) ([]*logging.LogBucket, error) {
	f.calls++
	f.project = project
	if f.err != nil {
		return nil, f.err
	}
	return f.buckets, nil
}

func logReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1"}
}

func decodePayload(t *testing.T, r *core.EvidenceRecord) logGroupPayload {
	t.Helper()
	var p logGroupPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	return p
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != "gcp.logging" {
		t.Errorf("ID = %q; want gcp.logging", p.ID())
	}
	emits := p.Emits()
	if len(emits) != 1 || emits[0] != "log_group" {
		t.Errorf("Emits = %v; want [log_group]", emits)
	}
}

func TestInit_NoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// TestCollect_SortsAndPopulates covers the happy path: a long-retention,
// locked, CMEK-encrypted regional bucket and the default 30-day
// Google-managed _Default bucket emit two records sorted by ID with all
// required fields and the GCP extras.
func TestCollect_SortsAndPopulates(t *testing.T) {
	fake := &fakeAPI{
		buckets: []*logging.LogBucket{
			{ // _Default: 30-day, Google-managed — honestly fails ≥90/≥365.
				Name:           "projects/p/locations/global/buckets/_Default",
				RetentionDays:  30,
				LifecycleState: "ACTIVE",
			},
			{ // long-retention, locked, CMEK regional bucket.
				Name:           "projects/p/locations/us-east1/buckets/audit",
				RetentionDays:  400,
				Locked:         true,
				LifecycleState: "ACTIVE",
				CmekSettings:   &logging.CmekSettings{KmsKeyName: "projects/p/locations/us-east1/keyRings/r/cryptoKeys/k"},
			},
		},
	}
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "proj-1", Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), logReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.project != "proj-1" {
		t.Errorf("project = %q; want proj-1", fake.project)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	// Sorted by ID (full resource name): "..._Default" before "...audit".
	if records[0].ID != "projects/p/locations/global/buckets/_Default" || records[1].ID != "projects/p/locations/us-east1/buckets/audit" {
		t.Fatalf("IDs = %q,%q; want _Default before audit", records[0].ID, records[1].ID)
	}
	for i := range records {
		if records[i].Type != EvidenceTypeID || records[i].SourceID != SourceID {
			t.Errorf("records[%d] meta = %q/%q; want %q/%q", i, records[i].Type, records[i].SourceID, EvidenceTypeID, SourceID)
		}
		if !records[i].CollectedAt.Equal(now) {
			t.Errorf("records[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].IdentityKey != "" {
			t.Errorf("records[%d].IdentityKey = %q; want empty (log groups have no identity)", i, records[i].IdentityKey)
		}
	}

	wantDefault := logGroupPayload{
		ID: "projects/p/locations/global/buckets/_Default", Name: "_Default", Provider: "gcp",
		RetentionSet: true, RetentionDays: 30, KMSEncrypted: false,
		Location: "global", Locked: false, LifecycleState: "ACTIVE",
	}
	if got := decodePayload(t, &records[0]); !reflect.DeepEqual(got, wantDefault) {
		t.Errorf("_Default payload = %+v; want %+v", got, wantDefault)
	}

	wantAudit := logGroupPayload{
		ID: "projects/p/locations/us-east1/buckets/audit", Name: "audit", Provider: "gcp",
		RetentionSet: true, RetentionDays: 400, KMSEncrypted: true,
		Location: "us-east1", Locked: true, LifecycleState: "ACTIVE",
		KMSKeyName: "projects/p/locations/us-east1/keyRings/r/cryptoKeys/k",
	}
	if got := decodePayload(t, &records[1]); !reflect.DeepEqual(got, wantAudit) {
		t.Errorf("audit payload = %+v; want %+v", got, wantAudit)
	}
}

// TestRetentionSet_NeverExpire covers a bucket with RetentionDays==0
// (no retention configured) → retention_set=false, retention_days=0.
func TestRetentionSet_NeverExpire(t *testing.T) {
	fake := &fakeAPI{buckets: []*logging.LogBucket{
		{Name: "projects/p/locations/global/buckets/_Default", RetentionDays: 0},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), logReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := decodePayload(t, &records[0])
	if got.RetentionSet || got.RetentionDays != 0 {
		t.Errorf("retention_set/days = %v/%d; want false/0", got.RetentionSet, got.RetentionDays)
	}
}

func TestCollect_NilBucketSkipped(t *testing.T) {
	fake := &fakeAPI{buckets: []*logging.LogBucket{
		nil,
		{Name: "projects/p/locations/global/buckets/real", RetentionDays: 90},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), logReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1 (nil bucket skipped)", len(records))
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"kms_key"}})
	if err == nil {
		t.Fatal("want error for unaccepted type; got nil")
	}
}

func TestCollect_PropagatesError(t *testing.T) {
	wantErr := errors.New("boom")
	p := New(Options{API: &fakeAPI{err: wantErr}})
	_, err := p.Collect(context.Background(), logReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_KISS_NoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{buckets: []*logging.LogBucket{
		{Name: "projects/p/locations/global/buckets/x", RetentionDays: 90},
	}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), logReq()); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.calls != 3 {
		t.Errorf("calls = %d; want 3 (no caching per KISS-no-DRY)", fake.calls)
	}
}

func TestLocationFromName(t *testing.T) {
	cases := map[string]string{
		"projects/p/locations/global/buckets/_Default": "global",
		"projects/p/locations/us-east1/buckets/audit":  "us-east1",
		"projects/p/locations/eu":                      "eu",
		"no-locations-segment":                         "",
	}
	for name, want := range cases {
		if got := locationFromName(name); got != want {
			t.Errorf("locationFromName(%q) = %q; want %q", name, got, want)
		}
	}
}

// TestRealLogging_ListBuckets exercises the production adapter against an
// httptest server, verifying it pages and returns all buckets.
func TestRealLogging_ListBuckets(t *testing.T) {
	body := mustMarshal(t, logging.ListBucketsResponse{
		Buckets: []*logging.LogBucket{
			{Name: "projects/p/locations/global/buckets/_Default", RetentionDays: 30},
			{Name: "projects/p/locations/us-east1/buckets/audit", RetentionDays: 400},
		},
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/buckets") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r := &realLogging{svc: newTestService(t, srv)}
	buckets, err := r.ListLogBuckets(context.Background(), "p")
	if err != nil {
		t.Fatalf("ListLogBuckets: %v", err)
	}
	if len(buckets) != 2 {
		t.Fatalf("len = %d; want 2", len(buckets))
	}
}

// TestRealLogging_Error verifies the adapter surfaces HTTP errors.
func TestRealLogging_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	r := &realLogging{svc: newTestService(t, srv)}
	if _, err := r.ListLogBuckets(context.Background(), "p"); err == nil {
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

func newTestService(t *testing.T, srv *httptest.Server) *logging.Service {
	t.Helper()
	svc, err := logging.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}
