package asset

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

	cloudasset "google.golang.org/api/cloudasset/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

// fakeAPI drives the plugin without hitting GCP. It records the project
// argument and call count to assert plumbing and the KISS-no-DRY axiom.
type fakeAPI struct {
	feeds   []*cloudasset.Feed
	err     error
	calls   int
	project string
}

func (f *fakeAPI) ListFeeds(_ context.Context, project string) ([]*cloudasset.Feed, error) {
	f.calls++
	f.project = project
	if f.err != nil {
		return nil, f.err
	}
	return f.feeds, nil
}

func assetReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1"}
}

func decodePayload(t *testing.T, r *core.EvidenceRecord) trackingPayload {
	t.Helper()
	var p trackingPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	return p
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != "gcp.asset" {
		t.Errorf("ID = %q; want gcp.asset", p.ID())
	}
	emits := p.Emits()
	if len(emits) != 1 || emits[0] != "config_change_tracking" {
		t.Errorf("Emits = %v; want [config_change_tracking]", emits)
	}
}

func TestInit_NoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// TestCollect_Recording covers a project with two feeds, one of them
// unrestricted by type (catch-all wildcard) → is_recording and
// all_resource_types both true.
func TestCollect_Recording(t *testing.T) {
	fake := &fakeAPI{
		feeds: []*cloudasset.Feed{
			{Name: "projects/123/feeds/scoped", AssetTypes: []string{"compute.googleapis.com/Instance"}},
			{Name: "projects/123/feeds/all", AssetTypes: []string{".*"}},
		},
	}
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "proj-1", Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), assetReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.project != "proj-1" {
		t.Errorf("project = %q; want proj-1", fake.project)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1 (project-level singleton)", len(records))
	}
	r := records[0]
	if r.Type != EvidenceTypeID || r.SourceID != SourceID {
		t.Errorf("meta = %q/%q; want %q/%q", r.Type, r.SourceID, EvidenceTypeID, SourceID)
	}
	if !r.CollectedAt.Equal(now) {
		t.Errorf("CollectedAt = %v; want %v", r.CollectedAt, now)
	}
	if r.IdentityKey != "" {
		t.Errorf("IdentityKey = %q; want empty", r.IdentityKey)
	}
	if r.ID != "projects/proj-1/configChangeTracking" {
		t.Errorf("ID = %q; want projects/proj-1/configChangeTracking", r.ID)
	}

	want := trackingPayload{
		ID:               "projects/proj-1/configChangeTracking",
		Name:             "proj-1",
		Provider:         "gcp",
		IsRecording:      true,
		AllResourceTypes: true,
		FeedCount:        2,
	}
	if got := decodePayload(t, &r); !reflect.DeepEqual(got, want) {
		t.Errorf("payload = %+v; want %+v", got, want)
	}
}

// TestCollect_NoFeeds covers a project with no asset feeds: is_recording
// and all_resource_types are false (the honest "no change-tracking
// pipeline configured" finding), even though Asset Inventory is always-on.
func TestCollect_NoFeeds(t *testing.T) {
	fake := &fakeAPI{}
	p := New(Options{API: fake, ProjectID: "proj-2"})
	records, err := p.Collect(context.Background(), assetReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := decodePayload(t, &records[0])
	want := trackingPayload{
		ID:               "projects/proj-2/configChangeTracking",
		Name:             "proj-2",
		Provider:         "gcp",
		IsRecording:      false,
		AllResourceTypes: false,
		FeedCount:        0,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("payload = %+v; want %+v", got, want)
	}
}

// TestCollect_ScopedOnly covers a project whose only feed is type-scoped:
// is_recording true, but all_resource_types false (tracks a subset).
func TestCollect_ScopedOnly(t *testing.T) {
	fake := &fakeAPI{feeds: []*cloudasset.Feed{
		nil, // nil feed skipped, not counted
		{Name: "projects/123/feeds/scoped", AssetTypes: []string{"storage.googleapis.com/Bucket"}},
	}}
	p := New(Options{API: fake, ProjectID: "proj-3"})
	records, err := p.Collect(context.Background(), assetReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := decodePayload(t, &records[0])
	if !got.IsRecording || got.AllResourceTypes || got.FeedCount != 1 {
		t.Errorf("got is_recording=%v all_types=%v count=%d; want true/false/1", got.IsRecording, got.AllResourceTypes, got.FeedCount)
	}
}

func TestFeedCoversAllTypes(t *testing.T) {
	cases := []struct {
		name string
		feed *cloudasset.Feed
		want bool
	}{
		{"empty asset types", &cloudasset.Feed{}, true},
		{"dot-star wildcard", &cloudasset.Feed{AssetTypes: []string{".*"}}, true},
		{"star wildcard", &cloudasset.Feed{AssetTypes: []string{"*"}}, true},
		{"wildcard with padding", &cloudasset.Feed{AssetTypes: []string{" .* "}}, true},
		{"specific type only", &cloudasset.Feed{AssetTypes: []string{"compute.googleapis.com/Instance"}}, false},
		{"mixed specific then wildcard", &cloudasset.Feed{AssetTypes: []string{"compute.googleapis.com/Instance", "*"}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := feedCoversAllTypes(c.feed); got != c.want {
				t.Errorf("feedCoversAllTypes = %v; want %v", got, c.want)
			}
		})
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"log_group"}})
	if err == nil {
		t.Fatal("want error for unaccepted type; got nil")
	}
}

func TestCollect_PropagatesError(t *testing.T) {
	wantErr := errors.New("boom")
	p := New(Options{API: &fakeAPI{err: wantErr}})
	_, err := p.Collect(context.Background(), assetReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_KISS_NoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), assetReq()); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.calls != 3 {
		t.Errorf("calls = %d; want 3 (no caching per KISS-no-DRY)", fake.calls)
	}
}

// TestRealAsset_ListFeeds exercises the production adapter against an
// httptest server, verifying it reads the feeds list (single request, no
// pagination).
func TestRealAsset_ListFeeds(t *testing.T) {
	body := mustMarshal(t, cloudasset.ListFeedsResponse{
		Feeds: []*cloudasset.Feed{
			{Name: "projects/123/feeds/a", AssetTypes: []string{".*"}},
			{Name: "projects/123/feeds/b"},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/feeds") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r := &realAsset{svc: newTestService(t, srv)}
	feeds, err := r.ListFeeds(context.Background(), "p")
	if err != nil {
		t.Fatalf("ListFeeds: %v", err)
	}
	if len(feeds) != 2 {
		t.Fatalf("len = %d; want 2", len(feeds))
	}
}

func TestRealAsset_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	r := &realAsset{svc: newTestService(t, srv)}
	if _, err := r.ListFeeds(context.Background(), "p"); err == nil {
		t.Fatal("want error from 403; got nil")
	}
}

func TestBuild_RequiresProjectID(t *testing.T) {
	_, err := build(context.Background(), sources.Env{Config: map[string]any{}})
	if err == nil {
		t.Fatal("want error when project_id is missing; got nil")
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

func newTestService(t *testing.T, srv *httptest.Server) *cloudasset.Service {
	t.Helper()
	svc, err := cloudasset.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}
