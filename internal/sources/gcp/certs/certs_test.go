package certs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	certificatemanager "google.golang.org/api/certificatemanager/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI drives the plugin without hitting GCP. It records the project
// argument and call count to assert plumbing and the KISS-no-DRY axiom.
type fakeAPI struct {
	certs   []*certificatemanager.Certificate
	listErr error
	calls   int
	project string
}

func (f *fakeAPI) ListCertificates(_ context.Context, project string) ([]*certificatemanager.Certificate, error) {
	f.calls++
	f.project = project
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.certs, nil
}

func certsReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1"}
}

func decodePayload(t *testing.T, r *core.EvidenceRecord) certPayload {
	t.Helper()
	var p certPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	return p
}

func jsonKeys(t *testing.T, body []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("Unmarshal keys: %v", err)
	}
	return m
}

func ptrBool(v bool) *bool { return &v }

func TestIDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != "gcp.certs" {
		t.Errorf("ID = %q; want gcp.certs", p.ID())
	}
	emits := p.Emits()
	if len(emits) != 1 || emits[0] != "tls_certificate" {
		t.Errorf("Emits = %v; want [tls_certificate]", emits)
	}
}

func TestInit_NoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// TestCollect_SortsAndPopulates covers the happy path: an active managed
// certificate (90 days out, auto-renew true) and a self-managed certificate
// (10 days out, auto-renew omitted) emit two records sorted by ID,
// exercising the managed/self-managed branch and expiry derivation.
func TestCollect_SortsAndPopulates(t *testing.T) {
	fake := &fakeAPI{
		certs: []*certificatemanager.Certificate{
			{ // self-managed, sorts second by Name (us-east1 > us-central1).
				Name:        "projects/p/locations/us-east1/certificates/self-cert",
				ExpireTime:  "2026-06-26T00:00:00Z",
				SanDnsnames: []string{"api.example.com"},
				SelfManaged: &certificatemanager.SelfManagedCertificate{PemCertificate: "-----BEGIN-----"},
			},
			{ // managed, sorts first by Name.
				Name:        "projects/p/locations/us-central1/certificates/managed-cert",
				ExpireTime:  "2026-09-14T00:00:00Z",
				SanDnsnames: []string{"www.example.com", "example.com"},
				Scope:       "DEFAULT",
				Managed:     &certificatemanager.ManagedCertificate{State: "ACTIVE", Domains: []string{"www.example.com"}},
			},
		},
	}
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "proj-1", Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), certsReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.project != "proj-1" {
		t.Errorf("project = %q; want proj-1", fake.project)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	// Sorted by ID (full resource name): "...us-central1.../managed-cert"
	// sorts before "...us-east1.../self-cert" ('c' < 'e').
	if id0, id1 := decodePayload(t, &records[0]).ID, decodePayload(t, &records[1]).ID; !reflect.DeepEqual(
		[]string{id0, id1},
		[]string{
			"projects/p/locations/us-central1/certificates/managed-cert",
			"projects/p/locations/us-east1/certificates/self-cert",
		}) {
		t.Fatalf("order = %q,%q; want managed-cert before self-cert", id0, id1)
	}
	for i := range records {
		if records[i].Type != EvidenceTypeID || records[i].SourceID != SourceID {
			t.Errorf("records[%d] meta = %q/%q; want %q/%q", i, records[i].Type, records[i].SourceID, EvidenceTypeID, SourceID)
		}
		if !records[i].CollectedAt.Equal(now) {
			t.Errorf("records[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].IdentityKey != "" {
			t.Errorf("records[%d].IdentityKey = %q; want empty (certs have no identity)", i, records[i].IdentityKey)
		}
	}

	wantManaged := certPayload{
		ID:              "projects/p/locations/us-central1/certificates/managed-cert",
		Domain:          "www.example.com",
		Provider:        "gcp",
		Status:          "ISSUED",
		NotAfter:        "2026-09-14T00:00:00Z",
		DaysUntilExpiry: 90,
		IsManaged:       true,
		AutoRenew:       ptrBool(true),
		Location:        "us-central1",
		SanDNSNames:     []string{"www.example.com", "example.com"},
		ManagedState:    "ACTIVE",
		Scope:           "DEFAULT",
	}
	if got := decodePayload(t, &records[0]); !reflect.DeepEqual(got, wantManaged) {
		t.Errorf("managed payload = %+v; want %+v", got, wantManaged)
	}

	wantSelf := certPayload{
		ID:              "projects/p/locations/us-east1/certificates/self-cert",
		Domain:          "api.example.com",
		Provider:        "gcp",
		Status:          "ISSUED",
		NotAfter:        "2026-06-26T00:00:00Z",
		DaysUntilExpiry: 10,
		IsManaged:       false,
		Location:        "us-east1",
		SanDNSNames:     []string{"api.example.com"},
	}
	if got := decodePayload(t, &records[1]); !reflect.DeepEqual(got, wantSelf) {
		t.Errorf("self-managed payload = %+v; want %+v", got, wantSelf)
	}

	// auto_renew present for managed, omitted (not false) for self-managed.
	if _, present := jsonKeys(t, records[0].Payload)["auto_renew"]; !present {
		t.Errorf("managed cert should emit auto_renew; body = %s", records[0].Payload)
	}
	if _, present := jsonKeys(t, records[1].Payload)["auto_renew"]; present {
		t.Errorf("self-managed cert should omit auto_renew; body = %s", records[1].Payload)
	}
}

// TestBuildPayload_Expired verifies an expired managed certificate maps to
// status EXPIRED with a negative days_until_expiry.
func TestBuildPayload_Expired(t *testing.T) {
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	got := buildPayload(&certificatemanager.Certificate{
		Name:        "projects/p/locations/us-central1/certificates/old",
		ExpireTime:  "2026-06-06T00:00:00Z", // 10 days ago
		SanDnsnames: []string{"old.example.com"},
		Managed:     &certificatemanager.ManagedCertificate{State: "ACTIVE"},
	}, now)
	if got.Status != "EXPIRED" {
		t.Errorf("status = %q; want EXPIRED", got.Status)
	}
	if got.DaysUntilExpiry != -10 {
		t.Errorf("days_until_expiry = %d; want -10", got.DaysUntilExpiry)
	}
	if got.NotAfter != "2026-06-06T00:00:00Z" {
		t.Errorf("not_after = %q; want 2026-06-06T00:00:00Z", got.NotAfter)
	}
}

// TestMapStatus covers the managed-state mapping, the expiry override, and
// the self-managed default.
func TestMapStatus(t *testing.T) {
	managed := func(state string) *certificatemanager.Certificate {
		return &certificatemanager.Certificate{Managed: &certificatemanager.ManagedCertificate{State: state}}
	}
	self := &certificatemanager.Certificate{SelfManaged: &certificatemanager.SelfManagedCertificate{}}
	cases := []struct {
		name    string
		cert    *certificatemanager.Certificate
		expired bool
		want    string
	}{
		{"managed active", managed("ACTIVE"), false, "ISSUED"},
		{"managed provisioning", managed("PROVISIONING"), false, "PENDING_VALIDATION"},
		{"managed failed", managed("FAILED"), false, "FAILED"},
		{"managed unspecified", managed("STATE_UNSPECIFIED"), false, "INACTIVE"},
		{"managed empty", managed(""), false, "INACTIVE"},
		{"managed expired overrides active", managed("ACTIVE"), true, "EXPIRED"},
		{"self-managed present", self, false, "ISSUED"},
		{"self-managed expired", self, true, "EXPIRED"},
	}
	for _, c := range cases {
		if got := mapStatus(c.cert, c.expired); got != c.want {
			t.Errorf("%s: mapStatus = %q; want %q", c.name, got, c.want)
		}
	}
}

// TestPrimaryDomain covers the SAN-first, managed-domains fallback, and
// empty cases.
func TestPrimaryDomain(t *testing.T) {
	cases := []struct {
		name string
		cert *certificatemanager.Certificate
		want string
	}{
		{"san first", &certificatemanager.Certificate{SanDnsnames: []string{"a.example.com", "b.example.com"}}, "a.example.com"},
		{
			"managed domains fallback",
			&certificatemanager.Certificate{Managed: &certificatemanager.ManagedCertificate{Domains: []string{"m.example.com"}}},
			"m.example.com",
		},
		{"none", &certificatemanager.Certificate{}, ""},
	}
	for _, c := range cases {
		if got := primaryDomain(c.cert); got != c.want {
			t.Errorf("%s: primaryDomain = %q; want %q", c.name, got, c.want)
		}
	}
}

// TestExpiry covers days derivation, the empty timestamp, and an
// unparseable timestamp passed through verbatim.
func TestExpiry(t *testing.T) {
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name         string
		expireTime   string
		wantNotAfter string
		wantDays     int
		wantExpired  bool
	}{
		{"future 90d", "2026-09-14T00:00:00Z", "2026-09-14T00:00:00Z", 90, false},
		{"past 10d", "2026-06-06T00:00:00Z", "2026-06-06T00:00:00Z", -10, true},
		{"offset normalized to UTC", "2026-06-26T02:00:00+02:00", "2026-06-26T00:00:00Z", 10, false},
		{"empty", "", "", 0, false},
		{"unparseable passthrough", "not-a-time", "not-a-time", 0, false},
	}
	for _, c := range cases {
		gotNotAfter, gotDays, gotExpired := expiry(c.expireTime, now)
		if gotNotAfter != c.wantNotAfter || gotDays != c.wantDays || gotExpired != c.wantExpired {
			t.Errorf("%s: expiry = (%q, %d, %v); want (%q, %d, %v)",
				c.name, gotNotAfter, gotDays, gotExpired, c.wantNotAfter, c.wantDays, c.wantExpired)
		}
	}
}

// TestLocationFromName covers the location parse and the fallback.
func TestLocationFromName(t *testing.T) {
	cases := map[string]string{
		"projects/p/locations/us-central1/certificates/c": "us-central1",
		"projects/p/locations/global/certificates/c":      "global",
		"projects/p/locations/us-east1":                   "us-east1",
		"no-locations-segment":                            "",
		"":                                                "",
	}
	for in, want := range cases {
		if got := locationFromName(in); got != want {
			t.Errorf("locationFromName(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestCollect_NilCertSkipped(t *testing.T) {
	fake := &fakeAPI{certs: []*certificatemanager.Certificate{nil, {Name: "projects/p/locations/us-central1/certificates/real"}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), certsReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1 (nil cert skipped)", len(records))
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
	_, err := p.Collect(context.Background(), certsReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_KISS_NoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{certs: []*certificatemanager.Certificate{{Name: "projects/p/locations/us-central1/certificates/c"}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), certsReq()); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.calls != 3 {
		t.Errorf("calls = %d; want 3 (no caching per KISS-no-DRY)", fake.calls)
	}
}

// TestRealCertManager_ListCertificates exercises the production adapter
// against an httptest server, verifying it lists certs via the all-locations
// wildcard.
func TestRealCertManager_ListCertificates(t *testing.T) {
	body := mustMarshal(t, certificatemanager.ListCertificatesResponse{
		Certificates: []*certificatemanager.Certificate{
			{Name: "projects/p/locations/us-central1/certificates/a"},
			{Name: "projects/p/locations/us-east1/certificates/b"},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r := &realCertManager{svc: newTestService(t, srv)}
	certs, err := r.ListCertificates(context.Background(), "p")
	if err != nil {
		t.Fatalf("ListCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("len = %d; want 2", len(certs))
	}
}

// TestRealCertManager_UnreachableErrors verifies the adapter refuses a
// partial result: any unreachable location is an error, not a silent drop.
func TestRealCertManager_UnreachableErrors(t *testing.T) {
	body := mustMarshal(t, certificatemanager.ListCertificatesResponse{
		Certificates: []*certificatemanager.Certificate{{Name: "projects/p/locations/us-central1/certificates/a"}},
		Unreachable:  []string{"us-west4"},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r := &realCertManager{svc: newTestService(t, srv)}
	if _, err := r.ListCertificates(context.Background(), "p"); err == nil {
		t.Fatal("want error when a location is unreachable; got nil")
	}
}

// TestRealCertManager_Error verifies the adapter surfaces HTTP errors.
func TestRealCertManager_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	r := &realCertManager{svc: newTestService(t, srv)}
	if _, err := r.ListCertificates(context.Background(), "p"); err == nil {
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

func newTestService(t *testing.T, srv *httptest.Server) *certificatemanager.Service {
	t.Helper()
	svc, err := certificatemanager.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}
