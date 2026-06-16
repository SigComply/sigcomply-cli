package audit

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

	"google.golang.org/api/cloudresourcemanager/v3"
	logging "google.golang.org/api/logging/v2"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

// fakeAPI drives the plugin without hitting GCP. It records the project
// argument and per-method call counts to assert plumbing and the
// KISS-no-DRY axiom.
type fakeAPI struct {
	configs    []*cloudresourcemanager.AuditConfig
	cmekKey    string
	configErr  error
	cmekErr    error
	configCall int
	cmekCall   int
	project    string
}

func (f *fakeAPI) GetAuditConfigs(_ context.Context, project string) ([]*cloudresourcemanager.AuditConfig, error) {
	f.configCall++
	f.project = project
	if f.configErr != nil {
		return nil, f.configErr
	}
	return f.configs, nil
}

func (f *fakeAPI) GetCMEKKeyName(_ context.Context, project string) (string, error) {
	f.cmekCall++
	f.project = project
	if f.cmekErr != nil {
		return "", f.cmekErr
	}
	return f.cmekKey, nil
}

func auditReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1"}
}

func decodePayload(t *testing.T, r *core.EvidenceRecord) trailPayload {
	t.Helper()
	var p trailPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	return p
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != "gcp.audit" {
		t.Errorf("ID = %q; want gcp.audit", p.ID())
	}
	emits := p.Emits()
	if len(emits) != 1 || emits[0] != "audit_log_trail" {
		t.Errorf("Emits = %v; want [audit_log_trail]", emits)
	}
}

func TestInit_NoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// TestCollect_SingletonRecord covers the happy path: a project with
// data-access logging on (DATA_READ, no exemptions) and a CMEK key emits
// exactly one fully-populated record.
func TestCollect_SingletonRecord(t *testing.T) {
	fake := &fakeAPI{
		configs: []*cloudresourcemanager.AuditConfig{
			{
				Service: "allServices",
				AuditLogConfigs: []*cloudresourcemanager.AuditLogConfig{
					{LogType: "ADMIN_READ"},
					{LogType: "DATA_READ"},
				},
			},
		},
		cmekKey: "projects/p/locations/us/keyRings/r/cryptoKeys/k",
	}
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "proj-1", Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), auditReq())
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
		t.Errorf("IdentityKey = %q; want empty (trails have no identity)", r.IdentityKey)
	}
	if r.ID != "projects/proj-1/cloudAuditLogs" {
		t.Errorf("ID = %q; want projects/proj-1/cloudAuditLogs", r.ID)
	}

	want := trailPayload{
		ID:                       "projects/proj-1/cloudAuditLogs",
		Name:                     "proj-1",
		Provider:                 "gcp",
		IsEnabled:                true,
		IsMultiRegion:            true,
		LogFileValidationEnabled: true,
		KMSEncrypted:             true,
		DataAccessLoggingEnabled: true,
		AuditedServices:          1,
		KMSKeyName:               "projects/p/locations/us/keyRings/r/cryptoKeys/k",
	}
	if got := decodePayload(t, &r); !reflect.DeepEqual(got, want) {
		t.Errorf("payload = %+v; want %+v", got, want)
	}
}

// TestCollect_DefaultPosture covers a project with no audit configs and
// no CMEK (the Google-managed default): the always-on platform fields
// stay true, but data_access_logging_enabled and kms_encrypted are false.
func TestCollect_DefaultPosture(t *testing.T) {
	fake := &fakeAPI{}
	p := New(Options{API: fake, ProjectID: "proj-2"})
	records, err := p.Collect(context.Background(), auditReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := decodePayload(t, &records[0])
	want := trailPayload{
		ID:                       "projects/proj-2/cloudAuditLogs",
		Name:                     "proj-2",
		Provider:                 "gcp",
		IsEnabled:                true,
		IsMultiRegion:            true,
		LogFileValidationEnabled: true,
		KMSEncrypted:             false,
		DataAccessLoggingEnabled: false,
		AuditedServices:          0,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("payload = %+v; want %+v", got, want)
	}
}

func TestDataAccessLoggingEnabled(t *testing.T) {
	cases := []struct {
		name    string
		configs []*cloudresourcemanager.AuditConfig
		want    bool
	}{
		{"nil", nil, false},
		{"nil entry skipped", []*cloudresourcemanager.AuditConfig{nil}, false},
		{
			"data_read no exemptions",
			[]*cloudresourcemanager.AuditConfig{{AuditLogConfigs: []*cloudresourcemanager.AuditLogConfig{{LogType: "DATA_READ"}}}},
			true,
		},
		{
			"data_read but fully exempted",
			[]*cloudresourcemanager.AuditConfig{{AuditLogConfigs: []*cloudresourcemanager.AuditLogConfig{{LogType: "DATA_READ", ExemptedMembers: []string{"user:x@e.com"}}}}},
			false,
		},
		{
			"unspecified log type",
			[]*cloudresourcemanager.AuditConfig{{AuditLogConfigs: []*cloudresourcemanager.AuditLogConfig{{LogType: "LOG_TYPE_UNSPECIFIED"}}}},
			false,
		},
		{
			"nil log config skipped, then a valid one",
			[]*cloudresourcemanager.AuditConfig{{AuditLogConfigs: []*cloudresourcemanager.AuditLogConfig{nil, {LogType: "DATA_WRITE"}}}},
			true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dataAccessLoggingEnabled(c.configs); got != c.want {
				t.Errorf("dataAccessLoggingEnabled = %v; want %v", got, c.want)
			}
		})
	}
}

func TestAuditedServiceCount(t *testing.T) {
	configs := []*cloudresourcemanager.AuditConfig{
		nil,
		{Service: "empty"}, // no AuditLogConfigs → not counted
		{Service: "storage.googleapis.com", AuditLogConfigs: []*cloudresourcemanager.AuditLogConfig{{LogType: "DATA_READ"}}},
		{Service: "allServices", AuditLogConfigs: []*cloudresourcemanager.AuditLogConfig{{LogType: "ADMIN_READ"}}},
	}
	if got := auditedServiceCount(configs); got != 2 {
		t.Errorf("auditedServiceCount = %d; want 2", got)
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"log_group"}})
	if err == nil {
		t.Fatal("want error for unaccepted type; got nil")
	}
}

func TestCollect_PropagatesConfigError(t *testing.T) {
	wantErr := errors.New("boom")
	p := New(Options{API: &fakeAPI{configErr: wantErr}})
	_, err := p.Collect(context.Background(), auditReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_PropagatesCMEKError(t *testing.T) {
	wantErr := errors.New("denied")
	p := New(Options{API: &fakeAPI{cmekErr: wantErr}})
	_, err := p.Collect(context.Background(), auditReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_KISS_NoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), auditReq()); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.configCall != 3 || fake.cmekCall != 3 {
		t.Errorf("calls = %d/%d; want 3/3 (no caching per KISS-no-DRY)", fake.configCall, fake.cmekCall)
	}
}

// TestRealAudit_GetAuditConfigs exercises the production adapter against
// an httptest server, verifying it posts the getIamPolicy request and
// parses the auditConfigs back.
func TestRealAudit_GetAuditConfigs(t *testing.T) {
	body := mustMarshal(t, cloudresourcemanager.Policy{
		AuditConfigs: []*cloudresourcemanager.AuditConfig{
			{Service: "allServices", AuditLogConfigs: []*cloudresourcemanager.AuditLogConfig{{LogType: "DATA_READ"}}},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, ":getIamPolicy") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r := &realAudit{crm: newTestCRM(t, srv)}
	configs, err := r.GetAuditConfigs(context.Background(), "p")
	if err != nil {
		t.Fatalf("GetAuditConfigs: %v", err)
	}
	if len(configs) != 1 || configs[0].Service != "allServices" {
		t.Fatalf("configs = %+v; want one allServices config", configs)
	}
}

func TestRealAudit_GetAuditConfigs_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	r := &realAudit{crm: newTestCRM(t, srv)}
	if _, err := r.GetAuditConfigs(context.Background(), "p"); err == nil {
		t.Fatal("want error from 403; got nil")
	}
}

// TestRealAudit_GetCMEKKeyName exercises the production adapter against an
// httptest server, verifying it reads the project CMEK settings.
func TestRealAudit_GetCMEKKeyName(t *testing.T) {
	body := mustMarshal(t, logging.CmekSettings{KmsKeyName: "projects/p/locations/us/keyRings/r/cryptoKeys/k"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/cmekSettings") {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r := &realAudit{log: newTestLogging(t, srv)}
	key, err := r.GetCMEKKeyName(context.Background(), "p")
	if err != nil {
		t.Fatalf("GetCMEKKeyName: %v", err)
	}
	if key != "projects/p/locations/us/keyRings/r/cryptoKeys/k" {
		t.Fatalf("key = %q; want the configured CMEK key", key)
	}
}

func TestRealAudit_GetCMEKKeyName_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	r := &realAudit{log: newTestLogging(t, srv)}
	if _, err := r.GetCMEKKeyName(context.Background(), "p"); err == nil {
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

func newTestCRM(t *testing.T, srv *httptest.Server) *cloudresourcemanager.Service {
	t.Helper()
	svc, err := cloudresourcemanager.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func newTestLogging(t *testing.T, srv *httptest.Server) *logging.Service {
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

func TestBuild_RequiresProjectID(t *testing.T) {
	_, err := build(context.Background(), sources.Env{Config: map[string]any{}})
	if err == nil {
		t.Fatal("want error when project_id is missing; got nil")
	}
}
