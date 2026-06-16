package scc

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

	"google.golang.org/api/option"
	securitycenter "google.golang.org/api/securitycenter/v1"
	sccsettings "google.golang.org/api/securitycenter/v1beta2"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

// Shared literals (goconst: these recur across the table-driven cases).
const (
	stateActive    = "ACTIVE"
	stateEnabled   = "ENABLED"
	classVuln      = "VULNERABILITY"
	classMisconfig = "MISCONFIGURATION"
)

// fakeAPI drives the plugin without hitting GCP. It records the org
// argument and per-method call counts to assert plumbing, dispatch, and
// the KISS-no-DRY axiom.
type fakeAPI struct {
	etdState string
	shaState string
	findings []Finding
	etdErr   error
	shaErr   error
	findErr  error
	etdCall  int
	shaCall  int
	findCall int
	org      string
}

func (f *fakeAPI) EventThreatDetectionState(_ context.Context, org string) (string, error) {
	f.etdCall++
	f.org = org
	if f.etdErr != nil {
		return "", f.etdErr
	}
	return f.etdState, nil
}

func (f *fakeAPI) SecurityHealthAnalyticsState(_ context.Context, org string) (string, error) {
	f.shaCall++
	f.org = org
	if f.shaErr != nil {
		return "", f.shaErr
	}
	return f.shaState, nil
}

func (f *fakeAPI) ListActiveFindings(_ context.Context, org string) ([]Finding, error) {
	f.findCall++
	f.org = org
	if f.findErr != nil {
		return nil, f.findErr
	}
	return f.findings, nil
}

func reqAll() core.SlotRequest {
	return core.SlotRequest{
		AcceptedTypes: []string{EvidenceTypeThreatService, EvidenceTypeSecurityService, EvidenceTypeVulnFinding},
		PolicyID:      "p1",
	}
}

func decodeThreat(t *testing.T, r *core.EvidenceRecord) threatServicePayload {
	t.Helper()
	var p threatServicePayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal threat payload: %v", err)
	}
	return p
}

func decodeSecurity(t *testing.T, r *core.EvidenceRecord) securityServicePayload {
	t.Helper()
	var p securityServicePayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal security payload: %v", err)
	}
	return p
}

func decodeVuln(t *testing.T, r *core.EvidenceRecord) vulnFindingPayload {
	t.Helper()
	var p vulnFindingPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal vuln payload: %v", err)
	}
	return p
}

// twoFindings returns two findings with non-sorted IDs (zzz before aaa) so
// tests can assert the by-ID sort.
func twoFindings() []Finding {
	return []Finding{
		{
			Name:           "organizations/o/sources/s/findings/zzz",
			ResourceName:   "//compute.googleapis.com/projects/p/instances/i",
			ResourceType:   "google.compute.Instance",
			Category:       "PUBLIC_IP_ADDRESS",
			Severity:       "HIGH",
			State:          stateActive,
			Mute:           "UNMUTED",
			FindingClass:   classMisconfig,
			HasRemediation: true,
		},
		{
			Name:         "organizations/o/sources/s/findings/aaa",
			ResourceName: "//container.googleapis.com/projects/p/images/x",
			ResourceType: "google.cloud.container.Image",
			Category:     "OS_VULNERABILITY",
			Severity:     "CRITICAL",
			State:        stateActive,
			Mute:         "UNMUTED",
			FindingClass: classVuln,
			CVEID:        "CVE-2024-9999",
			CVSSScore:    9.8,
		},
	}
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != "gcp.scc" {
		t.Errorf("ID = %q; want gcp.scc", p.ID())
	}
	emits := p.Emits()
	want := []string{"threat_detection_service", "security_service", "vulnerability_finding"}
	if !reflect.DeepEqual(emits, want) {
		t.Errorf("Emits = %v; want %v", emits, want)
	}
}

func TestInit_NoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// TestCollect_AllThreeTypes_ShapeAndOrder checks that all three slots
// accepted yields one threat + one security + N findings, findings sorted
// by ID, with consistent record metadata.
func TestCollect_AllThreeTypes_ShapeAndOrder(t *testing.T) {
	fake := &fakeAPI{etdState: stateEnabled, shaState: stateEnabled, findings: twoFindings()}
	now := time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, OrgID: "1234567890", Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), reqAll())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.org != "1234567890" {
		t.Errorf("org = %q; want 1234567890", fake.org)
	}
	if len(records) != 4 {
		t.Fatalf("len = %d; want 4 (1 threat + 1 security + 2 findings)", len(records))
	}
	// Grouped by type in Emits() order: threat, security, then findings.
	if records[0].Type != EvidenceTypeThreatService || records[1].Type != EvidenceTypeSecurityService {
		t.Errorf("order = %q,%q; want threat,security first", records[0].Type, records[1].Type)
	}
	for _, r := range records {
		if r.SourceID != SourceID || !r.CollectedAt.Equal(now) || r.IdentityKey != "" {
			t.Errorf("record meta off: %+v", r)
		}
	}
	// Findings sorted by ID: aaa before zzz.
	if records[2].ID != "organizations/o/sources/s/findings/aaa" || records[3].ID != "organizations/o/sources/s/findings/zzz" {
		t.Errorf("findings not sorted: %q, %q", records[2].ID, records[3].ID)
	}
}

func TestCollect_ThreatServicePayload(t *testing.T) {
	fake := &fakeAPI{etdState: stateEnabled}
	p := New(Options{API: fake, OrgID: "1234567890"})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeThreatService}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := decodeThreat(t, &records[0])
	want := threatServicePayload{
		ID:                     "organizations/1234567890/eventThreatDetectionSettings",
		Name:                   "Event Threat Detection",
		Provider:               "gcp",
		IsEnabled:              true,
		ServiceEnablementState: stateEnabled,
	}
	if got != want {
		t.Errorf("threat payload = %+v; want %+v", got, want)
	}
}

func TestCollect_SecurityServicePayload(t *testing.T) {
	fake := &fakeAPI{shaState: stateEnabled}
	p := New(Options{API: fake, OrgID: "1234567890"})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeSecurityService}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := decodeSecurity(t, &records[0])
	want := securityServicePayload{
		ID:                     "organizations/1234567890/securityHealthAnalyticsSettings",
		Name:                   "Google Security Command Center",
		Provider:               "gcp",
		ServiceType:            "siem",
		IsEnabled:              true,
		ServiceEnablementState: stateEnabled,
	}
	if got != want {
		t.Errorf("security payload = %+v; want %+v", got, want)
	}
}

func TestCollect_FindingPayload(t *testing.T) {
	fake := &fakeAPI{findings: twoFindings()}
	p := New(Options{API: fake, OrgID: "o"})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeVulnFinding}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// records[0] is aaa (sorted): a critical vulnerability with CVE/score.
	got := decodeVuln(t, &records[0])
	want := vulnFindingPayload{
		ID:                   "organizations/o/sources/s/findings/aaa",
		ResourceID:           "//container.googleapis.com/projects/p/images/x",
		ResourceType:         "google.cloud.container.Image",
		Title:                "OS_VULNERABILITY",
		Severity:             "CRITICAL",
		Status:               stateActive,
		CVEID:                "CVE-2024-9999",
		Score:                9.8,
		RemediationAvailable: false,
		Provider:             "gcp",
		FindingClass:         classVuln,
	}
	if got != want {
		t.Errorf("vuln payload = %+v; want %+v", got, want)
	}
	// records[1] is zzz: a high misconfiguration with next-steps remediation.
	zzz := decodeVuln(t, &records[1])
	if zzz.Severity != "HIGH" || zzz.Status != stateActive || zzz.FindingClass != classMisconfig {
		t.Errorf("zzz payload = %+v", zzz)
	}
	if !zzz.RemediationAvailable || zzz.Title != "PUBLIC_IP_ADDRESS" {
		t.Errorf("zzz remediation/title off: %+v", zzz)
	}
}

// TestCollect_ServicesDisabled covers a non-ENABLED state (DISABLED for
// ETD, INHERITED for SHA) mapping to is_enabled=false while the raw state
// is preserved for auditability.
func TestCollect_ServicesDisabled(t *testing.T) {
	fake := &fakeAPI{etdState: "DISABLED", shaState: "INHERITED"}
	p := New(Options{API: fake, OrgID: "o"})
	records, err := p.Collect(context.Background(), reqAll())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	threat := decodeThreat(t, &records[0])
	if threat.IsEnabled || threat.ServiceEnablementState != "DISABLED" {
		t.Errorf("threat = %+v; want is_enabled=false state=DISABLED", threat)
	}
	sec := decodeSecurity(t, &records[1])
	if sec.IsEnabled || sec.ServiceEnablementState != "INHERITED" {
		t.Errorf("security = %+v; want is_enabled=false state=INHERITED", sec)
	}
}

func TestMapSeverity(t *testing.T) {
	cases := map[string]string{
		"CRITICAL":             "CRITICAL",
		"HIGH":                 "HIGH",
		"MEDIUM":               "MEDIUM",
		"LOW":                  "LOW",
		"SEVERITY_UNSPECIFIED": "INFORMATIONAL",
		"":                     "INFORMATIONAL",
		"SOMETHING_ELSE":       "INFORMATIONAL",
	}
	for in, want := range cases {
		if got := mapSeverity(in); got != want {
			t.Errorf("mapSeverity(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestMapStatus(t *testing.T) {
	cases := []struct {
		state, mute, want string
	}{
		{stateActive, "UNMUTED", stateActive},
		{stateActive, "MUTED", "SUPPRESSED"}, // mute wins over state
		{"INACTIVE", "UNMUTED", "RESOLVED"},
		{"INACTIVE", "MUTED", "SUPPRESSED"},
		{"STATE_UNSPECIFIED", "UNDEFINED", "RESOLVED"},
		{"", "", "RESOLVED"},
	}
	for _, c := range cases {
		if got := mapStatus(c.state, c.mute); got != c.want {
			t.Errorf("mapStatus(%q,%q) = %q; want %q", c.state, c.mute, got, c.want)
		}
	}
}

// TestCollect_Findings_ResourceTypeFallback verifies a finding whose SCC
// resource wrapper omitted a type still emits a non-empty resource_type
// (the schema requires it), and that muted/optional fields map correctly.
func TestCollect_Findings_ResourceTypeFallback(t *testing.T) {
	fake := &fakeAPI{
		findings: []Finding{{
			Name:         "organizations/o/sources/s/findings/f1",
			ResourceName: "//foo/bar",
			ResourceType: "", // wrapper omitted it
			Severity:     "MEDIUM",
			State:        stateActive,
			Mute:         "MUTED",
			FindingClass: classVuln,
		}},
	}
	p := New(Options{API: fake, OrgID: "o"})
	req := core.SlotRequest{AcceptedTypes: []string{EvidenceTypeVulnFinding}}
	records, err := p.Collect(context.Background(), req)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1", len(records))
	}
	v := decodeVuln(t, &records[0])
	if v.ResourceType != resourceTypeFallback {
		t.Errorf("ResourceType = %q; want %q", v.ResourceType, resourceTypeFallback)
	}
	if v.Status != "SUPPRESSED" {
		t.Errorf("Status = %q; want SUPPRESSED (muted)", v.Status)
	}
	if v.Severity != "MEDIUM" {
		t.Errorf("Severity = %q; want MEDIUM", v.Severity)
	}
	if v.CVEID != "" || v.Score != 0 || v.Title != "" {
		t.Errorf("optional fields should be empty: %+v", v)
	}
}

// TestCollect_Dispatch_OnlyRequestedType verifies that a slot accepting a
// single type triggers only that type's API calls.
func TestCollect_Dispatch_OnlyRequestedType(t *testing.T) {
	// Only vulnerability_finding requested → no settings calls.
	fake := &fakeAPI{findings: []Finding{{Name: "x", ResourceName: "r", ResourceType: "t", Severity: "LOW", State: stateActive, FindingClass: classVuln}}}
	p := New(Options{API: fake, OrgID: "o"})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeVulnFinding}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].Type != EvidenceTypeVulnFinding {
		t.Errorf("records = %+v; want one vulnerability_finding", records)
	}
	if fake.etdCall != 0 || fake.shaCall != 0 {
		t.Errorf("settings calls = %d/%d; want 0/0 when only findings requested", fake.etdCall, fake.shaCall)
	}

	// Only threat_detection_service requested → no findings call.
	fake2 := &fakeAPI{etdState: stateEnabled}
	p2 := New(Options{API: fake2, OrgID: "o"})
	records2, err := p2.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeThreatService}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records2) != 1 || records2[0].Type != EvidenceTypeThreatService {
		t.Errorf("records2 = %+v; want one threat_detection_service", records2)
	}
	if fake2.findCall != 0 || fake2.shaCall != 0 {
		t.Errorf("calls = find %d / sha %d; want 0/0", fake2.findCall, fake2.shaCall)
	}
}

func TestCollect_RejectsUnknownType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}, OrgID: "o"})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil {
		t.Fatal("want error when slot accepts none of the emitted types")
	}
	if !strings.Contains(err.Error(), "emitted types") {
		t.Errorf("err = %v; want mention of emitted types", err)
	}
}

func TestCollect_ErrorPropagation(t *testing.T) {
	sentinel := errors.New("boom")
	t.Run("etd", func(t *testing.T) {
		p := New(Options{API: &fakeAPI{etdErr: sentinel}, OrgID: "o"})
		if _, err := p.Collect(context.Background(), reqAll()); !errors.Is(err, sentinel) {
			t.Errorf("err = %v; want wrap of sentinel", err)
		}
	})
	t.Run("sha", func(t *testing.T) {
		p := New(Options{API: &fakeAPI{shaErr: sentinel}, OrgID: "o"})
		if _, err := p.Collect(context.Background(), reqAll()); !errors.Is(err, sentinel) {
			t.Errorf("err = %v; want wrap of sentinel", err)
		}
	})
	t.Run("findings", func(t *testing.T) {
		p := New(Options{API: &fakeAPI{findErr: sentinel}, OrgID: "o"})
		if _, err := p.Collect(context.Background(), reqAll()); !errors.Is(err, sentinel) {
			t.Errorf("err = %v; want wrap of sentinel", err)
		}
	})
}

// TestCollect_KISSNoDRY verifies the plugin re-fetches every call (caches
// nothing): three Collect calls ⇒ three calls to each API method.
func TestCollect_KISSNoDRY(t *testing.T) {
	fake := &fakeAPI{etdState: stateEnabled, shaState: stateEnabled}
	p := New(Options{API: fake, OrgID: "o"})
	for i := 0; i < 3; i++ {
		if _, err := p.Collect(context.Background(), reqAll()); err != nil {
			t.Fatalf("Collect #%d: %v", i, err)
		}
	}
	if fake.etdCall != 3 || fake.shaCall != 3 || fake.findCall != 3 {
		t.Errorf("calls = etd %d / sha %d / find %d; want 3/3/3", fake.etdCall, fake.shaCall, fake.findCall)
	}
}

func TestBuild_RequiresOrgID(t *testing.T) {
	_, err := build(context.Background(), sources.Env{Config: map[string]any{}})
	if err == nil {
		t.Fatal("want error when organization_id is missing; got nil")
	}
}

// ---- real-adapter (httptest) tests ----

func newTestFindings(t *testing.T, srv *httptest.Server) *securitycenter.Service {
	t.Helper()
	svc, err := securitycenter.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func newTestSettings(t *testing.T, srv *httptest.Server) *sccsettings.Service {
	t.Helper()
	svc, err := sccsettings.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestRealSCC_ListFindings_HappyPath(t *testing.T) {
	const body = `{
		"listFindingsResults": [
			{
				"finding": {
					"name": "organizations/123/sources/5/findings/abc",
					"resourceName": "//compute.googleapis.com/projects/p/instances/i",
					"category": "PUBLIC_IP_ADDRESS",
					"severity": "HIGH",
					"state": "ACTIVE",
					"mute": "UNMUTED",
					"findingClass": "MISCONFIGURATION",
					"nextSteps": "Remove the public IP",
					"vulnerability": {"cve": {"id": "CVE-2024-1", "cvssv3": {"baseScore": 7.5}}}
				},
				"resource": {"type": "google.compute.Instance"}
			}
		]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/findings") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r := &realSCC{findings: newTestFindings(t, srv)}
	got, err := r.ListActiveFindings(context.Background(), "123")
	if err != nil {
		t.Fatalf("ListActiveFindings: %v", err)
	}
	want := []Finding{{
		Name:           "organizations/123/sources/5/findings/abc",
		ResourceName:   "//compute.googleapis.com/projects/p/instances/i",
		ResourceType:   "google.compute.Instance",
		Category:       "PUBLIC_IP_ADDRESS",
		Severity:       "HIGH",
		State:          stateActive,
		Mute:           "UNMUTED",
		FindingClass:   classMisconfig,
		CVEID:          "CVE-2024-1",
		CVSSScore:      7.5,
		HasRemediation: true,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %+v; want %+v", got, want)
	}
}

func TestRealSCC_Settings_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "eventThreatDetectionSettings"):
			_, _ = w.Write([]byte(`{"serviceEnablementState": "ENABLED"}`)) //nolint:errcheck // test handler
		case strings.Contains(r.URL.Path, "securityHealthAnalyticsSettings"):
			_, _ = w.Write([]byte(`{"serviceEnablementState": "DISABLED"}`)) //nolint:errcheck // test handler
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()

	r := &realSCC{settings: newTestSettings(t, srv)}
	etd, err := r.EventThreatDetectionState(context.Background(), "123")
	if err != nil {
		t.Fatalf("EventThreatDetectionState: %v", err)
	}
	if etd != stateEnabled {
		t.Errorf("etd = %q; want ENABLED", etd)
	}
	sha, err := r.SecurityHealthAnalyticsState(context.Background(), "123")
	if err != nil {
		t.Fatalf("SecurityHealthAnalyticsState: %v", err)
	}
	if sha != "DISABLED" {
		t.Errorf("sha = %q; want DISABLED", sha)
	}
}

func TestRealSCC_ListFindings_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	r := &realSCC{findings: newTestFindings(t, srv)}
	if _, err := r.ListActiveFindings(context.Background(), "123"); err == nil {
		t.Fatal("want error on 403; got nil")
	}
}
