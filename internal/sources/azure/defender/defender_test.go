package defender

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
	armsecurity "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

const (
	vulnStatusActive = "ACTIVE"
	vulnStatusFixed  = "RESOLVED"
	sevHigh          = "HIGH"
	testCVEID        = "CVE-2024-1234"
	testSub          = "sub-1"
	vmType           = "Microsoft.Compute/virtualMachines"
	catSoftware      = "SoftwareUpdate"
)

var fixedNow = time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

func mustUnmarshal(t *testing.T, raw json.RawMessage, dst any) {
	t.Helper()
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

// --- fakeAPI ---

type fakeAPI struct {
	pricings     []*armsecurity.Pricing
	findings     []Assessment
	pricingsErr  error
	findingsErr  error
	pricingCalls int
	findingCalls int
}

func (f *fakeAPI) ListPricings(context.Context) ([]*armsecurity.Pricing, error) {
	f.pricingCalls++
	if f.pricingsErr != nil {
		return nil, f.pricingsErr
	}
	return f.pricings, nil
}

func (f *fakeAPI) ListVulnerabilityAssessments(context.Context) ([]Assessment, error) {
	f.findingCalls++
	if f.findingsErr != nil {
		return nil, f.findingsErr
	}
	return f.findings, nil
}

func allReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeThreatService, EvidenceTypeSecurityService, EvidenceTypeVulnFinding}}
}

func newPlugin(f *fakeAPI) *Plugin {
	return New(Options{API: f, SubscriptionID: testSub, Now: func() time.Time { return fixedNow }})
}

// --- builders ---

func pricingID(name string) *string {
	return to.Ptr("/subscriptions/sub-1/providers/Microsoft.Security/pricings/" + name)
}

func pricing(name, tier, subPlanV string) *armsecurity.Pricing {
	props := &armsecurity.PricingProperties{PricingTier: to.Ptr(armsecurity.PricingTier(tier))}
	if subPlanV != "" {
		props.SubPlan = to.Ptr(subPlanV)
	}
	return &armsecurity.Pricing{ID: pricingID(name), Name: to.Ptr(name), Properties: props}
}

func assessment(id, sev, code, resID, display, category, cves, fixed string) Assessment {
	return Assessment{
		ID:           "/subscriptions/sub-1/providers/Microsoft.Security/assessments/" + id,
		ResourceID:   resID,
		DisplayName:  display,
		Severity:     sev,
		StatusCode:   code,
		Category:     category,
		CvesDetails:  cves,
		FixedVersion: fixed,
	}
}

// --- tests ---

func TestIDAndEmits(t *testing.T) {
	p := newPlugin(&fakeAPI{})
	if p.ID() != SourceID {
		t.Errorf("ID() = %q, want %q", p.ID(), SourceID)
	}
	want := []string{EvidenceTypeThreatService, EvidenceTypeSecurityService, EvidenceTypeVulnFinding}
	if got := p.Emits(); !reflect.DeepEqual(got, want) {
		t.Errorf("Emits() = %v, want %v", got, want)
	}
}

func TestCollect_RejectsWhenNoEmittedTypeAccepted(t *testing.T) {
	p := newPlugin(&fakeAPI{})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "does not include emitted types") {
		t.Fatalf("expected rejection error, got %v", err)
	}
}

func TestCollect_ThreatService_MapsSortsFullPayload(t *testing.T) {
	f := &fakeAPI{pricings: []*armsecurity.Pricing{
		pricing("VirtualMachines", "Standard", "P2"),
		pricing("StorageAccounts", "Free", ""),
	}}
	recs, err := newPlugin(f).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeThreatService}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	// Sorted by ID: StorageAccounts ("...S...") before VirtualMachines ("...V...").
	if !strings.HasSuffix(recs[0].ID, "/StorageAccounts") || !strings.HasSuffix(recs[1].ID, "/VirtualMachines") {
		t.Fatalf("records not sorted by ID: %q, %q", recs[0].ID, recs[1].ID)
	}
	for _, r := range recs {
		if r.Type != EvidenceTypeThreatService || r.SourceID != SourceID || !r.CollectedAt.Equal(fixedNow) {
			t.Errorf("record envelope wrong: %+v", r)
		}
		if r.Scope == nil || r.Scope.Account != testSub {
			t.Errorf("scope = %+v, want Account sub-1", r.Scope)
		}
	}
	var vm threatServicePayload
	mustUnmarshal(t, recs[1].Payload, &vm)
	wantVM := threatServicePayload{
		ID: *pricingID("VirtualMachines"), Name: "VirtualMachines", Provider: providerAzure,
		IsEnabled: true, PricingTier: "Standard", SubPlan: "P2",
	}
	if !reflect.DeepEqual(vm, wantVM) {
		t.Errorf("VM payload = %+v, want %+v", vm, wantVM)
	}
	var st threatServicePayload
	mustUnmarshal(t, recs[0].Payload, &st)
	wantST := threatServicePayload{
		ID: *pricingID("StorageAccounts"), Name: "StorageAccounts", Provider: providerAzure,
		IsEnabled: false, PricingTier: "Free",
	}
	if !reflect.DeepEqual(st, wantST) {
		t.Errorf("Storage payload = %+v, want %+v", st, wantST)
	}
}

func TestCollect_SecurityService_FullPayload(t *testing.T) {
	f := &fakeAPI{pricings: []*armsecurity.Pricing{
		pricing("VirtualMachines", "Standard", ""),
		pricing("StorageAccounts", "Free", ""),
		nil, // nil entries are skipped in the count
	}}
	recs, err := newPlugin(f).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeSecurityService}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].Type != EvidenceTypeSecurityService {
		t.Errorf("type = %q", recs[0].Type)
	}
	var p securityServicePayload
	mustUnmarshal(t, recs[0].Payload, &p)
	want := securityServicePayload{
		ID: "azure-defender-for-cloud", Name: "Microsoft Defender for Cloud", Provider: providerAzure,
		ServiceType: "cspm", IsEnabled: true, EnabledPlanCount: 1, TotalPlanCount: 2,
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("payload = %+v, want %+v", p, want)
	}
}

func TestCollect_SecurityService_DisabledWhenNoStandardPlan(t *testing.T) {
	f := &fakeAPI{pricings: []*armsecurity.Pricing{pricing("VirtualMachines", "Free", "")}}
	recs, err := newPlugin(f).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeSecurityService}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var p securityServicePayload
	mustUnmarshal(t, recs[0].Payload, &p)
	if p.IsEnabled || p.EnabledPlanCount != 0 || p.TotalPlanCount != 1 {
		t.Errorf("payload = %+v, want disabled with 0/1 plans", p)
	}
}

func TestCollect_VulnFindings_MapsSortsFullPayload(t *testing.T) {
	f := &fakeAPI{findings: []Assessment{
		assessment("a", "Critical", "Unhealthy",
			"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
			"openssl should be updated", catSoftware,
			`[{"CveId":"`+testCVEID+`"},{"CveId":"CVE-2024-5678"}]`, "3.0.15"),
		assessment("b", "Low", "Healthy", "", "", "", "", ""),
	}}
	recs, err := newPlugin(f).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeVulnFinding}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	// Sorted by ID: ".../a" before ".../b".
	if !strings.HasSuffix(recs[0].ID, "/a") || !strings.HasSuffix(recs[1].ID, "/b") {
		t.Fatalf("records not sorted by ID: %q, %q", recs[0].ID, recs[1].ID)
	}
	var a vulnFindingPayload
	mustUnmarshal(t, recs[0].Payload, &a)
	wantA := vulnFindingPayload{
		ID:           "/subscriptions/sub-1/providers/Microsoft.Security/assessments/a",
		ResourceID:   "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
		ResourceType: vmType,
		Title:        "openssl should be updated",
		Severity:     "CRITICAL", Status: vulnStatusActive, CVEID: testCVEID,
		CVEIDs:               []string{testCVEID, "CVE-2024-5678"},
		RemediationAvailable: true, Provider: providerAzure, Category: catSoftware,
	}
	if !reflect.DeepEqual(a, wantA) {
		t.Errorf("finding a = %+v, want %+v", a, wantA)
	}
	var b vulnFindingPayload
	mustUnmarshal(t, recs[1].Payload, &b)
	wantB := vulnFindingPayload{
		ID:           "/subscriptions/sub-1/providers/Microsoft.Security/assessments/b",
		ResourceID:   "",
		ResourceType: resourceTypeFallback,
		Severity:     "LOW", Status: vulnStatusFixed, RemediationAvailable: false, Provider: providerAzure,
	}
	if !reflect.DeepEqual(b, wantB) {
		t.Errorf("finding b = %+v, want %+v", b, wantB)
	}
}

func TestCollect_VulnFindings_ResourceTypeFromColumnWhenIDHasNone(t *testing.T) {
	// A non-ARM resource (an EC2 instance through a connector) carries no
	// providers segment, but the row still names its type.
	a := assessment("a", "High", "Unhealthy", "arn:aws:ec2:us-east-1:111122223333:instance/i-1", "", catSoftware, "", "")
	a.ResourceType = "ec2instance"
	recs, err := newPlugin(&fakeAPI{findings: []Assessment{a}}).Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeVulnFinding}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got vulnFindingPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if got.ResourceType != "ec2instance" {
		t.Errorf("resource_type = %q, want the row's ec2instance", got.ResourceType)
	}
}

func TestCollect_AllThreeTypes_SharedPricingsCalledOnce(t *testing.T) {
	f := &fakeAPI{
		pricings: []*armsecurity.Pricing{pricing("VirtualMachines", "Standard", "")},
		findings: []Assessment{assessment("a", "High", "Unhealthy", "", "", "", "", "")},
	}
	recs, err := newPlugin(f).Collect(context.Background(), allReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 1 threat + 1 security + 1 finding, grouped in Emits() order.
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}
	if recs[0].Type != EvidenceTypeThreatService || recs[1].Type != EvidenceTypeSecurityService || recs[2].Type != EvidenceTypeVulnFinding {
		t.Errorf("records not grouped in Emits() order: %q, %q, %q", recs[0].Type, recs[1].Type, recs[2].Type)
	}
	if f.pricingCalls != 1 {
		t.Errorf("pricings called %d times, want 1 (shared by threat+security)", f.pricingCalls)
	}
	if f.findingCalls != 1 {
		t.Errorf("assessments called %d times, want 1", f.findingCalls)
	}
}

func TestCollect_OnlyVuln_SkipsPricings(t *testing.T) {
	f := &fakeAPI{}
	_, err := newPlugin(f).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeVulnFinding}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if f.pricingCalls != 0 {
		t.Errorf("pricings called %d times, want 0", f.pricingCalls)
	}
	if f.findingCalls != 1 {
		t.Errorf("assessments called %d times, want 1", f.findingCalls)
	}
}

func TestCollect_OnlyThreat_SkipsAssessments(t *testing.T) {
	f := &fakeAPI{pricings: []*armsecurity.Pricing{pricing("VirtualMachines", "Standard", "")}}
	_, err := newPlugin(f).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeThreatService}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if f.findingCalls != 0 {
		t.Errorf("assessments called %d times, want 0", f.findingCalls)
	}
}

func TestCollect_NilEntriesSkipped(t *testing.T) {
	f := &fakeAPI{
		pricings: []*armsecurity.Pricing{nil, pricing("VirtualMachines", "Standard", "")},
		findings: []Assessment{assessment("a", "High", "Unhealthy", "", "", "", "", "")},
	}
	recs, err := newPlugin(f).Collect(context.Background(), allReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 1 threat (nil skipped) + 1 security + 1 finding.
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}
}

func TestCollect_ErrorPropagation(t *testing.T) {
	sentinel := errors.New("boom")
	cases := []struct {
		name string
		f    *fakeAPI
		req  core.SlotRequest
		want string
	}{
		{"pricings", &fakeAPI{pricingsErr: sentinel}, core.SlotRequest{AcceptedTypes: []string{EvidenceTypeThreatService}}, "list pricings"},
		{"assessments", &fakeAPI{findingsErr: sentinel}, core.SlotRequest{AcceptedTypes: []string{EvidenceTypeVulnFinding}}, "list vulnerability assessments"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := newPlugin(c.f).Collect(context.Background(), c.req)
			if err == nil || !strings.Contains(err.Error(), c.want) || !errors.Is(err, sentinel) {
				t.Fatalf("err = %v, want containing %q wrapping sentinel", err, c.want)
			}
		})
	}
}

func TestMapSeverity_Table(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Critical", "CRITICAL"}, {"High", sevHigh}, {"Medium", "MEDIUM"}, {"Low", "LOW"},
		{"high", sevHigh}, {"Informational", "INFORMATIONAL"}, {"", "INFORMATIONAL"},
	}
	for _, c := range cases {
		if got := mapSeverity(c.in); got != c.want {
			t.Errorf("mapSeverity(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMapStatus_Table(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Unhealthy", vulnStatusActive}, {"Healthy", vulnStatusFixed}, {"healthy", vulnStatusFixed},
		{"NotApplicable", "SUPPRESSED"}, {"", vulnStatusActive}, {"Unknown", vulnStatusActive},
	}
	for _, c := range cases {
		if got := mapStatus(c.in); got != c.want {
			t.Errorf("mapStatus(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResourceTypeFromID_Table(t *testing.T) {
	cases := []struct {
		id   string
		want string
	}{
		{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1", vmType},
		{"/subscriptions/s/providers/Microsoft.Storage/storageAccounts/sa", "Microsoft.Storage/storageAccounts"},
		{"/subscriptions/s/resourceGroups/rg", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := resourceTypeFromID(c.id); got != c.want {
			t.Errorf("resourceTypeFromID(%q) = %q, want %q", c.id, got, c.want)
		}
	}
}

func TestCVEIDs_Table(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"two", `[{"CveId":"CVE-2024-1"},{"CveId":"cve-2024-2"}]`, []string{"CVE-2024-1", "cve-2024-2"}},
		{"non-CVE ids dropped", `[{"CveId":"GHSA-xxxx"},{"CveId":"CVE-2024-3"}]`, []string{"CVE-2024-3"}},
		{"duplicates once", `[{"CveId":"CVE-2024-4"},{"CveId":"CVE-2024-4"}]`, []string{"CVE-2024-4"}},
		{"empty", "", nil},
		{"not JSON", "CVE-2024-5", nil},
		{"empty array", "[]", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cveIDs(c.in); !reflect.DeepEqual(got, c.want) {
				t.Errorf("cveIDs(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestPlanID_FallbackWhenNoARMID(t *testing.T) {
	pr := &armsecurity.Pricing{Name: to.Ptr("Containers"), Properties: &armsecurity.PricingProperties{PricingTier: to.Ptr(armsecurity.PricingTierFree)}}
	if got := planID(pr); got != "azure.defender/pricings/Containers" {
		t.Errorf("planID fallback = %q", got)
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

func realDefenderPointedAt(t *testing.T, srv *httptest.Server) *realDefender {
	t.Helper()
	opts := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.azure.com"},
		}},
		Transport: srv.Client(),
	}}
	rd, err := newRealDefender(testSub, fakeCred{}, opts)
	if err != nil {
		t.Fatalf("newRealDefender: %v", err)
	}
	return rd
}

func TestRealDefender_HappyPath(t *testing.T) {
	pricingBody := mustMarshal(t, armsecurity.PricingList{Value: []*armsecurity.Pricing{
		pricing("VirtualMachines", "Standard", ""),
	}})
	// One Resource Graph row, in the columns the plugin's query projects.
	graphBody := []byte(`{"totalRecords":1,"count":1,"resultTruncated":"false","data":[{` +
		`"id":"/subscriptions/sub-1/providers/Microsoft.Security/assessments/a",` +
		`"resourceId":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",` +
		`"resourceType":"microsoft.compute/virtualmachines","displayName":"finding","severity":"High",` +
		`"status":"Unhealthy","category":"SoftwareUpdate","cves":"[{\"CveId\":\"CVE-2024-1\"}]","fixedVersion":"1.2.3"}]}`)
	var graphReq struct {
		Subscriptions []string `json:"subscriptions"`
		Query         string   `json:"query"`
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/providers/Microsoft.ResourceGraph/resources"):
			if err := json.NewDecoder(r.Body).Decode(&graphReq); err != nil {
				t.Errorf("decode graph request: %v", err)
			}
			_, _ = w.Write(graphBody) //nolint:errcheck // test handler
		case strings.Contains(r.URL.Path, "/pricings"):
			_, _ = w.Write(pricingBody) //nolint:errcheck // test handler
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	rd := realDefenderPointedAt(t, srv)
	t.Run("pricings", func(t *testing.T) {
		ps, err := rd.ListPricings(context.Background())
		if err != nil || len(ps) != 1 || deref(ps[0].Name) != "VirtualMachines" {
			t.Fatalf("ListPricings = %+v, err %v", ps, err)
		}
	})
	t.Run("assessments", func(t *testing.T) {
		got, err := rd.ListVulnerabilityAssessments(context.Background())
		if err != nil {
			t.Fatalf("ListVulnerabilityAssessments: %v", err)
		}
		want := []Assessment{{
			ID:           "/subscriptions/sub-1/providers/Microsoft.Security/assessments/a",
			ResourceID:   "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
			ResourceType: "microsoft.compute/virtualmachines",
			DisplayName:  "finding", Severity: "High", StatusCode: "Unhealthy", Category: catSoftware,
			CvesDetails: `[{"CveId":"CVE-2024-1"}]`, FixedVersion: "1.2.3",
		}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ListVulnerabilityAssessments = %+v, want %+v", got, want)
		}
		if !reflect.DeepEqual(graphReq.Subscriptions, []string{testSub}) {
			t.Errorf("graph subscriptions = %v, want [sub-1]", graphReq.Subscriptions)
		}
		// The deprecated sub-assessments resource must never be queried again.
		if !strings.Contains(graphReq.Query, "'microsoft.security/assessments'") || strings.Contains(graphReq.Query, "subassessments") {
			t.Errorf("graph query does not read individual recommendations:\n%s", graphReq.Query)
		}
		for _, c := range vulnerabilityCategories {
			if !strings.Contains(graphReq.Query, "'"+c+"'") {
				t.Errorf("graph query does not filter on category %q", c)
			}
		}
	})
}

func TestRealDefender_ListError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	rd := realDefenderPointedAt(t, srv)
	if _, err := rd.ListPricings(context.Background()); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
	if _, err := rd.ListVulnerabilityAssessments(context.Background()); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}
