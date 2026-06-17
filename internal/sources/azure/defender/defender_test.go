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
	subs         []*armsecurity.SubAssessment
	pricingsErr  error
	subsErr      error
	pricingCalls int
	subCalls     int
}

func (f *fakeAPI) ListPricings(context.Context) ([]*armsecurity.Pricing, error) {
	f.pricingCalls++
	if f.pricingsErr != nil {
		return nil, f.pricingsErr
	}
	return f.pricings, nil
}

func (f *fakeAPI) ListSubAssessments(context.Context) ([]*armsecurity.SubAssessment, error) {
	f.subCalls++
	if f.subsErr != nil {
		return nil, f.subsErr
	}
	return f.subs, nil
}

func allReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeThreatService, EvidenceTypeSecurityService, EvidenceTypeVulnFinding}}
}

func newPlugin(f *fakeAPI) *Plugin {
	return New(Options{API: f, SubscriptionID: "sub-1", Now: func() time.Time { return fixedNow }})
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

func subAssessment(id string, sev armsecurity.Severity, code armsecurity.SubAssessmentStatusCode, resID, display, vulnID, remediation, cat string) *armsecurity.SubAssessment {
	props := &armsecurity.SubAssessmentProperties{
		Status: &armsecurity.SubAssessmentStatus{
			Severity: to.Ptr(sev),
			Code:     to.Ptr(code),
		},
	}
	if resID != "" {
		props.ResourceDetails = &armsecurity.AzureResourceDetails{ID: to.Ptr(resID)}
	}
	if display != "" {
		props.DisplayName = to.Ptr(display)
	}
	if vulnID != "" {
		props.ID = to.Ptr(vulnID)
	}
	if remediation != "" {
		props.Remediation = to.Ptr(remediation)
	}
	if cat != "" {
		props.Category = to.Ptr(cat)
	}
	return &armsecurity.SubAssessment{
		ID:         to.Ptr("/subscriptions/sub-1/providers/Microsoft.Security/subAssessments/" + id),
		Properties: props,
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
		if r.Scope == nil || r.Scope.Account != "sub-1" {
			t.Errorf("scope = %+v, want Account sub-1", r.Scope)
		}
	}
	var vm threatServicePayload
	mustUnmarshal(t, recs[1].Payload, &vm)
	wantVM := threatServicePayload{
		ID: *pricingID("VirtualMachines"), Name: "VirtualMachines", Provider: "azure",
		IsEnabled: true, PricingTier: "Standard", SubPlan: "P2",
	}
	if !reflect.DeepEqual(vm, wantVM) {
		t.Errorf("VM payload = %+v, want %+v", vm, wantVM)
	}
	var st threatServicePayload
	mustUnmarshal(t, recs[0].Payload, &st)
	wantST := threatServicePayload{
		ID: *pricingID("StorageAccounts"), Name: "StorageAccounts", Provider: "azure",
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
		ID: "azure-defender-for-cloud", Name: "Microsoft Defender for Cloud", Provider: "azure",
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
	f := &fakeAPI{subs: []*armsecurity.SubAssessment{
		subAssessment("a", armsecurity.SeverityCritical, armsecurity.SubAssessmentStatusCodeUnhealthy,
			"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
			"VM has a critical vuln", "CVE-2024-1234", "Apply patch KB123", "Vulnerabilities"),
		subAssessment("b", armsecurity.SeverityLow, armsecurity.SubAssessmentStatusCodeHealthy,
			"", "", "", "", ""),
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
		ID:           "/subscriptions/sub-1/providers/Microsoft.Security/subAssessments/a",
		ResourceID:   "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
		ResourceType: "Microsoft.Compute/virtualMachines",
		Title:        "VM has a critical vuln",
		Severity:     "CRITICAL", Status: "ACTIVE", CVEID: "CVE-2024-1234",
		RemediationAvailable: true, Provider: "azure", Category: "Vulnerabilities",
	}
	if !reflect.DeepEqual(a, wantA) {
		t.Errorf("finding a = %+v, want %+v", a, wantA)
	}
	var b vulnFindingPayload
	mustUnmarshal(t, recs[1].Payload, &b)
	wantB := vulnFindingPayload{
		ID:           "/subscriptions/sub-1/providers/Microsoft.Security/subAssessments/b",
		ResourceID:   "",
		ResourceType: resourceTypeFallback,
		Severity:     "LOW", Status: "RESOLVED", RemediationAvailable: false, Provider: "azure",
	}
	if !reflect.DeepEqual(b, wantB) {
		t.Errorf("finding b = %+v, want %+v", b, wantB)
	}
}

func TestCollect_AllThreeTypes_SharedPricingsCalledOnce(t *testing.T) {
	f := &fakeAPI{
		pricings: []*armsecurity.Pricing{pricing("VirtualMachines", "Standard", "")},
		subs:     []*armsecurity.SubAssessment{subAssessment("a", armsecurity.SeverityHigh, armsecurity.SubAssessmentStatusCodeUnhealthy, "", "", "", "", "")},
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
	if f.subCalls != 1 {
		t.Errorf("sub-assessments called %d times, want 1", f.subCalls)
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
	if f.subCalls != 1 {
		t.Errorf("sub-assessments called %d times, want 1", f.subCalls)
	}
}

func TestCollect_OnlyThreat_SkipsSubAssessments(t *testing.T) {
	f := &fakeAPI{pricings: []*armsecurity.Pricing{pricing("VirtualMachines", "Standard", "")}}
	_, err := newPlugin(f).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeThreatService}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if f.subCalls != 0 {
		t.Errorf("sub-assessments called %d times, want 0", f.subCalls)
	}
}

func TestCollect_NilEntriesSkipped(t *testing.T) {
	f := &fakeAPI{
		pricings: []*armsecurity.Pricing{nil, pricing("VirtualMachines", "Standard", "")},
		subs:     []*armsecurity.SubAssessment{nil, subAssessment("a", armsecurity.SeverityHigh, armsecurity.SubAssessmentStatusCodeUnhealthy, "", "", "", "", "")},
	}
	recs, err := newPlugin(f).Collect(context.Background(), allReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// 1 threat (nil skipped) + 1 security + 1 finding (nil skipped).
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
		{"subassessments", &fakeAPI{subsErr: sentinel}, core.SlotRequest{AcceptedTypes: []string{EvidenceTypeVulnFinding}}, "list sub-assessments"},
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
	crit, high, med, low, info := armsecurity.SeverityCritical, armsecurity.SeverityHigh, armsecurity.SeverityMedium, armsecurity.SeverityLow, armsecurity.Severity("Informational")
	cases := []struct {
		in   *armsecurity.Severity
		want string
	}{
		{&crit, "CRITICAL"}, {&high, "HIGH"}, {&med, "MEDIUM"}, {&low, "LOW"},
		{&info, "INFORMATIONAL"}, {nil, "INFORMATIONAL"},
	}
	for _, c := range cases {
		if got := mapSeverity(c.in); got != c.want {
			t.Errorf("mapSeverity(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMapStatus_Table(t *testing.T) {
	healthy, unhealthy, na := armsecurity.SubAssessmentStatusCodeHealthy, armsecurity.SubAssessmentStatusCodeUnhealthy, armsecurity.SubAssessmentStatusCodeNotApplicable
	cases := []struct {
		in   *armsecurity.SubAssessmentStatusCode
		want string
	}{
		{&unhealthy, "ACTIVE"}, {&healthy, "RESOLVED"}, {&na, "SUPPRESSED"}, {nil, "ACTIVE"},
	}
	for _, c := range cases {
		if got := mapStatus(c.in); got != c.want {
			t.Errorf("mapStatus(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResourceTypeFromID_Table(t *testing.T) {
	cases := []struct {
		id   string
		want string
	}{
		{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1", "Microsoft.Compute/virtualMachines"},
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

func TestCVEID_Table(t *testing.T) {
	cases := []struct {
		vulnID string
		want   string
	}{
		{"CVE-2024-1234", "CVE-2024-1234"},
		{"cve-2024-9999", "cve-2024-9999"},
		{"12345", ""},
		{"", ""},
	}
	for _, c := range cases {
		sa := subAssessment("x", armsecurity.SeverityLow, armsecurity.SubAssessmentStatusCodeUnhealthy, "", "", c.vulnID, "", "")
		if got := cveID(sa); got != c.want {
			t.Errorf("cveID(vulnID=%q) = %q, want %q", c.vulnID, got, c.want)
		}
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
	rd, err := newRealDefender("sub-1", fakeCred{}, opts)
	if err != nil {
		t.Fatalf("newRealDefender: %v", err)
	}
	return rd
}

func TestRealDefender_HappyPath(t *testing.T) {
	pricingBody := mustMarshal(t, armsecurity.PricingList{Value: []*armsecurity.Pricing{
		pricing("VirtualMachines", "Standard", ""),
	}})
	subBody := mustMarshal(t, armsecurity.SubAssessmentList{Value: []*armsecurity.SubAssessment{
		subAssessment("a", armsecurity.SeverityHigh, armsecurity.SubAssessmentStatusCodeUnhealthy, "", "finding", "", "", ""),
	}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/subAssessments"):
			_, _ = w.Write(subBody) //nolint:errcheck // test handler
		case strings.Contains(r.URL.Path, "/pricings"):
			_, _ = w.Write(pricingBody) //nolint:errcheck // test handler
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
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
	t.Run("subassessments", func(t *testing.T) {
		subs, err := rd.ListSubAssessments(context.Background())
		if err != nil || len(subs) != 1 || displayName(subs[0]) != "finding" {
			t.Fatalf("ListSubAssessments = %+v, err %v", subs, err)
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
	if _, err := rd.ListSubAssessments(context.Background()); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}
