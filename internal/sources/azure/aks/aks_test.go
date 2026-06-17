package aks

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
	armcontainerservice "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v9"
	armmonitor "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"

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

// fakeAPI records calls and returns staged clusters + per-cluster diagnostics.
type fakeAPI struct {
	clusters     []*armcontainerservice.ManagedCluster
	clusterErr   error
	clusterCalls int

	diag      map[string][]*armmonitor.DiagnosticSettingsResource
	diagErr   error
	diagCalls int
}

func (f *fakeAPI) ListManagedClusters(context.Context) ([]*armcontainerservice.ManagedCluster, error) {
	f.clusterCalls++
	if f.clusterErr != nil {
		return nil, f.clusterErr
	}
	return f.clusters, nil
}

func (f *fakeAPI) ListClusterDiagnosticSettings(_ context.Context, id string) ([]*armmonitor.DiagnosticSettingsResource, error) {
	f.diagCalls++
	if f.diagErr != nil {
		return nil, f.diagErr
	}
	return f.diag[id], nil
}

func req() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}
}

func aksID(name string) *string {
	return to.Ptr("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/" + name)
}

// auditLogs builds a diagnostic-settings resource enabling the given log
// categories (each enabled).
func auditLogs(categories ...string) *armmonitor.DiagnosticSettingsResource {
	logs := make([]*armmonitor.LogSettings, 0, len(categories))
	for _, c := range categories {
		logs = append(logs, &armmonitor.LogSettings{Category: to.Ptr(c), Enabled: to.Ptr(true)})
	}
	return &armmonitor.DiagnosticSettingsResource{Properties: &armmonitor.DiagnosticSettings{Logs: logs}}
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{})
	if got := p.ID(); got != "azure.aks" {
		t.Errorf("ID() = %q, want azure.aks", got)
	}
	got := p.Emits()
	if len(got) != 1 || got[0] != EvidenceTypeID {
		t.Errorf("Emits() = %v, want [kubernetes_cluster]", got)
	}
}

func TestCollect_RejectsNonEmittedType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "kubernetes_cluster") {
		t.Fatalf("expected rejection error, got %v", err)
	}
}

func TestCollect_MapsSortsAndFullPayload(t *testing.T) {
	// Two clusters (out of order to prove sort): a private, KMS-secrets-encrypted,
	// audit-logging, auto-upgrading, RBAC Standard cluster; and a public, no-KMS,
	// non-audit-logging, no-auto-upgrade Free cluster.
	keyURI := "https://vault.vault.azure.net/keys/k/abc123"
	desID := "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/diskEncryptionSets/des"
	f := &fakeAPI{
		clusters: []*armcontainerservice.ManagedCluster{
			{
				ID:       aksID("z-prod"),
				Name:     to.Ptr("z-prod"),
				Location: to.Ptr("eastus"),
				SKU:      &armcontainerservice.ManagedClusterSKU{Tier: to.Ptr(armcontainerservice.ManagedClusterSKUTierStandard)},
				Properties: &armcontainerservice.ManagedClusterProperties{
					CurrentKubernetesVersion: to.Ptr("1.29.2"),
					KubernetesVersion:        to.Ptr("1.29"),
					ProvisioningState:        to.Ptr("Succeeded"),
					EnableRBAC:               to.Ptr(true),
					DiskEncryptionSetID:      to.Ptr(desID),
					PowerState:               &armcontainerservice.PowerState{Code: to.Ptr(armcontainerservice.CodeRunning)},
					SecurityProfile: &armcontainerservice.ManagedClusterSecurityProfile{
						AzureKeyVaultKms: &armcontainerservice.AzureKeyVaultKms{Enabled: to.Ptr(true), KeyID: to.Ptr(keyURI)},
					},
					APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{
						EnablePrivateCluster: to.Ptr(true),
						AuthorizedIPRanges:   []*string{to.Ptr("10.0.0.0/24"), to.Ptr("10.0.1.0/24"), nil, to.Ptr("")},
					},
					AutoUpgradeProfile: &armcontainerservice.ManagedClusterAutoUpgradeProfile{UpgradeChannel: to.Ptr(armcontainerservice.UpgradeChannelStable)},
					NetworkProfile: &armcontainerservice.NetworkProfile{
						NetworkPolicy: to.Ptr(armcontainerservice.NetworkPolicyCalico),
						NetworkPlugin: to.Ptr(armcontainerservice.NetworkPluginAzure),
					},
					AgentPoolProfiles: []*armcontainerservice.ManagedClusterAgentPoolProfile{
						{EnableEncryptionAtHost: to.Ptr(true)},
						{EnableEncryptionAtHost: to.Ptr(true)},
					},
				},
			},
			{
				ID:       aksID("a-dev"),
				Name:     to.Ptr("a-dev"),
				Location: to.Ptr("westus"),
				SKU:      &armcontainerservice.ManagedClusterSKU{Tier: to.Ptr(armcontainerservice.ManagedClusterSKUTierFree)},
				Properties: &armcontainerservice.ManagedClusterProperties{
					KubernetesVersion:  to.Ptr("1.28.0"),
					ProvisioningState:  to.Ptr("Succeeded"),
					EnableRBAC:         to.Ptr(false),
					PowerState:         &armcontainerservice.PowerState{Code: to.Ptr(armcontainerservice.CodeStopped)},
					AutoUpgradeProfile: &armcontainerservice.ManagedClusterAutoUpgradeProfile{UpgradeChannel: to.Ptr(armcontainerservice.UpgradeChannelNone)},
					NetworkProfile:     &armcontainerservice.NetworkProfile{NetworkPlugin: to.Ptr(armcontainerservice.NetworkPluginAzure)},
					AgentPoolProfiles: []*armcontainerservice.ManagedClusterAgentPoolProfile{
						{EnableEncryptionAtHost: to.Ptr(false)},
					},
				},
			},
		},
		diag: map[string][]*armmonitor.DiagnosticSettingsResource{
			*aksID("z-prod"): {
				// kube-audit + guard enabled, kube-audit-admin disabled → ["guard","kube-audit"].
				{Properties: &armmonitor.DiagnosticSettings{Logs: []*armmonitor.LogSettings{
					{Category: to.Ptr("kube-audit"), Enabled: to.Ptr(true)},
					{Category: to.Ptr("guard"), Enabled: to.Ptr(true)},
					{Category: to.Ptr("kube-audit-admin"), Enabled: to.Ptr(false)},
				}}},
			},
			// a-dev: a non-audit category enabled → logging stays false.
			*aksID("a-dev"): {auditLogs("cluster-autoscaler")},
		},
	}
	p := New(Options{API: f, SubscriptionID: "sub-1", Now: func() time.Time { return fixedNow }})

	recs, err := p.Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	// Sorted by ID (ARM id): a-dev before z-prod.
	if recs[0].ID != *aksID("a-dev") || recs[1].ID != *aksID("z-prod") {
		t.Fatalf("sort order wrong: %s, %s", recs[0].ID, recs[1].ID)
	}
	for _, r := range recs {
		if r.Type != EvidenceTypeID || r.SourceID != SourceID || !r.CollectedAt.Equal(fixedNow) {
			t.Errorf("record %s: Type/SourceID/CollectedAt = %s/%s/%v", r.ID, r.Type, r.SourceID, r.CollectedAt)
		}
		if r.Scope == nil || r.Scope.Account != "sub-1" {
			t.Errorf("record %s: scope = %+v", r.ID, r.Scope)
		}
		if r.IdentityKey != "" {
			t.Errorf("record %s: unexpected IdentityKey %q", r.ID, r.IdentityKey)
		}
	}

	var dev clusterPayload
	mustUnmarshal(t, recs[0].Payload, &dev)
	wantDev := clusterPayload{
		ID:                       *aksID("a-dev"),
		Name:                     "a-dev",
		Provider:                 "azure",
		Version:                  "1.28.0",
		SecretsEncryptionEnabled: false,
		LoggingEnabled:           false,
		IsPrivateEndpoint:        false,
		NodeAutoUpgradeEnabled:   false,
		ResourceGroup:            "rg",
		Location:                 "westus",
		PowerState:               "Stopped",
		ProvisioningState:        "Succeeded",
		SKUTier:                  "Free",
		RBACEnabled:              false,
		NetworkPlugin:            "azure",
		EncryptionAtHost:         false,
		AuthorizedIPRanges:       0,
	}
	if !reflect.DeepEqual(dev, wantDev) {
		t.Errorf("dev payload mismatch:\n got  %+v\n want %+v", dev, wantDev)
	}

	var prod clusterPayload
	mustUnmarshal(t, recs[1].Payload, &prod)
	wantProd := clusterPayload{
		ID:                       *aksID("z-prod"),
		Name:                     "z-prod",
		Provider:                 "azure",
		Version:                  "1.29.2",
		SecretsEncryptionEnabled: true,
		LoggingEnabled:           true,
		IsPrivateEndpoint:        true,
		NodeAutoUpgradeEnabled:   true,
		ResourceGroup:            "rg",
		Location:                 "eastus",
		PowerState:               "Running",
		ProvisioningState:        "Succeeded",
		SKUTier:                  "Standard",
		RBACEnabled:              true,
		NetworkPolicy:            "calico",
		NetworkPlugin:            "azure",
		KMSKeyID:                 keyURI,
		DiskEncryptionSetID:      desID,
		EncryptionAtHost:         true,
		AuditLogCategories:       []string{"guard", "kube-audit"},
		AuthorizedIPRanges:       2,
	}
	if !reflect.DeepEqual(prod, wantProd) {
		t.Errorf("prod payload mismatch:\n got  %+v\n want %+v", prod, wantProd)
	}
}

// TestCollect_BarePropertiesStillRequiredFields proves the schema-required fields
// are emitted for a bare cluster (nil Properties): secrets/logging default false,
// id/name/provider present, and no diagnostic-settings call is made for an empty id.
func TestCollect_BarePropertiesStillRequiredFields(t *testing.T) {
	f := &fakeAPI{clusters: []*armcontainerservice.ManagedCluster{
		{ID: aksID("bare"), Name: to.Ptr("bare")}, // nil Properties, nil SKU
	}}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got clusterPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if got.SecretsEncryptionEnabled || got.LoggingEnabled || got.IsPrivateEndpoint || got.NodeAutoUpgradeEnabled {
		t.Errorf("bare cluster: want all-false load-bearing fields, got %+v", got)
	}
	if got.ID == "" || got.Name != "bare" || got.Provider != "azure" {
		t.Errorf("bare cluster: missing required fields, got %+v", got)
	}
}

// TestCollect_EmptyIDSkipsDiagnostics proves a cluster with no ARM id does not
// trigger a diagnostic-settings read (which would need a valid resource id).
func TestCollect_EmptyIDSkipsDiagnostics(t *testing.T) {
	f := &fakeAPI{clusters: []*armcontainerservice.ManagedCluster{
		{Name: to.Ptr("no-id")}, // nil ID
	}}
	if _, err := New(Options{API: f}).Collect(context.Background(), req()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if f.diagCalls != 0 {
		t.Errorf("expected 0 diagnostic-settings calls for empty id, got %d", f.diagCalls)
	}
}

func TestCollect_NilEntriesSkipped(t *testing.T) {
	f := &fakeAPI{clusters: []*armcontainerservice.ManagedCluster{
		nil,
		{ID: aksID("ok"), Name: to.Ptr("ok")},
	}}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record (nil cluster skipped), got %d", len(recs))
	}
}

func TestCollect_ClusterListError(t *testing.T) {
	_, err := New(Options{API: &fakeAPI{clusterErr: errors.New("list boom")}}).Collect(context.Background(), req())
	if err == nil || !strings.Contains(err.Error(), "list boom") {
		t.Fatalf("cluster-list error should surface, got %v", err)
	}
}

func TestCollect_DiagnosticSettingsError(t *testing.T) {
	f := &fakeAPI{
		clusters: []*armcontainerservice.ManagedCluster{{ID: aksID("c"), Name: to.Ptr("c")}},
		diagErr:  errors.New("diag boom"),
	}
	_, err := New(Options{API: f}).Collect(context.Background(), req())
	if err == nil || !strings.Contains(err.Error(), "diag boom") || !strings.Contains(err.Error(), *aksID("c")) {
		t.Fatalf("diagnostic-settings error should surface with cluster id, got %v", err)
	}
}

func TestCollect_KISSNoDRY_RefetchesEachCollect(t *testing.T) {
	f := &fakeAPI{clusters: []*armcontainerservice.ManagedCluster{{ID: aksID("c"), Name: to.Ptr("c")}}}
	p := New(Options{API: f})
	for i := 0; i < 3; i++ {
		if _, err := p.Collect(context.Background(), req()); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
	}
	if f.clusterCalls != 3 || f.diagCalls != 3 {
		t.Errorf("expected 3 cluster + 3 diag calls, got %d / %d", f.clusterCalls, f.diagCalls)
	}
}

func TestKMSSecretsEncryptionEnabled_Table(t *testing.T) {
	mk := func(p *armcontainerservice.ManagedClusterProperties) *armcontainerservice.ManagedCluster {
		return &armcontainerservice.ManagedCluster{Properties: p}
	}
	cases := []struct {
		name string
		mc   *armcontainerservice.ManagedCluster
		want bool
	}{
		{"enabled", mk(&armcontainerservice.ManagedClusterProperties{SecurityProfile: &armcontainerservice.ManagedClusterSecurityProfile{AzureKeyVaultKms: &armcontainerservice.AzureKeyVaultKms{Enabled: to.Ptr(true)}}}), true},
		{"disabled", mk(&armcontainerservice.ManagedClusterProperties{SecurityProfile: &armcontainerservice.ManagedClusterSecurityProfile{AzureKeyVaultKms: &armcontainerservice.AzureKeyVaultKms{Enabled: to.Ptr(false)}}}), false},
		{"nil-enabled", mk(&armcontainerservice.ManagedClusterProperties{SecurityProfile: &armcontainerservice.ManagedClusterSecurityProfile{AzureKeyVaultKms: &armcontainerservice.AzureKeyVaultKms{}}}), false},
		{"nil-kms", mk(&armcontainerservice.ManagedClusterProperties{SecurityProfile: &armcontainerservice.ManagedClusterSecurityProfile{}}), false},
		{"nil-securityprofile", mk(&armcontainerservice.ManagedClusterProperties{}), false},
		{"nil-properties", &armcontainerservice.ManagedCluster{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := kmsSecretsEncryptionEnabled(c.mc); got != c.want {
				t.Errorf("kmsSecretsEncryptionEnabled = %v, want %v", got, c.want)
			}
		})
	}
}

func TestPrivateCluster_NilSafe(t *testing.T) {
	if privateCluster(&armcontainerservice.ManagedCluster{}) {
		t.Error("nil properties → false")
	}
	if privateCluster(&armcontainerservice.ManagedCluster{Properties: &armcontainerservice.ManagedClusterProperties{APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{}}}) {
		t.Error("nil EnablePrivateCluster → false")
	}
	if !privateCluster(&armcontainerservice.ManagedCluster{Properties: &armcontainerservice.ManagedClusterProperties{APIServerAccessProfile: &armcontainerservice.ManagedClusterAPIServerAccessProfile{EnablePrivateCluster: to.Ptr(true)}}}) {
		t.Error("EnablePrivateCluster=true → true")
	}
}

func TestAutoUpgradeEnabled_Table(t *testing.T) {
	mk := func(ch *armcontainerservice.UpgradeChannel) *armcontainerservice.ManagedCluster {
		return &armcontainerservice.ManagedCluster{Properties: &armcontainerservice.ManagedClusterProperties{AutoUpgradeProfile: &armcontainerservice.ManagedClusterAutoUpgradeProfile{UpgradeChannel: ch}}}
	}
	cases := []struct {
		name string
		mc   *armcontainerservice.ManagedCluster
		want bool
	}{
		{"stable", mk(to.Ptr(armcontainerservice.UpgradeChannelStable)), true},
		{"none", mk(to.Ptr(armcontainerservice.UpgradeChannelNone)), false},
		{"nil-channel", mk(nil), false},
		{"nil-profile", &armcontainerservice.ManagedCluster{Properties: &armcontainerservice.ManagedClusterProperties{}}, false},
		{"nil-properties", &armcontainerservice.ManagedCluster{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := autoUpgradeEnabled(c.mc); got != c.want {
				t.Errorf("autoUpgradeEnabled = %v, want %v", got, c.want)
			}
		})
	}
}

func TestAllPoolsEncryptionAtHost_Table(t *testing.T) {
	pool := func(on bool) *armcontainerservice.ManagedClusterAgentPoolProfile {
		return &armcontainerservice.ManagedClusterAgentPoolProfile{EnableEncryptionAtHost: to.Ptr(on)}
	}
	mk := func(pools ...*armcontainerservice.ManagedClusterAgentPoolProfile) *armcontainerservice.ManagedCluster {
		return &armcontainerservice.ManagedCluster{Properties: &armcontainerservice.ManagedClusterProperties{AgentPoolProfiles: pools}}
	}
	cases := []struct {
		name string
		mc   *armcontainerservice.ManagedCluster
		want bool
	}{
		{"all-on", mk(pool(true), pool(true)), true},
		{"one-off", mk(pool(true), pool(false)), false},
		{"nil-flag", mk(&armcontainerservice.ManagedClusterAgentPoolProfile{}), false},
		{"nil-pool", mk(nil), false},
		{"empty-pools", mk(), false},
		{"nil-properties", &armcontainerservice.ManagedCluster{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := allPoolsEncryptionAtHost(c.mc); got != c.want {
				t.Errorf("allPoolsEncryptionAtHost = %v, want %v", got, c.want)
			}
		})
	}
}

func TestAuditLoggingEnabled_Table(t *testing.T) {
	logs := func(ls ...*armmonitor.LogSettings) []*armmonitor.DiagnosticSettingsResource {
		return []*armmonitor.DiagnosticSettingsResource{{Properties: &armmonitor.DiagnosticSettings{Logs: ls}}}
	}
	cat := func(name string, on bool) *armmonitor.LogSettings {
		return &armmonitor.LogSettings{Category: to.Ptr(name), Enabled: to.Ptr(on)}
	}
	group := func(name string, on bool) *armmonitor.LogSettings {
		return &armmonitor.LogSettings{CategoryGroup: to.Ptr(name), Enabled: to.Ptr(on)}
	}
	cases := []struct {
		name     string
		settings []*armmonitor.DiagnosticSettingsResource
		wantOn   bool
		wantCats []string
	}{
		{"kube-audit", logs(cat("kube-audit", true)), true, []string{"kube-audit"}},
		{"kube-audit-admin", logs(cat("kube-audit-admin", true)), true, []string{"kube-audit-admin"}},
		{"guard", logs(cat("guard", true)), true, []string{"guard"}},
		{"audit-group", logs(group("audit", true)), true, []string{"audit"}},
		{"allLogs-group", logs(group("allLogs", true)), true, []string{"allLogs"}},
		{"disabled-audit", logs(cat("kube-audit", false)), false, nil},
		{"non-audit-category", logs(cat("cluster-autoscaler", true)), false, nil},
		{"dedup-and-sort", logs(cat("kube-audit", true), cat("guard", true), cat("kube-audit", true)), true, []string{"guard", "kube-audit"}},
		{"nil-settings", nil, false, nil},
		{"nil-properties", []*armmonitor.DiagnosticSettingsResource{{}}, false, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotOn, gotCats := auditLoggingEnabled(c.settings)
			if gotOn != c.wantOn || !reflect.DeepEqual(gotCats, c.wantCats) {
				t.Errorf("auditLoggingEnabled = (%v,%v), want (%v,%v)", gotOn, gotCats, c.wantOn, c.wantCats)
			}
		})
	}
}

func TestResourceGroupFromID(t *testing.T) {
	cases := []struct {
		id   string
		want string
	}{
		{"/subscriptions/s/resourceGroups/my-rg/providers/Microsoft.ContainerService/managedClusters/c", "my-rg"},
		{"/subscriptions/s/resourcegroups/lower/providers/x", "lower"},
		{"/subscriptions/s/providers/x", ""},
		{"garbage", ""},
	}
	for _, c := range cases {
		if got := resourceGroupFromID(c.id); got != c.want {
			t.Errorf("resourceGroupFromID(%q) = %q, want %q", c.id, got, c.want)
		}
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

func realAKSPointedAt(t *testing.T, srv *httptest.Server) *realAKS {
	t.Helper()
	opts := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.azure.com"},
		}},
		Transport: srv.Client(),
	}}
	r, err := newRealAKS("sub-1", fakeCred{}, opts)
	if err != nil {
		t.Fatalf("newRealAKS: %v", err)
	}
	return r
}

func TestRealAKS_HappyPath(t *testing.T) {
	clusterBody := mustMarshal(t, armcontainerservice.ManagedClusterListResult{Value: []*armcontainerservice.ManagedCluster{
		{Name: to.Ptr("c1"), ID: aksID("c1"), Properties: &armcontainerservice.ManagedClusterProperties{
			SecurityProfile: &armcontainerservice.ManagedClusterSecurityProfile{AzureKeyVaultKms: &armcontainerservice.AzureKeyVaultKms{Enabled: to.Ptr(true)}},
		}},
	}})
	diagBody := mustMarshal(t, armmonitor.DiagnosticSettingsResourceCollection{Value: []*armmonitor.DiagnosticSettingsResource{
		auditLogs("kube-audit"),
	}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/diagnosticSettings"):
			_, _ = w.Write(diagBody) //nolint:errcheck // test handler
		case strings.Contains(r.URL.Path, "/managedClusters"):
			_, _ = w.Write(clusterBody) //nolint:errcheck // test handler
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r := realAKSPointedAt(t, srv)
	clusters, err := r.ListManagedClusters(context.Background())
	if err != nil || len(clusters) != 1 || deref(clusters[0].Name) != "c1" {
		t.Fatalf("ListManagedClusters = %+v, err %v", clusters, err)
	}
	if !kmsSecretsEncryptionEnabled(clusters[0]) {
		t.Errorf("expected KMS-encrypted cluster to round-trip, got %+v", clusters[0])
	}
	settings, err := r.ListClusterDiagnosticSettings(context.Background(), deref(clusters[0].ID))
	if err != nil {
		t.Fatalf("ListClusterDiagnosticSettings: %v", err)
	}
	if on, cats := auditLoggingEnabled(settings); !on || len(cats) != 1 || cats[0] != "kube-audit" {
		t.Errorf("expected audit logging enabled, got on=%v cats=%v", on, cats)
	}
}

func TestRealAKS_ListError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r := realAKSPointedAt(t, srv)
	if _, err := r.ListManagedClusters(context.Background()); err == nil {
		t.Fatal("expected error on 403 for clusters, got nil")
	}
	if _, err := r.ListClusterDiagnosticSettings(context.Background(), *aksID("c1")); err == nil {
		t.Fatal("expected error on 403 for diagnostics, got nil")
	}
}
