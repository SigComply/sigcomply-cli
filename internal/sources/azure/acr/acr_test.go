package acr

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
	armcontainerregistry "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry/v3"

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

// fakeAPI records calls and returns staged registries.
type fakeAPI struct {
	registries []*armcontainerregistry.Registry
	regErr     error
	regCalls   int
}

func (f *fakeAPI) ListRegistries(context.Context) ([]*armcontainerregistry.Registry, error) {
	f.regCalls++
	if f.regErr != nil {
		return nil, f.regErr
	}
	return f.registries, nil
}

func req() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}
}

func acrID(name string) *string {
	return to.Ptr("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/" + name)
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{})
	if got := p.ID(); got != "azure.acr" {
		t.Errorf("ID() = %q, want azure.acr", got)
	}
	got := p.Emits()
	if len(got) != 1 || got[0] != EvidenceTypeID {
		t.Errorf("Emits() = %v, want [container_registry]", got)
	}
}

func TestCollect_RejectsNonEmittedType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "container_registry") {
		t.Fatalf("expected rejection error, got %v", err)
	}
}

func TestCollect_MapsSortsAndFullPayload(t *testing.T) {
	// Two registries (out of order to prove sort): a public (anonymous-pull),
	// quarantine-gated, CMEK, admin-enabled Premium registry; and a private,
	// no-quarantine, Microsoft-managed Basic registry.
	keyURI := "https://vault.vault.azure.net/keys/k/abc123"
	f := &fakeAPI{
		registries: []*armcontainerregistry.Registry{
			{
				ID:       acrID("z-prod"),
				Name:     to.Ptr("z-prod"),
				Location: to.Ptr("eastus"),
				SKU:      &armcontainerregistry.SKU{Name: to.Ptr(armcontainerregistry.SKUNamePremium)},
				Properties: &armcontainerregistry.RegistryProperties{
					LoginServer:          to.Ptr("zprod.azurecr.io"),
					AdminUserEnabled:     to.Ptr(true),
					AnonymousPullEnabled: to.Ptr(true),
					PublicNetworkAccess:  to.Ptr(armcontainerregistry.PublicNetworkAccessEnabled),
					ZoneRedundancy:       to.Ptr(armcontainerregistry.ZoneRedundancyEnabled),
					Encryption: &armcontainerregistry.EncryptionProperty{
						Status:             to.Ptr(armcontainerregistry.EncryptionStatusEnabled),
						KeyVaultProperties: &armcontainerregistry.KeyVaultProperties{VersionedKeyIdentifier: to.Ptr(keyURI)},
					},
					Policies: &armcontainerregistry.Policies{
						QuarantinePolicy: &armcontainerregistry.QuarantinePolicy{Status: to.Ptr(armcontainerregistry.PolicyStatusEnabled)},
					},
				},
			},
			{
				ID:       acrID("a-dev"),
				Name:     to.Ptr("a-dev"),
				Location: to.Ptr("westus"),
				SKU:      &armcontainerregistry.SKU{Name: to.Ptr(armcontainerregistry.SKUNameBasic)},
				Properties: &armcontainerregistry.RegistryProperties{
					LoginServer:         to.Ptr("adev.azurecr.io"),
					PublicNetworkAccess: to.Ptr(armcontainerregistry.PublicNetworkAccessDisabled),
					Encryption:          &armcontainerregistry.EncryptionProperty{Status: to.Ptr(armcontainerregistry.EncryptionStatusEnabled)},
				},
			},
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
	if recs[0].ID != *acrID("a-dev") || recs[1].ID != *acrID("z-prod") {
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

	var dev registryPayload
	mustUnmarshal(t, recs[0].Payload, &dev)
	wantDev := registryPayload{
		ID:                  *acrID("a-dev"),
		Name:                "a-dev",
		Provider:            "azure",
		Region:              "westus",
		ScanOnPushEnabled:   false,
		IsPublic:            false,
		EncryptionEnabled:   true,
		SKU:                 "Basic",
		LoginServer:         "adev.azurecr.io",
		PublicNetworkAccess: "Disabled",
		EncryptionStatus:    "enabled",
		ResourceGroup:       "rg",
	}
	if !reflect.DeepEqual(dev, wantDev) {
		t.Errorf("dev payload mismatch:\n got  %+v\n want %+v", dev, wantDev)
	}

	var prod registryPayload
	mustUnmarshal(t, recs[1].Payload, &prod)
	wantProd := registryPayload{
		ID:                     *acrID("z-prod"),
		Name:                   "z-prod",
		Provider:               "azure",
		Region:                 "eastus",
		ScanOnPushEnabled:      true,
		IsPublic:               true,
		EncryptionEnabled:      true,
		SKU:                    "Premium",
		LoginServer:            "zprod.azurecr.io",
		PublicNetworkAccess:    "Enabled",
		AnonymousPullEnabled:   true,
		AdminUserEnabled:       true,
		CMEKEnabled:            true,
		KMSKeyID:               keyURI,
		EncryptionStatus:       "enabled",
		ZoneRedundancy:         "Enabled",
		QuarantinePolicyStatus: "enabled",
		ResourceGroup:          "rg",
	}
	if !reflect.DeepEqual(prod, wantProd) {
		t.Errorf("prod payload mismatch:\n got  %+v\n want %+v", prod, wantProd)
	}
}

// TestCollect_NilPropertiesStillEncrypted proves the schema-required fields are
// emitted even for a bare registry: encryption_enabled is the platform constant
// true, scan/public default false, and the always-on constant never depends on
// the Encryption block being present.
func TestCollect_NilPropertiesStillEncrypted(t *testing.T) {
	f := &fakeAPI{registries: []*armcontainerregistry.Registry{
		{ID: acrID("bare"), Name: to.Ptr("bare")}, // nil Properties, nil SKU
	}}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got registryPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if !got.EncryptionEnabled || got.ScanOnPushEnabled || got.IsPublic {
		t.Errorf("bare registry: want encryption=true/scan=false/public=false, got %+v", got)
	}
}

func TestCollect_NilEntriesSkipped(t *testing.T) {
	f := &fakeAPI{registries: []*armcontainerregistry.Registry{
		nil,
		{ID: acrID("ok"), Name: to.Ptr("ok")},
	}}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record (nil registry skipped), got %d", len(recs))
	}
}

func TestCollect_ErrorPropagation(t *testing.T) {
	_, err := New(Options{API: &fakeAPI{regErr: errors.New("list boom")}}).Collect(context.Background(), req())
	if err == nil || !strings.Contains(err.Error(), "list boom") {
		t.Fatalf("list error should surface, got %v", err)
	}
}

// TestCollect_MalformedID_ResourceGroupEmpty proves a malformed ARM id yields an
// empty resource_group extra (informational) rather than an error — unlike
// azure.compute there is no follow-up GET that would need the parsed group.
func TestCollect_MalformedID_ResourceGroupEmpty(t *testing.T) {
	f := &fakeAPI{registries: []*armcontainerregistry.Registry{
		{ID: to.Ptr("/subscriptions/s/providers/x/registries/odd"), Name: to.Ptr("odd")},
	}}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got registryPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if got.ResourceGroup != "" {
		t.Errorf("malformed id should yield empty resource_group, got %q", got.ResourceGroup)
	}
}

func TestCollect_KISSNoDRY_RefetchesEachCollect(t *testing.T) {
	f := &fakeAPI{registries: []*armcontainerregistry.Registry{{ID: acrID("r"), Name: to.Ptr("r")}}}
	p := New(Options{API: f})
	for i := 0; i < 3; i++ {
		if _, err := p.Collect(context.Background(), req()); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
	}
	if f.regCalls != 3 {
		t.Errorf("expected 3 list calls, got %d", f.regCalls)
	}
}

func TestQuarantineEnabled_Table(t *testing.T) {
	mk := func(p *armcontainerregistry.RegistryProperties) *armcontainerregistry.Registry {
		return &armcontainerregistry.Registry{Properties: p}
	}
	cases := []struct {
		name string
		reg  *armcontainerregistry.Registry
		want bool
	}{
		{"enabled", mk(&armcontainerregistry.RegistryProperties{Policies: &armcontainerregistry.Policies{QuarantinePolicy: &armcontainerregistry.QuarantinePolicy{Status: to.Ptr(armcontainerregistry.PolicyStatusEnabled)}}}), true},
		{"disabled", mk(&armcontainerregistry.RegistryProperties{Policies: &armcontainerregistry.Policies{QuarantinePolicy: &armcontainerregistry.QuarantinePolicy{Status: to.Ptr(armcontainerregistry.PolicyStatusDisabled)}}}), false},
		{"nil-status", mk(&armcontainerregistry.RegistryProperties{Policies: &armcontainerregistry.Policies{QuarantinePolicy: &armcontainerregistry.QuarantinePolicy{}}}), false},
		{"nil-quarantine", mk(&armcontainerregistry.RegistryProperties{Policies: &armcontainerregistry.Policies{}}), false},
		{"nil-policies", mk(&armcontainerregistry.RegistryProperties{}), false},
		{"nil-properties", &armcontainerregistry.Registry{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := quarantineEnabled(c.reg); got != c.want {
				t.Errorf("quarantineEnabled = %v, want %v", got, c.want)
			}
		})
	}
}

func TestAnonymousPullEnabled_NilSafe(t *testing.T) {
	if anonymousPullEnabled(&armcontainerregistry.Registry{}) {
		t.Error("nil properties → false")
	}
	if anonymousPullEnabled(&armcontainerregistry.Registry{Properties: &armcontainerregistry.RegistryProperties{}}) {
		t.Error("nil AnonymousPullEnabled → false")
	}
	if !anonymousPullEnabled(&armcontainerregistry.Registry{Properties: &armcontainerregistry.RegistryProperties{AnonymousPullEnabled: to.Ptr(true)}}) {
		t.Error("AnonymousPullEnabled=true → true")
	}
}

func TestCMEKKeyID_Table(t *testing.T) {
	mk := func(e *armcontainerregistry.EncryptionProperty) *armcontainerregistry.Registry {
		return &armcontainerregistry.Registry{Properties: &armcontainerregistry.RegistryProperties{Encryption: e}}
	}
	cases := []struct {
		name string
		reg  *armcontainerregistry.Registry
		want string
	}{
		{"versioned-preferred", mk(&armcontainerregistry.EncryptionProperty{KeyVaultProperties: &armcontainerregistry.KeyVaultProperties{KeyIdentifier: to.Ptr("base"), VersionedKeyIdentifier: to.Ptr("versioned")}}), "versioned"},
		{"falls-back-to-unversioned", mk(&armcontainerregistry.EncryptionProperty{KeyVaultProperties: &armcontainerregistry.KeyVaultProperties{KeyIdentifier: to.Ptr("base")}}), "base"},
		{"no-keyvault-props", mk(&armcontainerregistry.EncryptionProperty{Status: to.Ptr(armcontainerregistry.EncryptionStatusEnabled)}), ""},
		{"nil-encryption", mk(nil), ""},
		{"nil-properties", &armcontainerregistry.Registry{}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cmekKeyID(c.reg); got != c.want {
				t.Errorf("cmekKeyID = %q, want %q", got, c.want)
			}
		})
	}
}

func TestResourceGroupFromID_Table(t *testing.T) {
	cases := []struct {
		id      string
		want    string
		wantErr bool
	}{
		{"/subscriptions/s/resourceGroups/my-rg/providers/Microsoft.ContainerRegistry/registries/r", "my-rg", false},
		{"/subscriptions/s/resourcegroups/lower/providers/x", "lower", false},
		{"/subscriptions/s/providers/x", "", true},
	}
	for _, c := range cases {
		got, err := resourceGroupFromID(c.id)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("resourceGroupFromID(%q) = (%q,%v), want (%q,err=%v)", c.id, got, err, c.want, c.wantErr)
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

func realACRPointedAt(t *testing.T, srv *httptest.Server) *realACR {
	t.Helper()
	opts := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.azure.com"},
		}},
		Transport: srv.Client(),
	}}
	rc, err := newRealACR("sub-1", fakeCred{}, opts)
	if err != nil {
		t.Fatalf("newRealACR: %v", err)
	}
	return rc
}

func TestRealACR_ListRegistries_HappyPath(t *testing.T) {
	body := mustMarshal(t, armcontainerregistry.RegistryListResult{Value: []*armcontainerregistry.Registry{
		{Name: to.Ptr("acr1"), ID: acrID("acr1"), Properties: &armcontainerregistry.RegistryProperties{AnonymousPullEnabled: to.Ptr(true)}},
	}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/registries") {
			_, _ = w.Write(body) //nolint:errcheck // test handler
			return
		}
		t.Errorf("unexpected path: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rc := realACRPointedAt(t, srv)
	regs, err := rc.ListRegistries(context.Background())
	if err != nil || len(regs) != 1 || deref(regs[0].Name) != "acr1" {
		t.Fatalf("ListRegistries = %+v, err %v", regs, err)
	}
	if !anonymousPullEnabled(regs[0]) {
		t.Errorf("expected anonymous-pull registry to round-trip, got %+v", regs[0])
	}
}

func TestRealACR_ListError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	rc := realACRPointedAt(t, srv)
	if _, err := rc.ListRegistries(context.Background()); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}
