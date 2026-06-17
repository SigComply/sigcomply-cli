package cosmos

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
	armcosmos "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v3"

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

// fakeAPI records calls and returns staged accounts.
type fakeAPI struct {
	accounts []*armcosmos.DatabaseAccountGetResults
	acctErr  error
	calls    int
}

func (f *fakeAPI) ListAccounts(context.Context) ([]*armcosmos.DatabaseAccountGetResults, error) {
	f.calls++
	if f.acctErr != nil {
		return nil, f.acctErr
	}
	return f.accounts, nil
}

func req() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}
}

func cosmosID(name string) *string {
	return to.Ptr("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/" + name)
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{})
	if got := p.ID(); got != "azure.cosmos" {
		t.Errorf("ID() = %q, want azure.cosmos", got)
	}
	got := p.Emits()
	if len(got) != 1 || got[0] != EvidenceTypeID {
		t.Errorf("Emits() = %v, want [nosql_table]", got)
	}
}

func TestCollect_RejectsNonEmittedType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "nosql_table") {
		t.Fatalf("expected rejection error, got %v", err)
	}
}

func TestCollect_MapsSortsAndFullPayload(t *testing.T) {
	// Two accounts (out of order to prove sort): a continuous-backup (PITR),
	// CMEK, private, AAD-only Mongo account; and a periodic-backup, public,
	// Microsoft-managed GlobalDocumentDB account.
	keyURI := "https://vault.vault.azure.net/keys/cosmos-key"
	f := &fakeAPI{
		accounts: []*armcosmos.DatabaseAccountGetResults{
			{
				ID:       cosmosID("z-prod"),
				Name:     to.Ptr("z-prod"),
				Location: to.Ptr("eastus"),
				Kind:     to.Ptr(armcosmos.DatabaseAccountKindMongoDB),
				Properties: &armcosmos.DatabaseAccountGetProperties{
					ProvisioningState:             to.Ptr("Succeeded"),
					KeyVaultKeyURI:                to.Ptr(keyURI),
					DisableLocalAuth:              to.Ptr(true),
					IsVirtualNetworkFilterEnabled: to.Ptr(true),
					PublicNetworkAccess:           to.Ptr(armcosmos.PublicNetworkAccessDisabled),
					BackupPolicy: &armcosmos.ContinuousModeBackupPolicy{
						Type: to.Ptr(armcosmos.BackupPolicyTypeContinuous),
						ContinuousModeProperties: &armcosmos.ContinuousModeProperties{
							Tier: to.Ptr(armcosmos.ContinuousTierContinuous30Days),
						},
					},
				},
			},
			{
				ID:       cosmosID("a-dev"),
				Name:     to.Ptr("a-dev"),
				Location: to.Ptr("westus"),
				Kind:     to.Ptr(armcosmos.DatabaseAccountKindGlobalDocumentDB),
				Properties: &armcosmos.DatabaseAccountGetProperties{
					ProvisioningState:   to.Ptr("Succeeded"),
					PublicNetworkAccess: to.Ptr(armcosmos.PublicNetworkAccessEnabled),
					BackupPolicy: &armcosmos.PeriodicModeBackupPolicy{
						Type: to.Ptr(armcosmos.BackupPolicyTypePeriodic),
					},
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
	if recs[0].ID != *cosmosID("a-dev") || recs[1].ID != *cosmosID("z-prod") {
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

	var dev accountPayload
	mustUnmarshal(t, recs[0].Payload, &dev)
	wantDev := accountPayload{
		ID:                         *cosmosID("a-dev"),
		Name:                       "a-dev",
		Provider:                   "azure",
		EncryptionEnabled:          true,
		PointInTimeRecoveryEnabled: false,
		DeletionProtection:         false,
		Kind:                       "GlobalDocumentDB",
		Location:                   "westus",
		ResourceGroup:              "rg",
		BackupPolicyType:           "Periodic",
		PublicNetworkAccess:        "Enabled",
		ProvisioningState:          "Succeeded",
	}
	if !reflect.DeepEqual(dev, wantDev) {
		t.Errorf("dev payload mismatch:\n got  %+v\n want %+v", dev, wantDev)
	}

	var prod accountPayload
	mustUnmarshal(t, recs[1].Payload, &prod)
	wantProd := accountPayload{
		ID:                         *cosmosID("z-prod"),
		Name:                       "z-prod",
		Provider:                   "azure",
		EncryptionEnabled:          true,
		PointInTimeRecoveryEnabled: true,
		DeletionProtection:         false,
		Kind:                       "MongoDB",
		Location:                   "eastus",
		ResourceGroup:              "rg",
		BackupPolicyType:           "Continuous",
		ContinuousBackupTier:       "Continuous30Days",
		CMEKEnabled:                true,
		KMSKeyID:                   keyURI,
		PublicNetworkAccess:        "Disabled",
		LocalAuthDisabled:          true,
		VNetFilterEnabled:          true,
		ProvisioningState:          "Succeeded",
	}
	if !reflect.DeepEqual(prod, wantProd) {
		t.Errorf("prod payload mismatch:\n got  %+v\n want %+v", prod, wantProd)
	}
}

// TestCollect_BarePropertiesStillRequiredFields proves the schema-required
// fields are emitted even for a bare account: encryption_enabled is the platform
// constant true, deletion_protection the constant false, PITR defaults false.
func TestCollect_BarePropertiesStillRequiredFields(t *testing.T) {
	f := &fakeAPI{accounts: []*armcosmos.DatabaseAccountGetResults{
		{ID: cosmosID("bare"), Name: to.Ptr("bare")}, // nil Properties, nil Kind
	}}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got accountPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if !got.EncryptionEnabled || got.PointInTimeRecoveryEnabled || got.DeletionProtection {
		t.Errorf("bare account: want encryption=true/pitr=false/deletion=false, got %+v", got)
	}
}

func TestCollect_NilEntriesSkipped(t *testing.T) {
	f := &fakeAPI{accounts: []*armcosmos.DatabaseAccountGetResults{
		nil,
		{ID: cosmosID("ok"), Name: to.Ptr("ok")},
	}}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record (nil account skipped), got %d", len(recs))
	}
}

func TestCollect_ErrorPropagation(t *testing.T) {
	_, err := New(Options{API: &fakeAPI{acctErr: errors.New("list boom")}}).Collect(context.Background(), req())
	if err == nil || !strings.Contains(err.Error(), "list boom") {
		t.Fatalf("list error should surface, got %v", err)
	}
}

// TestCollect_MalformedID_ResourceGroupEmpty proves a malformed ARM id yields an
// empty resource_group extra (informational) rather than an error.
func TestCollect_MalformedID_ResourceGroupEmpty(t *testing.T) {
	f := &fakeAPI{accounts: []*armcosmos.DatabaseAccountGetResults{
		{ID: to.Ptr("/subscriptions/s/providers/x/databaseAccounts/odd"), Name: to.Ptr("odd")},
	}}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got accountPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if got.ResourceGroup != "" {
		t.Errorf("malformed id should yield empty resource_group, got %q", got.ResourceGroup)
	}
}

func TestCollect_KISSNoDRY_RefetchesEachCollect(t *testing.T) {
	f := &fakeAPI{accounts: []*armcosmos.DatabaseAccountGetResults{{ID: cosmosID("c"), Name: to.Ptr("c")}}}
	p := New(Options{API: f})
	for i := 0; i < 3; i++ {
		if _, err := p.Collect(context.Background(), req()); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
	}
	if f.calls != 3 {
		t.Errorf("expected 3 list calls, got %d", f.calls)
	}
}

func TestPITREnabled_Table(t *testing.T) {
	mk := func(bp armcosmos.BackupPolicyClassification) *armcosmos.DatabaseAccountGetResults {
		return &armcosmos.DatabaseAccountGetResults{Properties: &armcosmos.DatabaseAccountGetProperties{BackupPolicy: bp}}
	}
	cases := []struct {
		name string
		acct *armcosmos.DatabaseAccountGetResults
		want bool
	}{
		{"continuous", mk(&armcosmos.ContinuousModeBackupPolicy{Type: to.Ptr(armcosmos.BackupPolicyTypeContinuous)}), true},
		{"periodic", mk(&armcosmos.PeriodicModeBackupPolicy{Type: to.Ptr(armcosmos.BackupPolicyTypePeriodic)}), false},
		{"nil-policy", mk(nil), false},
		{"nil-properties", &armcosmos.DatabaseAccountGetResults{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pitrEnabled(c.acct); got != c.want {
				t.Errorf("pitrEnabled = %v, want %v", got, c.want)
			}
		})
	}
}

func TestBackupPolicyTypeAndTier_Table(t *testing.T) {
	mk := func(bp armcosmos.BackupPolicyClassification) *armcosmos.DatabaseAccountGetResults {
		return &armcosmos.DatabaseAccountGetResults{Properties: &armcosmos.DatabaseAccountGetProperties{BackupPolicy: bp}}
	}
	cases := []struct {
		name     string
		acct     *armcosmos.DatabaseAccountGetResults
		wantType string
		wantTier string
	}{
		{"continuous-7d", mk(&armcosmos.ContinuousModeBackupPolicy{Type: to.Ptr(armcosmos.BackupPolicyTypeContinuous), ContinuousModeProperties: &armcosmos.ContinuousModeProperties{Tier: to.Ptr(armcosmos.ContinuousTierContinuous7Days)}}), "Continuous", "Continuous7Days"},
		{"continuous-no-tier", mk(&armcosmos.ContinuousModeBackupPolicy{Type: to.Ptr(armcosmos.BackupPolicyTypeContinuous)}), "Continuous", ""},
		{"periodic", mk(&armcosmos.PeriodicModeBackupPolicy{Type: to.Ptr(armcosmos.BackupPolicyTypePeriodic)}), "Periodic", ""},
		{"nil-policy", mk(nil), "", ""},
		{"nil-properties", &armcosmos.DatabaseAccountGetResults{}, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := backupPolicyType(c.acct); got != c.wantType {
				t.Errorf("backupPolicyType = %q, want %q", got, c.wantType)
			}
			if got := continuousBackupTier(c.acct); got != c.wantTier {
				t.Errorf("continuousBackupTier = %q, want %q", got, c.wantTier)
			}
		})
	}
}

func TestCMEKKeyID_NilSafe(t *testing.T) {
	if cmekKeyID(&armcosmos.DatabaseAccountGetResults{}) != "" {
		t.Error("nil properties → empty")
	}
	if cmekKeyID(&armcosmos.DatabaseAccountGetResults{Properties: &armcosmos.DatabaseAccountGetProperties{}}) != "" {
		t.Error("nil KeyVaultKeyURI → empty")
	}
	got := cmekKeyID(&armcosmos.DatabaseAccountGetResults{Properties: &armcosmos.DatabaseAccountGetProperties{KeyVaultKeyURI: to.Ptr("uri")}})
	if got != "uri" {
		t.Errorf("KeyVaultKeyURI set → %q, want uri", got)
	}
}

func TestResourceGroupFromID_Table(t *testing.T) {
	cases := []struct {
		id      string
		want    string
		wantErr bool
	}{
		{"/subscriptions/s/resourceGroups/my-rg/providers/Microsoft.DocumentDB/databaseAccounts/a", "my-rg", false},
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

func realCosmosPointedAt(t *testing.T, srv *httptest.Server) *realCosmos {
	t.Helper()
	opts := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.azure.com"},
		}},
		Transport: srv.Client(),
	}}
	rc, err := newRealCosmos("sub-1", fakeCred{}, opts)
	if err != nil {
		t.Fatalf("newRealCosmos: %v", err)
	}
	return rc
}

func TestRealCosmos_ListAccounts_HappyPath(t *testing.T) {
	body := mustMarshal(t, armcosmos.DatabaseAccountsListResult{Value: []*armcosmos.DatabaseAccountGetResults{
		{Name: to.Ptr("c1"), ID: cosmosID("c1"), Properties: &armcosmos.DatabaseAccountGetProperties{
			BackupPolicy: &armcosmos.ContinuousModeBackupPolicy{Type: to.Ptr(armcosmos.BackupPolicyTypeContinuous)},
		}},
	}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/databaseAccounts") {
			_, _ = w.Write(body) //nolint:errcheck // test handler
			return
		}
		t.Errorf("unexpected path: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rc := realCosmosPointedAt(t, srv)
	accts, err := rc.ListAccounts(context.Background())
	if err != nil || len(accts) != 1 || deref(accts[0].Name) != "c1" {
		t.Fatalf("ListAccounts = %+v, err %v", accts, err)
	}
	if !pitrEnabled(accts[0]) {
		t.Errorf("expected continuous-backup account to round-trip as PITR-enabled, got %+v", accts[0])
	}
}

func TestRealCosmos_ListError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	rc := realCosmosPointedAt(t, srv)
	if _, err := rc.ListAccounts(context.Background()); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}
