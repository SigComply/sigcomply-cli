package storage

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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

var fixedNow = time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)

// fakeAPI is the in-memory API seam used by the Collect unit tests.
type fakeAPI struct {
	accounts  []*armstorage.Account
	blob      map[string]*armstorage.BlobServicePropertiesProperties
	listErr   error
	blobErr   error
	listCalls int
	blobCalls int
}

func (f *fakeAPI) ListAccounts(context.Context) ([]*armstorage.Account, error) {
	f.listCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.accounts, nil
}

func (f *fakeAPI) GetBlobProperties(_ context.Context, _, account string) (*armstorage.BlobServicePropertiesProperties, error) {
	f.blobCalls++
	if f.blobErr != nil {
		return nil, f.blobErr
	}
	return f.blob[account], nil
}

func acceptReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}
}

func idOf(sub, rg, name string) *string {
	return to.Ptr("/subscriptions/" + sub + "/resourceGroups/" + rg + "/providers/Microsoft.Storage/storageAccounts/" + name)
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{})
	if got := p.ID(); got != "azure.storage" {
		t.Errorf("ID() = %q, want azure.storage", got)
	}
	if got := p.Emits(); len(got) != 1 || got[0] != EvidenceTypeID {
		t.Errorf("Emits() = %v, want [%s]", got, EvidenceTypeID)
	}
}

func TestCollect_RejectsNonEmittedType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"directory_user"}})
	if err == nil || !strings.Contains(err.Error(), EvidenceTypeID) {
		t.Fatalf("expected rejection error mentioning %s, got %v", EvidenceTypeID, err)
	}
}

func TestCollect_MapsSortsAndFullPayload(t *testing.T) {
	alpha := &armstorage.Account{
		Name:     to.Ptr("alpha"),
		ID:       idOf("sub-1", "rg-a", "alpha"),
		Location: to.Ptr("eastus"),
		Properties: &armstorage.AccountProperties{
			AllowBlobPublicAccess: to.Ptr(false),
			CreationTime:          to.Ptr(time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)),
			MinimumTLSVersion:     to.Ptr(armstorage.MinimumTLSVersionTLS12),
			PublicNetworkAccess:   to.Ptr(armstorage.PublicNetworkAccessEnabled),
			Encryption: &armstorage.Encryption{
				KeySource: to.Ptr(armstorage.KeySourceMicrosoftKeyvault),
				KeyVaultProperties: &armstorage.KeyVaultProperties{
					KeyVaultURI: to.Ptr("https://v.vault.azure.net"),
					KeyName:     to.Ptr("k1"),
					KeyVersion:  to.Ptr("ver1"),
				},
			},
		},
	}
	beta := &armstorage.Account{
		Name:     to.Ptr("beta"),
		ID:       idOf("sub-1", "rg-b", "beta"),
		Location: to.Ptr("westus"),
		Properties: &armstorage.AccountProperties{
			AllowBlobPublicAccess: to.Ptr(true),
			Encryption:            &armstorage.Encryption{KeySource: to.Ptr(armstorage.KeySourceMicrosoftStorage)},
		},
	}
	f := &fakeAPI{
		accounts: []*armstorage.Account{beta, alpha}, // unsorted on purpose
		blob: map[string]*armstorage.BlobServicePropertiesProperties{
			"alpha": {IsVersioningEnabled: to.Ptr(true)},
			"beta": {
				IsVersioningEnabled:   to.Ptr(false),
				DeleteRetentionPolicy: &armstorage.DeleteRetentionPolicy{Enabled: to.Ptr(true), Days: to.Ptr[int32](7)},
			},
		},
	}
	p := New(Options{API: f, SubscriptionID: "sub-1", Now: func() time.Time { return fixedNow }})

	recs, err := p.Collect(context.Background(), acceptReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs[0].ID != "alpha" || recs[1].ID != "beta" {
		t.Fatalf("records not sorted by ID: %s, %s", recs[0].ID, recs[1].ID)
	}

	for _, r := range recs {
		if r.Type != EvidenceTypeID || r.SourceID != SourceID {
			t.Errorf("record %s: Type/SourceID = %s/%s", r.ID, r.Type, r.SourceID)
		}
		if !r.CollectedAt.Equal(fixedNow) {
			t.Errorf("record %s: CollectedAt = %v", r.ID, r.CollectedAt)
		}
		if r.Scope == nil || r.Scope.Account != "sub-1" {
			t.Errorf("record %s: scope = %+v", r.ID, r.Scope)
		}
		if r.IdentityKey != "" {
			t.Errorf("record %s: unexpected IdentityKey %q", r.ID, r.IdentityKey)
		}
	}

	wantAlpha := bucketPayload{
		Name:                    "alpha",
		RegionOrLocation:        "eastus",
		EncryptionAtRestEnabled: true,
		KMSManaged:              true,
		KMSKeyID:                "https://v.vault.azure.net/k1/ver1",
		PublicAccessBlocked:     true,
		VersioningEnabled:       true,
		CreatedAt:               time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC),
		BlobVersioningEnabled:   true,
		BlobSoftDeleteEnabled:   false,
		MinimumTLSVersion:       "TLS1_2",
		PublicNetworkAccess:     "Enabled",
	}
	wantBeta := bucketPayload{
		Name:                    "beta",
		RegionOrLocation:        "westus",
		EncryptionAtRestEnabled: true,
		PublicAccessBlocked:     false,
		VersioningEnabled:       true,
		BlobVersioningEnabled:   false,
		BlobSoftDeleteEnabled:   true,
		SoftDeleteRetentionDays: 7,
	}
	assertPayload(t, recs[0].Payload, &wantAlpha)
	assertPayload(t, recs[1].Payload, &wantBeta)
}

func assertPayload(t *testing.T, raw json.RawMessage, want *bucketPayload) {
	t.Helper()
	var got bucketPayload
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if !reflect.DeepEqual(got, *want) {
		t.Errorf("payload mismatch:\n got  %+v\n want %+v", got, *want)
	}
}

func TestCollect_NilAccountSkipped(t *testing.T) {
	f := &fakeAPI{
		accounts: []*armstorage.Account{nil, {Name: to.Ptr("a"), ID: idOf("s", "rg", "a")}},
		blob:     map[string]*armstorage.BlobServicePropertiesProperties{"a": {}},
	}
	recs, err := New(Options{API: f}).Collect(context.Background(), acceptReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != "a" {
		t.Fatalf("expected one record 'a', got %+v", recs)
	}
}

func TestCollect_NilBlobProps_VersioningFalse(t *testing.T) {
	f := &fakeAPI{
		accounts: []*armstorage.Account{{Name: to.Ptr("a"), ID: idOf("s", "rg", "a"), Properties: &armstorage.AccountProperties{}}},
		blob:     map[string]*armstorage.BlobServicePropertiesProperties{}, // returns nil for "a"
	}
	recs, err := New(Options{API: f}).Collect(context.Background(), acceptReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got bucketPayload
	if err := json.Unmarshal(recs[0].Payload, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.VersioningEnabled || got.BlobVersioningEnabled || got.BlobSoftDeleteEnabled {
		t.Errorf("nil blob props should yield all-false versioning, got %+v", got)
	}
}

func TestCollect_ListError(t *testing.T) {
	f := &fakeAPI{listErr: errors.New("boom")}
	_, err := New(Options{API: f}).Collect(context.Background(), acceptReq())
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected list error, got %v", err)
	}
}

func TestCollect_BlobError(t *testing.T) {
	f := &fakeAPI{
		accounts: []*armstorage.Account{{Name: to.Ptr("a"), ID: idOf("s", "rg", "a")}},
		blobErr:  errors.New("403 forbidden"),
	}
	_, err := New(Options{API: f}).Collect(context.Background(), acceptReq())
	if err == nil || !strings.Contains(err.Error(), "403 forbidden") {
		t.Fatalf("expected blob error to propagate, got %v", err)
	}
}

func TestCollect_BadResourceGroupID(t *testing.T) {
	f := &fakeAPI{accounts: []*armstorage.Account{{Name: to.Ptr("a"), ID: to.Ptr("/subscriptions/s/providers/x")}}}
	_, err := New(Options{API: f}).Collect(context.Background(), acceptReq())
	if err == nil || !strings.Contains(err.Error(), "resourceGroups") {
		t.Fatalf("expected resource-group parse error, got %v", err)
	}
}

func TestCollect_KISSNoDRY_RefetchesEachCollect(t *testing.T) {
	f := &fakeAPI{
		accounts: []*armstorage.Account{{Name: to.Ptr("a"), ID: idOf("s", "rg", "a")}},
		blob:     map[string]*armstorage.BlobServicePropertiesProperties{"a": {}},
	}
	p := New(Options{API: f})
	for i := 0; i < 3; i++ {
		if _, err := p.Collect(context.Background(), acceptReq()); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
	}
	if f.listCalls != 3 || f.blobCalls != 3 {
		t.Errorf("expected 3 list + 3 blob calls, got %d + %d", f.listCalls, f.blobCalls)
	}
}

func TestPublicAccessBlocked_Table(t *testing.T) {
	cases := []struct {
		name string
		set  *bool
		want bool
	}{
		{"nil-not-blocked", nil, false},
		{"explicit-true-allows-public", to.Ptr(true), false},
		{"explicit-false-blocks-public", to.Ptr(false), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			acc := &armstorage.Account{Properties: &armstorage.AccountProperties{AllowBlobPublicAccess: c.set}}
			if got := publicAccessBlocked(acc); got != c.want {
				t.Errorf("publicAccessBlocked = %v, want %v", got, c.want)
			}
		})
	}
	if publicAccessBlocked(&armstorage.Account{}) {
		t.Error("nil Properties should yield false")
	}
}

func TestVersioningSignals_Table(t *testing.T) {
	cases := []struct {
		name              string
		bp                *armstorage.BlobServicePropertiesProperties
		wantVer, wantSoft bool
		wantDays          int32
	}{
		{"nil", nil, false, false, 0},
		{"versioning-only", &armstorage.BlobServicePropertiesProperties{IsVersioningEnabled: to.Ptr(true)}, true, false, 0},
		{"soft-delete-only", &armstorage.BlobServicePropertiesProperties{DeleteRetentionPolicy: &armstorage.DeleteRetentionPolicy{Enabled: to.Ptr(true), Days: to.Ptr[int32](30)}}, false, true, 30},
		{"soft-delete-disabled", &armstorage.BlobServicePropertiesProperties{DeleteRetentionPolicy: &armstorage.DeleteRetentionPolicy{Enabled: to.Ptr(false), Days: to.Ptr[int32](30)}}, false, false, 0},
		{"both", &armstorage.BlobServicePropertiesProperties{IsVersioningEnabled: to.Ptr(true), DeleteRetentionPolicy: &armstorage.DeleteRetentionPolicy{Enabled: to.Ptr(true)}}, true, true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ver, soft, days := versioningSignals(c.bp)
			if ver != c.wantVer || soft != c.wantSoft || days != c.wantDays {
				t.Errorf("versioningSignals = (%v,%v,%d), want (%v,%v,%d)", ver, soft, days, c.wantVer, c.wantSoft, c.wantDays)
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
		{"/subscriptions/s/resourceGroups/my-rg/providers/Microsoft.Storage/storageAccounts/a", "my-rg", false},
		{"/subscriptions/s/resourcegroups/lower-rg/providers/x", "lower-rg", false}, // case-insensitive
		{"/subscriptions/s/providers/x", "", true},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := resourceGroupFromID(c.id)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("resourceGroupFromID(%q) = (%q,%v), want (%q,err=%v)", c.id, got, err, c.want, c.wantErr)
		}
	}
}

func TestKMSKeyID(t *testing.T) {
	// CurrentVersionedKeyIdentifier takes precedence.
	enc := &armstorage.Encryption{
		KeySource: to.Ptr(armstorage.KeySourceMicrosoftKeyvault),
		KeyVaultProperties: &armstorage.KeyVaultProperties{
			KeyVaultURI:                   to.Ptr("https://v.vault.azure.net"),
			KeyName:                       to.Ptr("k"),
			CurrentVersionedKeyIdentifier: to.Ptr("https://v.vault.azure.net/keys/k/abc123"),
		},
	}
	if got := kmsKeyID(enc); got != "https://v.vault.azure.net/keys/k/abc123" {
		t.Errorf("kmsKeyID precedence = %q", got)
	}
	// Microsoft-managed → no key.
	if got := kmsKeyID(&armstorage.Encryption{KeySource: to.Ptr(armstorage.KeySourceMicrosoftStorage)}); got != "" {
		t.Errorf("microsoft-managed should have no key id, got %q", got)
	}
	// CMEK without KeyVaultProperties → empty.
	if got := kmsKeyID(&armstorage.Encryption{KeySource: to.Ptr(armstorage.KeySourceMicrosoftKeyvault)}); got != "" {
		t.Errorf("CMEK w/o vault props should be empty, got %q", got)
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

func realStoragePointedAt(t *testing.T, srv *httptest.Server) *realStorage {
	t.Helper()
	opts := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.azure.com"},
		}},
		Transport: srv.Client(),
	}}
	rs, err := newRealStorage("sub-1", fakeCred{}, opts)
	if err != nil {
		t.Fatalf("newRealStorage: %v", err)
	}
	return rs
}

func TestRealStorage_ListAndBlob_HappyPath(t *testing.T) {
	accountsBody := mustMarshal(t, armstorage.AccountListResult{Value: []*armstorage.Account{
		{Name: to.Ptr("alpha"), ID: idOf("sub-1", "rg-a", "alpha"), Location: to.Ptr("eastus"),
			Properties: &armstorage.AccountProperties{AllowBlobPublicAccess: to.Ptr(false)}},
	}})
	blobBody := mustMarshal(t, armstorage.BlobServiceProperties{
		BlobServiceProperties: &armstorage.BlobServicePropertiesProperties{IsVersioningEnabled: to.Ptr(true)},
	})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/storageAccounts"):
			_, _ = w.Write(accountsBody) //nolint:errcheck // test handler
		case strings.Contains(r.URL.Path, "/blobServices/"):
			if !strings.Contains(r.URL.Path, "/rg-a/") {
				t.Errorf("blob request used unexpected resource group: %s", r.URL.Path)
			}
			_, _ = w.Write(blobBody) //nolint:errcheck // test handler
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	rs := realStoragePointedAt(t, srv)
	accounts, err := rs.ListAccounts(context.Background())
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(accounts) != 1 || deref(accounts[0].Name) != "alpha" {
		t.Fatalf("unexpected accounts: %+v", accounts)
	}
	bp, err := rs.GetBlobProperties(context.Background(), "rg-a", "alpha")
	if err != nil {
		t.Fatalf("GetBlobProperties: %v", err)
	}
	if bp == nil || bp.IsVersioningEnabled == nil || !*bp.IsVersioningEnabled {
		t.Fatalf("expected versioning enabled, got %+v", bp)
	}
}

func TestRealStorage_ListError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	rs := realStoragePointedAt(t, srv)
	if _, err := rs.ListAccounts(context.Background()); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}
