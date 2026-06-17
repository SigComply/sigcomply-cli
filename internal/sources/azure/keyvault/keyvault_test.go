package keyvault

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
	armkeyvault "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault/v2"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

var fixedNow = time.Date(2026, 6, 17, 12, 0, 0, 0, time.UTC)

const subID = "sub-1"

// --- id builders ---

func vaultID(rg, name string) *string {
	return to.Ptr("/subscriptions/" + subID + "/resourceGroups/" + rg + "/providers/Microsoft.KeyVault/vaults/" + name)
}

func keyID(rg, vault, name string) *string {
	return to.Ptr(*vaultID(rg, vault) + "/keys/" + name)
}

// secretID builds a secret resource id; every secret fixture lives in rg1/kv-a.
func secretID(name string) *string {
	return to.Ptr(*vaultID("rg1", "kv-a") + "/secrets/" + name)
}

// --- fakeAPI ---

type fakeAPI struct {
	vaults   []*armkeyvault.Vault
	keys     map[string][]*armkeyvault.Key    // vaultName -> stripped list keys
	fullKeys map[string]*armkeyvault.Key      // keyName -> full key
	secrets  map[string][]*armkeyvault.Secret // vaultName -> secrets

	vaultsErr  error
	keysErr    error
	getKeyErr  error
	secretsErr error

	vaultCalls   int
	listKeyCalls int
	getKeyCalls  int
	secretCalls  int
}

func (f *fakeAPI) ListVaults(context.Context) ([]*armkeyvault.Vault, error) {
	f.vaultCalls++
	if f.vaultsErr != nil {
		return nil, f.vaultsErr
	}
	return f.vaults, nil
}

func (f *fakeAPI) ListKeys(_ context.Context, _, vaultName string) ([]*armkeyvault.Key, error) {
	f.listKeyCalls++
	if f.keysErr != nil {
		return nil, f.keysErr
	}
	return f.keys[vaultName], nil
}

func (f *fakeAPI) GetKey(_ context.Context, _, _, keyName string) (*armkeyvault.Key, error) {
	f.getKeyCalls++
	if f.getKeyErr != nil {
		return nil, f.getKeyErr
	}
	return f.fullKeys[keyName], nil
}

func (f *fakeAPI) ListSecrets(_ context.Context, _, vaultName string) ([]*armkeyvault.Secret, error) {
	f.secretCalls++
	if f.secretsErr != nil {
		return nil, f.secretsErr
	}
	return f.secrets[vaultName], nil
}

// --- fixtures ---

// rotatingHSMKey is a full key with auto-rotation and HSM protection.
func rotatingHSMKey(rg, vault, name string) *armkeyvault.Key {
	return &armkeyvault.Key{
		ID:   keyID(rg, vault, name),
		Name: to.Ptr(name),
		Properties: &armkeyvault.KeyProperties{
			Attributes: &armkeyvault.KeyAttributes{Enabled: to.Ptr(true)},
			Kty:        to.Ptr(armkeyvault.JSONWebKeyTypeRSAHSM),
			RotationPolicy: &armkeyvault.RotationPolicy{
				LifetimeActions: []*armkeyvault.LifetimeAction{{
					Action:  &armkeyvault.Action{Type: to.Ptr(armkeyvault.KeyRotationPolicyActionTypeRotate)},
					Trigger: &armkeyvault.Trigger{TimeAfterCreate: to.Ptr("P90D")},
				}},
			},
		},
	}
}

// plainSoftwareKey is a full key with no rotation policy and software backing.
func plainSoftwareKey(rg, vault, name string) *armkeyvault.Key {
	return &armkeyvault.Key{
		ID:   keyID(rg, vault, name),
		Name: to.Ptr(name),
		Properties: &armkeyvault.KeyProperties{
			Attributes: &armkeyvault.KeyAttributes{Enabled: to.Ptr(false)},
			Kty:        to.Ptr(armkeyvault.JSONWebKeyTypeRSA),
		},
	}
}

func newPlugin(api API) *Plugin {
	return New(Options{API: api, SubscriptionID: subID, Now: func() time.Time { return fixedNow }})
}

func req(types ...string) core.SlotRequest { return core.SlotRequest{AcceptedTypes: types} }

func unmarshalKey(t *testing.T, raw json.RawMessage) keyPayload {
	t.Helper()
	var p keyPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal key payload: %v", err)
	}
	return p
}

func unmarshalSecret(t *testing.T, raw json.RawMessage) secretPayload {
	t.Helper()
	var p secretPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal secret payload: %v", err)
	}
	return p
}

// --- tests ---

func TestPlugin_IDAndEmits(t *testing.T) {
	p := newPlugin(&fakeAPI{})
	if p.ID() != "azure.keyvault" {
		t.Errorf("ID() = %q", p.ID())
	}
	if got := p.Emits(); !reflect.DeepEqual(got, []string{"kms_key", "secret"}) {
		t.Errorf("Emits() = %v", got)
	}
}

func TestCollect_RejectsWhenNoEmittedTypeAccepted(t *testing.T) {
	p := newPlugin(&fakeAPI{})
	_, err := p.Collect(context.Background(), req("network"))
	if err == nil || !strings.Contains(err.Error(), "does not include emitted types") {
		t.Fatalf("expected reject error, got %v", err)
	}
}

func TestCollect_Keys_MapsSortsFullPayload(t *testing.T) {
	f := &fakeAPI{
		vaults: []*armkeyvault.Vault{
			{ID: vaultID("rg1", "kv-a"), Name: to.Ptr("kv-a")},
			{ID: vaultID("rg2", "kv-b"), Name: to.Ptr("kv-b")},
		},
		keys: map[string][]*armkeyvault.Key{
			"kv-a": {{ID: keyID("rg1", "kv-a", "k-rotate"), Name: to.Ptr("k-rotate")}},
			"kv-b": {{ID: keyID("rg2", "kv-b", "k-plain"), Name: to.Ptr("k-plain")}},
		},
		fullKeys: map[string]*armkeyvault.Key{
			"k-rotate": rotatingHSMKey("rg1", "kv-a", "k-rotate"),
			"k-plain":  plainSoftwareKey("rg2", "kv-b", "k-plain"),
		},
	}
	recs, err := newPlugin(f).Collect(context.Background(), req("kms_key"))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("len(recs) = %d, want 2", len(recs))
	}
	// Sorted by ID: rg1/kv-a/k-rotate < rg2/kv-b/k-plain.
	if recs[0].ID >= recs[1].ID {
		t.Errorf("records not sorted by ID: %q, %q", recs[0].ID, recs[1].ID)
	}
	for _, r := range recs {
		if r.Type != "kms_key" || r.SourceID != "azure.keyvault" || !r.CollectedAt.Equal(fixedNow) {
			t.Errorf("record envelope wrong: %+v", r)
		}
		if r.Scope == nil || r.Scope.Account != subID {
			t.Errorf("scope = %+v, want account %q", r.Scope, subID)
		}
	}

	gotRotate := unmarshalKey(t, recs[0].Payload)
	wantRotate := keyPayload{
		KeyID:             *keyID("rg1", "kv-a", "k-rotate"),
		KeyManager:        "CUSTOMER",
		IsCustomerManaged: true,
		Enabled:           true,
		RotationEnabled:   true,
		Provider:          "azure",
		ProtectionLevel:   "HSM",
		KeyType:           "RSA-HSM",
		RotationPeriod:    "P90D",
		VaultName:         "kv-a",
		ResourceGroup:     "rg1",
	}
	if !reflect.DeepEqual(gotRotate, wantRotate) {
		t.Errorf("rotate key payload\n got %+v\nwant %+v", gotRotate, wantRotate)
	}

	gotPlain := unmarshalKey(t, recs[1].Payload)
	wantPlain := keyPayload{
		KeyID:             *keyID("rg2", "kv-b", "k-plain"),
		KeyManager:        "CUSTOMER",
		IsCustomerManaged: true,
		Enabled:           false,
		RotationEnabled:   false,
		Provider:          "azure",
		ProtectionLevel:   "SOFTWARE",
		KeyType:           "RSA",
		VaultName:         "kv-b",
		ResourceGroup:     "rg2",
	}
	if !reflect.DeepEqual(gotPlain, wantPlain) {
		t.Errorf("plain key payload\n got %+v\nwant %+v", gotPlain, wantPlain)
	}
}

func TestCollect_Secrets_MapsSortsFullPayload(t *testing.T) {
	created := fixedNow.Add(-30 * 24 * time.Hour)
	updated := fixedNow.Add(-5 * 24 * time.Hour)
	f := &fakeAPI{
		vaults: []*armkeyvault.Vault{{ID: vaultID("rg1", "kv-a"), Name: to.Ptr("kv-a")}},
		secrets: map[string][]*armkeyvault.Secret{
			"kv-a": {
				{ID: secretID("s-old"), Name: to.Ptr("s-old"), Properties: &armkeyvault.SecretProperties{
					ContentType: to.Ptr("text/plain"),
					Attributes:  &armkeyvault.SecretAttributes{Enabled: to.Ptr(true), Created: &created, Updated: &created},
				}},
				{ID: secretID("s-rot"), Name: to.Ptr("s-rot"), Properties: &armkeyvault.SecretProperties{
					Attributes: &armkeyvault.SecretAttributes{Enabled: to.Ptr(true), Created: &created, Updated: &updated},
				}},
			},
		},
	}
	recs, err := newPlugin(f).Collect(context.Background(), req("secret"))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("len(recs) = %d, want 2", len(recs))
	}
	for _, r := range recs {
		if r.Type != "secret" {
			t.Errorf("record type = %q, want secret", r.Type)
		}
	}

	// Sorted by ID: s-old < s-rot.
	gotOld := unmarshalSecret(t, recs[0].Payload)
	wantOld := secretPayload{
		ID:              *secretID("s-old"),
		Name:            "s-old",
		Provider:        "azure",
		RotationEnabled: false,
		KMSEncrypted:    true,
		NeverRotated:    true,
		LastRotatedDays: nil,
		ContentType:     "text/plain",
		Enabled:         true,
		VaultName:       "kv-a",
		ResourceGroup:   "rg1",
	}
	if !reflect.DeepEqual(gotOld, wantOld) {
		t.Errorf("never-rotated secret payload\n got %+v\nwant %+v", gotOld, wantOld)
	}

	gotRot := unmarshalSecret(t, recs[1].Payload)
	wantRot := secretPayload{
		ID:              *secretID("s-rot"),
		Name:            "s-rot",
		Provider:        "azure",
		RotationEnabled: false,
		KMSEncrypted:    true,
		NeverRotated:    false,
		LastRotatedDays: to.Ptr(5),
		Enabled:         true,
		VaultName:       "kv-a",
		ResourceGroup:   "rg1",
	}
	if !reflect.DeepEqual(gotRot, wantRot) {
		t.Errorf("rotated secret payload\n got %+v\nwant %+v", gotRot, wantRot)
	}
}

func TestCollect_BothTypes_GroupedInEmitsOrder(t *testing.T) {
	f := &fakeAPI{
		vaults: []*armkeyvault.Vault{{ID: vaultID("rg1", "kv-a"), Name: to.Ptr("kv-a")}},
		keys: map[string][]*armkeyvault.Key{
			"kv-a": {{ID: keyID("rg1", "kv-a", "k1"), Name: to.Ptr("k1")}},
		},
		fullKeys: map[string]*armkeyvault.Key{"k1": plainSoftwareKey("rg1", "kv-a", "k1")},
		secrets: map[string][]*armkeyvault.Secret{
			"kv-a": {{ID: secretID("s1"), Name: to.Ptr("s1"), Properties: &armkeyvault.SecretProperties{
				Attributes: &armkeyvault.SecretAttributes{Enabled: to.Ptr(true)},
			}}},
		},
	}
	recs, err := newPlugin(f).Collect(context.Background(), req("kms_key", "secret"))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 || recs[0].Type != "kms_key" || recs[1].Type != "secret" {
		t.Fatalf("expected [kms_key, secret] in Emits order, got %+v", recs)
	}
	// Vaults listed once even though both collectors need them.
	if f.vaultCalls != 1 {
		t.Errorf("vaultCalls = %d, want 1", f.vaultCalls)
	}
}

func TestCollect_OnlyKeys_DoesNotListSecrets(t *testing.T) {
	f := &fakeAPI{vaults: []*armkeyvault.Vault{{ID: vaultID("rg1", "kv-a"), Name: to.Ptr("kv-a")}}}
	if _, err := newPlugin(f).Collect(context.Background(), req("kms_key")); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if f.listKeyCalls != 1 || f.secretCalls != 0 {
		t.Errorf("listKeyCalls=%d secretCalls=%d, want 1 and 0", f.listKeyCalls, f.secretCalls)
	}
}

func TestCollect_OnlySecrets_DoesNotListOrGetKeys(t *testing.T) {
	f := &fakeAPI{vaults: []*armkeyvault.Vault{{ID: vaultID("rg1", "kv-a"), Name: to.Ptr("kv-a")}}}
	if _, err := newPlugin(f).Collect(context.Background(), req("secret")); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if f.secretCalls != 1 || f.listKeyCalls != 0 || f.getKeyCalls != 0 {
		t.Errorf("secretCalls=%d listKeyCalls=%d getKeyCalls=%d, want 1, 0, 0", f.secretCalls, f.listKeyCalls, f.getKeyCalls)
	}
}

func TestCollect_NilEntriesSkipped(t *testing.T) {
	f := &fakeAPI{
		vaults: []*armkeyvault.Vault{nil, {ID: vaultID("rg1", "kv-a"), Name: to.Ptr("kv-a")}},
		keys: map[string][]*armkeyvault.Key{
			"kv-a": {nil, {ID: keyID("rg1", "kv-a", "k1"), Name: to.Ptr("k1")}},
		},
		fullKeys: map[string]*armkeyvault.Key{"k1": nil}, // GetKey returns nil → skipped
		secrets: map[string][]*armkeyvault.Secret{
			"kv-a": {nil},
		},
	}
	recs, err := newPlugin(f).Collect(context.Background(), req("kms_key", "secret"))
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("len(recs) = %d, want 0 (all entries nil/skipped)", len(recs))
	}
}

func TestCollect_ErrorPropagation(t *testing.T) {
	base := func() *fakeAPI {
		return &fakeAPI{
			vaults: []*armkeyvault.Vault{{ID: vaultID("rg1", "kv-a"), Name: to.Ptr("kv-a")}},
			keys: map[string][]*armkeyvault.Key{
				"kv-a": {{ID: keyID("rg1", "kv-a", "k1"), Name: to.Ptr("k1")}},
			},
			fullKeys: map[string]*armkeyvault.Key{"k1": plainSoftwareKey("rg1", "kv-a", "k1")},
			secrets: map[string][]*armkeyvault.Secret{
				"kv-a": {{ID: secretID("s1"), Name: to.Ptr("s1"), Properties: &armkeyvault.SecretProperties{}}},
			},
		}
	}
	boom := errors.New("boom")
	tests := []struct {
		name    string
		mutate  func(*fakeAPI)
		accepts []string
	}{
		{"vaults", func(f *fakeAPI) { f.vaultsErr = boom }, []string{"kms_key"}},
		{"keys", func(f *fakeAPI) { f.keysErr = boom }, []string{"kms_key"}},
		{"getKey", func(f *fakeAPI) { f.getKeyErr = boom }, []string{"kms_key"}},
		{"secrets", func(f *fakeAPI) { f.secretsErr = boom }, []string{"secret"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := base()
			tc.mutate(f)
			if _, err := newPlugin(f).Collect(context.Background(), req(tc.accepts...)); err == nil {
				t.Fatalf("expected error for %s failure", tc.name)
			}
		})
	}
}

func TestCollect_BadResourceGroupID(t *testing.T) {
	f := &fakeAPI{vaults: []*armkeyvault.Vault{{ID: to.Ptr("/no/resource/group/here"), Name: to.Ptr("kv-a")}}}
	if _, err := newPlugin(f).Collect(context.Background(), req("kms_key")); err == nil {
		t.Fatal("expected error for malformed vault ID")
	}
}

func TestCollect_KISSNoDRY_RefetchesEachCall(t *testing.T) {
	f := &fakeAPI{
		vaults: []*armkeyvault.Vault{{ID: vaultID("rg1", "kv-a"), Name: to.Ptr("kv-a")}},
		keys: map[string][]*armkeyvault.Key{
			"kv-a": {{ID: keyID("rg1", "kv-a", "k1"), Name: to.Ptr("k1")}},
		},
		fullKeys: map[string]*armkeyvault.Key{"k1": plainSoftwareKey("rg1", "kv-a", "k1")},
		secrets: map[string][]*armkeyvault.Secret{
			"kv-a": {{ID: secretID("s1"), Name: to.Ptr("s1"), Properties: &armkeyvault.SecretProperties{}}},
		},
	}
	p := newPlugin(f)
	for i := 0; i < 3; i++ {
		if _, err := p.Collect(context.Background(), req("kms_key", "secret")); err != nil {
			t.Fatalf("Collect #%d: %v", i, err)
		}
	}
	if f.vaultCalls != 3 || f.listKeyCalls != 3 || f.getKeyCalls != 3 || f.secretCalls != 3 {
		t.Errorf("call counts vault=%d listKey=%d getKey=%d secret=%d, want all 3",
			f.vaultCalls, f.listKeyCalls, f.getKeyCalls, f.secretCalls)
	}
}

func TestRotationEnabled(t *testing.T) {
	notify := &armkeyvault.Key{Properties: &armkeyvault.KeyProperties{RotationPolicy: &armkeyvault.RotationPolicy{
		LifetimeActions: []*armkeyvault.LifetimeAction{{
			Action:  &armkeyvault.Action{Type: to.Ptr(armkeyvault.KeyRotationPolicyActionTypeNotify)},
			Trigger: &armkeyvault.Trigger{TimeBeforeExpiry: to.Ptr("P30D")},
		}},
	}}}
	rotateNoTrigger := &armkeyvault.Key{Properties: &armkeyvault.KeyProperties{RotationPolicy: &armkeyvault.RotationPolicy{
		LifetimeActions: []*armkeyvault.LifetimeAction{{
			Action: &armkeyvault.Action{Type: to.Ptr(armkeyvault.KeyRotationPolicyActionTypeRotate)},
		}},
	}}}
	tests := []struct {
		name string
		key  *armkeyvault.Key
		want bool
	}{
		{"nil", nil, false},
		{"no properties", &armkeyvault.Key{}, false},
		{"no policy", &armkeyvault.Key{Properties: &armkeyvault.KeyProperties{}}, false},
		{"rotate with trigger", rotatingHSMKey("rg", "v", "k"), true},
		{"notify only", notify, false},
		{"rotate no trigger", rotateNoTrigger, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rotationEnabled(tc.key); got != tc.want {
				t.Errorf("rotationEnabled = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProtectionLevel(t *testing.T) {
	cases := map[string]string{"RSA": "SOFTWARE", "EC": "SOFTWARE", "RSA-HSM": "HSM", "EC-HSM": "HSM"}
	for kty, want := range cases {
		if got := protectionLevel(kty); got != want {
			t.Errorf("protectionLevel(%q) = %q, want %q", kty, got, want)
		}
	}
}

func TestNeverRotated(t *testing.T) {
	c := fixedNow.Add(-10 * 24 * time.Hour)
	later := fixedNow
	tests := []struct {
		name string
		attr *armkeyvault.SecretAttributes
		want bool
	}{
		{"nil", nil, true},
		{"no timestamps", &armkeyvault.SecretAttributes{}, true},
		{"created == updated", &armkeyvault.SecretAttributes{Created: &c, Updated: &c}, true},
		{"updated after created", &armkeyvault.SecretAttributes{Created: &c, Updated: &later}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := neverRotated(tc.attr); got != tc.want {
				t.Errorf("neverRotated = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLastRotatedDays(t *testing.T) {
	updated := fixedNow.Add(-7 * 24 * time.Hour)
	if got := lastRotatedDays(&armkeyvault.SecretAttributes{Updated: &updated}, fixedNow); got == nil || *got != 7 {
		t.Errorf("lastRotatedDays = %v, want 7", got)
	}
	if got := lastRotatedDays(&armkeyvault.SecretAttributes{}, fixedNow); got != nil {
		t.Errorf("lastRotatedDays with no Updated = %v, want nil", got)
	}
	// Future timestamp clamps to 0.
	future := fixedNow.Add(24 * time.Hour)
	if got := lastRotatedDays(&armkeyvault.SecretAttributes{Updated: &future}, fixedNow); got == nil || *got != 0 {
		t.Errorf("lastRotatedDays future = %v, want 0", got)
	}
}

func TestResourceGroupFromID(t *testing.T) {
	if rg, err := resourceGroupFromID(*vaultID("My-RG", "kv")); err != nil || rg != "My-RG" {
		t.Errorf("resourceGroupFromID = %q, %v", rg, err)
	}
	// Case-insensitive segment match.
	lower := "/subscriptions/s/resourcegroups/rg2/providers/Microsoft.KeyVault/vaults/kv"
	if rg, err := resourceGroupFromID(lower); err != nil || rg != "rg2" {
		t.Errorf("resourceGroupFromID lower = %q, %v", rg, err)
	}
	if _, err := resourceGroupFromID("/bad/id"); err == nil {
		t.Error("expected error for id without resourceGroups segment")
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

type route struct {
	pattern string
	body    []byte
}

// keyvaultRouter serves a body for the first path-substring match, in the given
// order — list URLs are nested under /vaults/{name}, so the "/vaults" route
// must come last (it would otherwise shadow the nested /keys and /secrets).
func keyvaultRouter(t *testing.T, routes []route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for _, rt := range routes {
			if strings.Contains(r.URL.Path, rt.pattern) {
				_, _ = w.Write(rt.body) //nolint:errcheck // test handler
				return
			}
		}
		t.Errorf("unexpected path: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func realKeyvaultPointedAt(t *testing.T, srv *httptest.Server) *realKeyvault {
	t.Helper()
	opts := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.azure.com"},
		}},
		Transport: srv.Client(),
	}}
	rk, err := newRealKeyvault(subID, fakeCred{}, opts)
	if err != nil {
		t.Fatalf("newRealKeyvault: %v", err)
	}
	return rk
}

func TestRealKeyvault_HappyPath(t *testing.T) {
	vaultsBody := mustMarshal(t, armkeyvault.VaultListResult{Value: []*armkeyvault.Vault{
		{ID: vaultID("rg1", "kv-a"), Name: to.Ptr("kv-a")},
	}})
	keysBody := mustMarshal(t, armkeyvault.KeyListResult{Value: []*armkeyvault.Key{
		{ID: keyID("rg1", "kv-a", "k1"), Name: to.Ptr("k1")},
	}})
	keyBody := mustMarshal(t, rotatingHSMKey("rg1", "kv-a", "k1"))
	secretsBody := mustMarshal(t, armkeyvault.SecretListResult{Value: []*armkeyvault.Secret{
		{ID: secretID("s1"), Name: to.Ptr("s1"), Properties: &armkeyvault.SecretProperties{}},
	}})

	srv := httptest.NewTLSServer(keyvaultRouter(t, []route{
		{"/keys/k1", keyBody}, // most specific first
		{"/keys", keysBody},
		{"/secrets", secretsBody},
		{"/vaults", vaultsBody}, // parent path — must be last
	}))
	defer srv.Close()

	rk := realKeyvaultPointedAt(t, srv)
	ctx := context.Background()
	t.Run("vaults", func(t *testing.T) {
		vaults, err := rk.ListVaults(ctx)
		if err != nil || len(vaults) != 1 || deref(vaults[0].Name) != "kv-a" {
			t.Fatalf("ListVaults = %+v, err %v", vaults, err)
		}
	})
	t.Run("keys", func(t *testing.T) {
		keys, err := rk.ListKeys(ctx, "rg1", "kv-a")
		if err != nil || len(keys) != 1 || deref(keys[0].Name) != "k1" {
			t.Fatalf("ListKeys = %+v, err %v", keys, err)
		}
	})
	t.Run("getKey", func(t *testing.T) {
		key, err := rk.GetKey(ctx, "rg1", "kv-a", "k1")
		if err != nil || key == nil || !rotationEnabled(key) {
			t.Fatalf("GetKey = %+v, err %v", key, err)
		}
	})
	t.Run("secrets", func(t *testing.T) {
		secrets, err := rk.ListSecrets(ctx, "rg1", "kv-a")
		if err != nil || len(secrets) != 1 || deref(secrets[0].Name) != "s1" {
			t.Fatalf("ListSecrets = %+v, err %v", secrets, err)
		}
	})
}

func TestRealKeyvault_ListError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	rk := realKeyvaultPointedAt(t, srv)
	if _, err := rk.ListVaults(context.Background()); err == nil {
		t.Fatal("expected error on 403, got nil")
	}
}
