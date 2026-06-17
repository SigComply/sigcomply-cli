package certs

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
	armappservice "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v6"
	armcertificateregistration "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/certificateregistration/armcertificateregistration"

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

// fakeAPI records calls and returns staged certificates / orders.
type fakeAPI struct {
	certs     []*armappservice.AppCertificate
	orders    []*armcertificateregistration.AppServiceCertificateOrder
	certErr   error
	orderErr  error
	certCalls int
	ordCalls  int
}

func (f *fakeAPI) ListCertificates(context.Context) ([]*armappservice.AppCertificate, error) {
	f.certCalls++
	if f.certErr != nil {
		return nil, f.certErr
	}
	return f.certs, nil
}

func (f *fakeAPI) ListCertificateOrders(context.Context) ([]*armcertificateregistration.AppServiceCertificateOrder, error) {
	f.ordCalls++
	if f.orderErr != nil {
		return nil, f.orderErr
	}
	return f.orders, nil
}

func req() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}
}

func certID(name string) *string {
	return to.Ptr("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/certificates/" + name)
}

func orderID(name string) *string {
	return to.Ptr("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.CertificateRegistration/certificateOrders/" + name)
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{})
	if got := p.ID(); got != "azure.certs" {
		t.Errorf("ID() = %q, want azure.certs", got)
	}
	got := p.Emits()
	if len(got) != 1 || got[0] != EvidenceTypeID {
		t.Errorf("Emits() = %v, want [tls_certificate]", got)
	}
}

func TestCollect_RejectsNonEmittedType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "tls_certificate") {
		t.Fatalf("expected rejection error, got %v", err)
	}
}

func TestCollect_MapsSortsAndFullPayload(t *testing.T) {
	// One imported App Service cert (valid, KV-backed) and one managed cert
	// order (auto-renewing, issued). The order's ARM id sorts before the cert's
	// (CertificateRegistration < Web), proving cross-source sort.
	expCert := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)  // ~90 days out
	expOrder := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC) // ~167 days out
	f := &fakeAPI{
		certs: []*armappservice.AppCertificate{
			{
				ID:       certID("web-cert"),
				Name:     to.Ptr("web-cert"),
				Location: to.Ptr("eastus"),
				Properties: &armappservice.AppCertificateProperties{
					ExpirationDate:       to.Ptr(expCert),
					SubjectName:          to.Ptr("app.example.com"),
					HostNames:            []*string{to.Ptr("app.example.com"), to.Ptr("www.example.com")},
					Issuer:               to.Ptr("DigiCert"),
					Thumbprint:           to.Ptr("ABC123"),
					Valid:                to.Ptr(true),
					KeyVaultID:           to.Ptr("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v"),
					KeyVaultSecretStatus: to.Ptr(armappservice.KeyVaultSecretStatusSucceeded),
				},
			},
		},
		orders: []*armcertificateregistration.AppServiceCertificateOrder{
			{
				ID:       orderID("managed-order"),
				Name:     to.Ptr("managed-order"),
				Location: to.Ptr("global"),
				Properties: &armcertificateregistration.AppServiceCertificateOrderProperties{
					ExpirationTime:    to.Ptr(expOrder),
					AutoRenew:         to.Ptr(true),
					DistinguishedName: to.Ptr("CN=managed.example.com, O=Contoso"),
					Status:            to.Ptr(armcertificateregistration.CertificateOrderStatusIssued),
					ProductType:       to.Ptr(armcertificateregistration.CertificateProductTypeStandardDomainValidatedSSL),
					ProvisioningState: to.Ptr(armcertificateregistration.ProvisioningStateSucceeded),
					SerialNumber:      to.Ptr("SN-9"),
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
	// Sorted by ARM id: CertificateRegistration (order) before Web (cert).
	if recs[0].ID != *orderID("managed-order") || recs[1].ID != *certID("web-cert") {
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

	var order certPayload
	mustUnmarshal(t, recs[0].Payload, &order)
	wantOrder := certPayload{
		ID:                *orderID("managed-order"),
		Domain:            "managed.example.com",
		Provider:          "azure",
		Status:            statusIssued,
		NotAfter:          "2026-12-01T00:00:00Z",
		DaysUntilExpiry:   166,
		IsManaged:         true,
		AutoRenew:         to.Ptr(true),
		Name:              "managed-order",
		Location:          "global",
		ResourceGroup:     "rg",
		ProductType:       "StandardDomainValidatedSsl",
		ProvisioningState: "Succeeded",
		SerialNumber:      "SN-9",
	}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Errorf("order payload mismatch:\n got  %+v\n want %+v", order, wantOrder)
	}

	var cert certPayload
	mustUnmarshal(t, recs[1].Payload, &cert)
	wantCert := certPayload{
		ID:                   *certID("web-cert"),
		Domain:               "app.example.com",
		Provider:             "azure",
		Status:               statusIssued,
		NotAfter:             "2026-09-15T00:00:00Z",
		DaysUntilExpiry:      89,
		IsManaged:            false,
		AutoRenew:            nil, // omitted for imported certs
		Name:                 "web-cert",
		Location:             "eastus",
		ResourceGroup:        "rg",
		Issuer:               "DigiCert",
		Thumbprint:           "ABC123",
		HostNames:            []string{"app.example.com", "www.example.com"},
		KeyVaultID:           "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v",
		KeyVaultSecretStatus: "Succeeded",
	}
	if !reflect.DeepEqual(cert, wantCert) {
		t.Errorf("cert payload mismatch:\n got  %+v\n want %+v", cert, wantCert)
	}
}

// TestCollect_ManagedOrderAutoRenewFalse proves auto_renew is emitted (not
// omitted) for a managed order whose AutoRenew is false — the field is
// load-bearing for the "managed certs must auto-renew" policy.
func TestCollect_ManagedOrderAutoRenewFalse(t *testing.T) {
	f := &fakeAPI{orders: []*armcertificateregistration.AppServiceCertificateOrder{
		{
			ID:   orderID("no-renew"),
			Name: to.Ptr("no-renew"),
			Properties: &armcertificateregistration.AppServiceCertificateOrderProperties{
				AutoRenew:         to.Ptr(false),
				DistinguishedName: to.Ptr("CN=no-renew.example.com"),
				Status:            to.Ptr(armcertificateregistration.CertificateOrderStatusIssued),
			},
		},
	}}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got certPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if !got.IsManaged {
		t.Error("order should be is_managed=true")
	}
	if got.AutoRenew == nil {
		t.Fatal("managed order must emit auto_renew, got omitted")
	}
	if *got.AutoRenew {
		t.Error("auto_renew should be false")
	}
}

// TestCollect_BarePropertiesStillRequiredFields proves the schema-required
// fields are emitted even for certs/orders with nil Properties.
func TestCollect_BarePropertiesStillRequiredFields(t *testing.T) {
	f := &fakeAPI{
		certs:  []*armappservice.AppCertificate{{ID: certID("bare-cert"), Name: to.Ptr("bare-cert")}},
		orders: []*armcertificateregistration.AppServiceCertificateOrder{{ID: orderID("bare-order"), Name: to.Ptr("bare-order")}},
	}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	for _, r := range recs {
		var got certPayload
		mustUnmarshal(t, r.Payload, &got)
		if got.Status != statusInactive {
			t.Errorf("%s: bare cert status = %q, want INACTIVE", r.ID, got.Status)
		}
		if got.NotAfter != "" || got.DaysUntilExpiry != 0 {
			t.Errorf("%s: bare cert expiry = %q/%d, want empty/0", r.ID, got.NotAfter, got.DaysUntilExpiry)
		}
	}
}

// TestCollect_ExpiredOverridesStatus proves expiry takes precedence over the
// lifecycle status for both surfaces, and days_until_expiry reads negative.
func TestCollect_ExpiredOverridesStatus(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f := &fakeAPI{
		certs: []*armappservice.AppCertificate{{
			ID:   certID("old"),
			Name: to.Ptr("old"),
			Properties: &armappservice.AppCertificateProperties{
				ExpirationDate: to.Ptr(past),
				Valid:          to.Ptr(true), // valid but expired → EXPIRED wins
			},
		}},
		orders: []*armcertificateregistration.AppServiceCertificateOrder{{
			ID:   orderID("old"),
			Name: to.Ptr("old"),
			Properties: &armcertificateregistration.AppServiceCertificateOrderProperties{
				ExpirationTime: to.Ptr(past),
				Status:         to.Ptr(armcertificateregistration.CertificateOrderStatusIssued),
			},
		}},
	}
	recs, err := New(Options{API: f, Now: func() time.Time { return fixedNow }}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range recs {
		var got certPayload
		mustUnmarshal(t, r.Payload, &got)
		if got.Status != statusExpired {
			t.Errorf("%s: status = %q, want EXPIRED", r.ID, got.Status)
		}
		if got.DaysUntilExpiry >= 0 {
			t.Errorf("%s: days_until_expiry = %d, want negative", r.ID, got.DaysUntilExpiry)
		}
	}
}

func TestCollect_NilEntriesSkipped(t *testing.T) {
	f := &fakeAPI{
		certs:  []*armappservice.AppCertificate{nil, {ID: certID("ok"), Name: to.Ptr("ok")}},
		orders: []*armcertificateregistration.AppServiceCertificateOrder{nil, {ID: orderID("ok"), Name: to.Ptr("ok")}},
	}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 records (nil entries skipped), got %d", len(recs))
	}
}

func TestCollect_ErrorPropagation(t *testing.T) {
	t.Run("certs", func(t *testing.T) {
		_, err := New(Options{API: &fakeAPI{certErr: errors.New("cert boom")}}).Collect(context.Background(), req())
		if err == nil || !strings.Contains(err.Error(), "cert boom") {
			t.Fatalf("cert list error should surface, got %v", err)
		}
	})
	t.Run("orders", func(t *testing.T) {
		_, err := New(Options{API: &fakeAPI{orderErr: errors.New("order boom")}}).Collect(context.Background(), req())
		if err == nil || !strings.Contains(err.Error(), "order boom") {
			t.Fatalf("order list error should surface, got %v", err)
		}
	})
}

// TestCollect_MalformedID_ResourceGroupEmpty proves a malformed ARM id yields an
// empty resource_group extra (informational) rather than an error.
func TestCollect_MalformedID_ResourceGroupEmpty(t *testing.T) {
	f := &fakeAPI{certs: []*armappservice.AppCertificate{
		{ID: to.Ptr("/subscriptions/s/providers/Microsoft.Web/certificates/odd"), Name: to.Ptr("odd")},
	}}
	recs, err := New(Options{API: f}).Collect(context.Background(), req())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var got certPayload
	mustUnmarshal(t, recs[0].Payload, &got)
	if got.ResourceGroup != "" {
		t.Errorf("malformed id should yield empty resource_group, got %q", got.ResourceGroup)
	}
}

func TestCollect_KISSNoDRY_RefetchesEachCollect(t *testing.T) {
	f := &fakeAPI{
		certs:  []*armappservice.AppCertificate{{ID: certID("c"), Name: to.Ptr("c")}},
		orders: []*armcertificateregistration.AppServiceCertificateOrder{{ID: orderID("o"), Name: to.Ptr("o")}},
	}
	p := New(Options{API: f})
	for i := 0; i < 3; i++ {
		if _, err := p.Collect(context.Background(), req()); err != nil {
			t.Fatalf("Collect %d: %v", i, err)
		}
	}
	if f.certCalls != 3 || f.ordCalls != 3 {
		t.Errorf("expected 3 list calls each, got certs=%d orders=%d", f.certCalls, f.ordCalls)
	}
}

func TestExpiry_Table(t *testing.T) {
	cases := []struct {
		name        string
		t           *time.Time
		wantAfter   string
		wantDays    int
		wantExpired bool
	}{
		{"nil", nil, "", 0, false},
		{"future", to.Ptr(time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)), "2026-07-17T12:00:00Z", 30, false},
		{"past", to.Ptr(time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)), "2026-06-07T12:00:00Z", -10, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotAfter, gotDays, gotExpired := expiry(c.t, fixedNow)
			if gotAfter != c.wantAfter || gotDays != c.wantDays || gotExpired != c.wantExpired {
				t.Errorf("expiry = (%q,%d,%v), want (%q,%d,%v)", gotAfter, gotDays, gotExpired, c.wantAfter, c.wantDays, c.wantExpired)
			}
		})
	}
}

func TestAppCertStatus_Table(t *testing.T) {
	mk := func(valid *bool, kvs *armappservice.KeyVaultSecretStatus) *armappservice.AppCertificateProperties {
		return &armappservice.AppCertificateProperties{Valid: valid, KeyVaultSecretStatus: kvs}
	}
	cases := []struct {
		name    string
		props   *armappservice.AppCertificateProperties
		expired bool
		want    string
	}{
		{"expired", mk(to.Ptr(true), nil), true, statusExpired},
		{"nil-props", nil, false, statusInactive},
		{"valid", mk(to.Ptr(true), nil), false, statusIssued},
		{"waiting", mk(to.Ptr(false), to.Ptr(armappservice.KeyVaultSecretStatusWaitingOnCertificateOrder)), false, statusPendingValidation},
		{"kv-failed", mk(to.Ptr(false), to.Ptr(armappservice.KeyVaultSecretStatusCertificateOrderFailed)), false, statusFailed},
		{"kv-unauthorized", mk(nil, to.Ptr(armappservice.KeyVaultSecretStatusAzureServiceUnauthorizedToAccessKeyVault)), false, statusFailed},
		{"unknown-status", mk(to.Ptr(false), to.Ptr(armappservice.KeyVaultSecretStatusSucceeded)), false, statusInactive},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := appCertStatus(c.props, c.expired); got != c.want {
				t.Errorf("appCertStatus = %q, want %q", got, c.want)
			}
		})
	}
}

func TestOrderStatus_Table(t *testing.T) {
	mk := func(s armcertificateregistration.CertificateOrderStatus) *armcertificateregistration.AppServiceCertificateOrderProperties {
		return &armcertificateregistration.AppServiceCertificateOrderProperties{Status: to.Ptr(s)}
	}
	cases := []struct {
		name    string
		props   *armcertificateregistration.AppServiceCertificateOrderProperties
		expired bool
		want    string
	}{
		{"expired-flag", mk(armcertificateregistration.CertificateOrderStatusIssued), true, statusExpired},
		{"nil-props", nil, false, statusInactive},
		{"nil-status", &armcertificateregistration.AppServiceCertificateOrderProperties{}, false, statusInactive},
		{"issued", mk(armcertificateregistration.CertificateOrderStatusIssued), false, statusIssued},
		{"pending", mk(armcertificateregistration.CertificateOrderStatusPendingissuance), false, statusPendingValidation},
		{"rekey", mk(armcertificateregistration.CertificateOrderStatusPendingRekey), false, statusPendingValidation},
		{"expired-status", mk(armcertificateregistration.CertificateOrderStatusExpired), false, statusExpired},
		{"revoked", mk(armcertificateregistration.CertificateOrderStatusRevoked), false, statusRevoked},
		{"canceled", mk(armcertificateregistration.CertificateOrderStatusCanceled), false, statusInactive},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := orderStatus(c.props, c.expired); got != c.want {
				t.Errorf("orderStatus = %q, want %q", got, c.want)
			}
		})
	}
}

func TestCNFromDN_Table(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"CN=example.com", "example.com"},
		{"CN=example.com, O=Contoso, C=US", "example.com"},
		{"cn=lower.example.com", "lower.example.com"},
		{"O=Contoso, CN=mid.example.com", "mid.example.com"},
		{"no-cn-here", "no-cn-here"},
		{"", ""},
	}
	for _, c := range cases {
		if got := cnFromDN(c.in); got != c.want {
			t.Errorf("cnFromDN(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResourceGroupFromID_Table(t *testing.T) {
	cases := []struct {
		id      string
		want    string
		wantErr bool
	}{
		{"/subscriptions/s/resourceGroups/my-rg/providers/Microsoft.Web/certificates/a", "my-rg", false},
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

func realCertsPointedAt(t *testing.T, srv *httptest.Server) *realCerts {
	t.Helper()
	opts := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.azure.com"},
		}},
		Transport: srv.Client(),
	}}
	rc, err := newRealCerts("sub-1", fakeCred{}, opts)
	if err != nil {
		t.Fatalf("newRealCerts: %v", err)
	}
	return rc
}

func TestRealCerts_ListCertificates_HappyPath(t *testing.T) {
	body := mustMarshal(t, armappservice.AppCertificateCollection{Value: []*armappservice.AppCertificate{
		{Name: to.Ptr("c1"), ID: certID("c1"), Properties: &armappservice.AppCertificateProperties{
			SubjectName: to.Ptr("c1.example.com"),
		}},
	}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// /certificateOrders must be matched before /certificates (substring).
		if strings.Contains(r.URL.Path, "/certificateOrders") {
			_, _ = w.Write([]byte(`{"value":[]}`)) //nolint:errcheck // test handler
			return
		}
		if strings.Contains(r.URL.Path, "/certificates") {
			_, _ = w.Write(body) //nolint:errcheck // test handler
			return
		}
		t.Errorf("unexpected path: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rc := realCertsPointedAt(t, srv)
	certs, err := rc.ListCertificates(context.Background())
	if err != nil || len(certs) != 1 || deref(certs[0].Name) != "c1" {
		t.Fatalf("ListCertificates = %+v, err %v", certs, err)
	}
}

func TestRealCerts_ListCertificateOrders_HappyPath(t *testing.T) {
	body := mustMarshal(t, armcertificateregistration.AppServiceCertificateOrderCollection{Value: []*armcertificateregistration.AppServiceCertificateOrder{
		{Name: to.Ptr("o1"), ID: orderID("o1"), Properties: &armcertificateregistration.AppServiceCertificateOrderProperties{
			AutoRenew: to.Ptr(true),
			Status:    to.Ptr(armcertificateregistration.CertificateOrderStatusIssued),
		}},
	}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/certificateOrders") {
			_, _ = w.Write(body) //nolint:errcheck // test handler
			return
		}
		t.Errorf("unexpected path: %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	rc := realCertsPointedAt(t, srv)
	orders, err := rc.ListCertificateOrders(context.Background())
	if err != nil || len(orders) != 1 || deref(orders[0].Name) != "o1" {
		t.Fatalf("ListCertificateOrders = %+v, err %v", orders, err)
	}
	if !derefBool(orders[0].Properties.AutoRenew) {
		t.Errorf("expected auto-renewing order to round-trip, got %+v", orders[0])
	}
}

func TestRealCerts_ListError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed"}}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	rc := realCertsPointedAt(t, srv)
	if _, err := rc.ListCertificates(context.Background()); err == nil {
		t.Fatal("expected error on 403 from certificates list, got nil")
	}
	if _, err := rc.ListCertificateOrders(context.Background()); err == nil {
		t.Fatal("expected error on 403 from orders list, got nil")
	}
}
