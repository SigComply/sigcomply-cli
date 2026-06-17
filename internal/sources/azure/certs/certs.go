// Package certs implements the azure.certs source plugin: it lists Azure
// certificates in a subscription and emits one cross-vendor tls_certificate
// record per certificate, so the expiry and auto-renewal policies evaluate
// against Azure exactly as they do against AWS ACM and GCP Certificate Manager
// — zero policy changes (Invariant #4, substitutability).
//
// Two ARM management-plane reads, both subscription-wide, are merged into one
// record set:
//
//   - App Service certificates (armappservice CertificatesClient.NewListPager):
//     the TLS certificates uploaded to or Key-Vault-referenced by App Services.
//     These are imported (not provider-auto-renewed at this layer), so they
//     emit is_managed=false and OMIT auto_renew (matching aws.acm imported
//     certs, where the auto-renew policy guards on is_managed).
//   - App Service certificate orders (armcertificateregistration
//     AppServiceCertificateOrdersClient.NewListPager): provider-managed
//     certificates (App Service Certificates). These emit is_managed=true and a
//     real auto_renew (the order's AutoRenew flag) — this is what makes the
//     "managed certs must auto-renew" policy meaningful on Azure.
//
// Both surfaces are pure ARM management plane, readable with subscription-level
// Reader RBAC — consistent with every other azure.* plugin. Key Vault
// certificate objects are deliberately NOT collected here: their expiry and
// auto-renew (lifetime-action) policy live only on the data plane
// (azcertificates), which needs per-vault access policies / RBAC beyond Reader
// and an N+1 over vaults. That breaks the ARM-plane/Reader-only invariant
// azure.keyvault (WU-5.6) established; Key Vault cert auto-renewal evidence is
// covered via manual evidence — the honest-gap pattern azure.sql /
// azure.keyvault already use.
//
// Field mapping (the schema-required fields id, domain, status, not_after,
// days_until_expiry, is_managed are emitted unconditionally — per WU-0.2 the
// evaluator errors on a payload that omits a field a policy clause references;
// the shipped policies read days_until_expiry directly and auto_renew guarded by
// is_managed):
//
//   - not_after ← the certificate's expiry timestamp (App Service cert
//     ExpirationDate / order ExpirationTime), normalized to RFC3339 UTC.
//     days_until_expiry is derived from it at collect time, rounded toward zero
//     so an already-expired cert reads negative.
//   - is_managed ← false for App Service certs, true for certificate orders.
//     auto_renew is a pointer set to the order's real AutoRenew value for orders
//     (managed); OMITTED for App Service certs (imported — no renewal concept).
//   - status ← an honest enum: an expired cert is EXPIRED; otherwise an App
//     Service cert maps its Valid flag / Key Vault secret status, and an order
//     maps its CertificateOrderStatus.
//   - domain ← the App Service cert SubjectName (else first host name) / the
//     order's distinguished-name CN.
//
// A list failure (e.g. a missing-permission 403, or an unregistered
// Microsoft.CertificateRegistration provider) is surfaced as an error (tagging
// only the azure.certs-bound policies `error`) rather than returning a partial
// or fabricated result — never fabricate.
//
// Test injection: the API interface is the single seam and returns raw SDK types
// so 100% of the vendor→canonical mapping stays in Collect under fakeAPI unit
// tests; the real adapter (realCerts) wraps the two ARM clients.
package certs

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armappservice "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v6"
	armcertificateregistration "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/certificateregistration/armcertificateregistration"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "tls_certificate"

// SourceID is the registered ID for the azure.certs plugin instance.
const SourceID = "azure.certs"

// hoursPerDay converts an expiry duration to whole days.
const hoursPerDay = 24

// tls_certificate status enum values (see the evidence-type schema).
const (
	statusIssued            = "ISSUED"
	statusPendingValidation = "PENDING_VALIDATION"
	statusExpired           = "EXPIRED"
	statusInactive          = "INACTIVE"
	statusRevoked           = "REVOKED"
	statusFailed            = "FAILED"
)

// API is the subset of the Azure certificate management planes this plugin
// uses. It returns raw SDK types so the vendor→canonical mapping is exercised by
// fakeAPI unit tests; the real adapter (realCerts) wraps the SDK clients.
type API interface {
	// ListCertificates returns every App Service certificate in the
	// subscription (imported / Key-Vault-referenced TLS certs).
	ListCertificates(ctx context.Context) ([]*armappservice.AppCertificate, error)
	// ListCertificateOrders returns every App Service certificate order in the
	// subscription (provider-managed certificates).
	ListCertificateOrders(ctx context.Context) ([]*armcertificateregistration.AppServiceCertificateOrder, error)
}

// Plugin is the in-process azure.certs source.
type Plugin struct {
	api            API
	subscriptionID string
	now            func() time.Time
}

// Options is the constructor input.
type Options struct {
	API            API
	SubscriptionID string
	// Now is injected so tests can produce deterministic timestamps and expiry
	// math. Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation. Callers using
// the real Azure SDK should use NewFromAzure.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:            opts.API,
		subscriptionID: opts.SubscriptionID,
		now:            now,
	}
}

// NewFromAzure constructs a Plugin backed by the real armappservice and
// armcertificateregistration SDKs using the given credential (a
// DefaultAzureCredential) scoped to cfg.SubscriptionID.
func NewFromAzure(cred azcore.TokenCredential, cfg azcommon.Config) (*Plugin, error) {
	adapter, err := newRealCerts(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return New(Options{API: adapter, SubscriptionID: cfg.SubscriptionID}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// certPayload is the cross-vendor tls_certificate shape (see
// internal/evidence_types/schemas/tls_certificate.v1.json) with Azure enrichment
// fields in the additionalProperties tail. The required fields are always
// emitted. auto_renew is a pointer so it is omitted (not false) for App Service
// (imported) certs, which have no renewal concept.
type certPayload struct {
	ID              string `json:"id"`
	Domain          string `json:"domain"`
	Provider        string `json:"provider"`
	Status          string `json:"status"`
	NotAfter        string `json:"not_after"`
	DaysUntilExpiry int    `json:"days_until_expiry"`
	IsManaged       bool   `json:"is_managed"`
	AutoRenew       *bool  `json:"auto_renew,omitempty"`

	// Auditable Azure extras (additionalProperties).
	Name                 string   `json:"name,omitempty"`
	Location             string   `json:"location,omitempty"`
	ResourceGroup        string   `json:"resource_group,omitempty"`
	Issuer               string   `json:"issuer,omitempty"`
	Thumbprint           string   `json:"thumbprint,omitempty"`
	HostNames            []string `json:"host_names,omitempty"`
	KeyVaultID           string   `json:"key_vault_id,omitempty"`
	KeyVaultSecretStatus string   `json:"key_vault_secret_status,omitempty"`
	ProductType          string   `json:"product_type,omitempty"`
	ProvisioningState    string   `json:"provisioning_state,omitempty"`
	SerialNumber         string   `json:"serial_number,omitempty"`
}

// Collect lists App Service certificates and certificate orders in the
// subscription and emits one tls_certificate record per certificate, sorted by
// ID (ARM resource id) so envelope bytes are stable across runs against stable
// state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("azure.certs: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	appCerts, err := p.api.ListCertificates(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.certs: list certificates: %w", err)
	}
	orders, err := p.api.ListCertificateOrders(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.certs: list certificate orders: %w", err)
	}
	var scope *core.RecordScope
	if p.subscriptionID != "" {
		scope = &core.RecordScope{Account: p.subscriptionID}
	}
	now := p.now()

	records := make([]core.EvidenceRecord, 0, len(appCerts)+len(orders))
	appendRecord := func(payload certPayload) error {
		body, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("azure.certs: marshal payload for %q: %w", payload.ID, err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          payload.ID,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
			Scope:       scope,
		})
		return nil
	}

	for _, c := range appCerts {
		if c == nil {
			continue
		}
		if err := appendRecord(buildCertPayload(c, now)); err != nil {
			return nil, err
		}
	}
	for _, o := range orders {
		if o == nil {
			continue
		}
		if err := appendRecord(buildOrderPayload(o, now)); err != nil {
			return nil, err
		}
	}

	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// buildCertPayload maps one App Service certificate (imported / Key-Vault-
// referenced) into the cross-vendor tls_certificate shape. These are not
// provider-managed at this layer: is_managed=false and auto_renew is omitted.
func buildCertPayload(c *armappservice.AppCertificate, now time.Time) certPayload {
	props := c.Properties
	var notAfter string
	var days int
	var expired bool
	if props != nil {
		notAfter, days, expired = expiry(props.ExpirationDate, now)
	}
	p := certPayload{
		ID:              deref(c.ID),
		Domain:          appCertDomain(props),
		Provider:        "azure",
		Status:          appCertStatus(props, expired),
		NotAfter:        notAfter,
		DaysUntilExpiry: days,
		IsManaged:       false,

		Name:          deref(c.Name),
		Location:      deref(c.Location),
		ResourceGroup: resourceGroupOrEmpty(deref(c.ID)),
	}
	if props != nil {
		p.Issuer = deref(props.Issuer)
		p.Thumbprint = deref(props.Thumbprint)
		p.HostNames = hostNames(props.HostNames)
		p.KeyVaultID = deref(props.KeyVaultID)
		p.KeyVaultSecretStatus = keyVaultSecretStatus(props)
	}
	return p
}

// buildOrderPayload maps one App Service certificate order (provider-managed)
// into the cross-vendor tls_certificate shape: is_managed=true and a real
// auto_renew from the order's AutoRenew flag.
func buildOrderPayload(o *armcertificateregistration.AppServiceCertificateOrder, now time.Time) certPayload {
	props := o.Properties
	var notAfter string
	var days int
	var expired bool
	if props != nil {
		notAfter, days, expired = expiry(props.ExpirationTime, now)
	}
	// auto_renew is always present for managed certs (the policy guards on
	// is_managed and reads auto_renew directly); a nil order AutoRenew → false.
	autoRenew := derefBool(orderAutoRenew(props))
	p := certPayload{
		ID:              deref(o.ID),
		Domain:          orderDomain(props),
		Provider:        "azure",
		Status:          orderStatus(props, expired),
		NotAfter:        notAfter,
		DaysUntilExpiry: days,
		IsManaged:       true,
		AutoRenew:       &autoRenew,

		Name:          deref(o.Name),
		Location:      deref(o.Location),
		ResourceGroup: resourceGroupOrEmpty(deref(o.ID)),
	}
	if props != nil {
		p.ProductType = productType(props)
		p.ProvisioningState = provisioningState(props)
		p.SerialNumber = deref(props.SerialNumber)
	}
	return p
}

// --- pure mapping helpers (unit-tested via table tests) ---

// expiry normalizes the certificate's expiry timestamp to RFC3339 UTC and
// returns the whole days remaining (rounded toward zero; negative once expired)
// and whether it has already expired. A nil timestamp yields zero values.
func expiry(t *time.Time, now time.Time) (notAfter string, days int, expired bool) {
	if t == nil {
		return "", 0, false
	}
	u := t.UTC()
	days = int(math.Trunc(u.Sub(now).Hours() / hoursPerDay))
	return u.Format(time.RFC3339), days, u.Before(now)
}

// appCertDomain returns the App Service certificate's subject name, falling back
// to the first host name.
func appCertDomain(props *armappservice.AppCertificateProperties) string {
	if props == nil {
		return ""
	}
	if s := deref(props.SubjectName); s != "" {
		return s
	}
	if len(props.HostNames) > 0 {
		return deref(props.HostNames[0])
	}
	return ""
}

// appCertStatus maps an App Service certificate to the tls_certificate status
// enum. Expiry takes precedence; a valid cert is ISSUED; otherwise the Key Vault
// secret status (for KV-backed certs) distinguishes pending vs failed.
func appCertStatus(props *armappservice.AppCertificateProperties, expired bool) string {
	if expired {
		return statusExpired
	}
	if props == nil {
		return statusInactive
	}
	if derefBool(props.Valid) {
		return statusIssued
	}
	switch keyVaultSecretStatus(props) {
	case string(armappservice.KeyVaultSecretStatusWaitingOnCertificateOrder):
		return statusPendingValidation
	case string(armappservice.KeyVaultSecretStatusCertificateOrderFailed),
		string(armappservice.KeyVaultSecretStatusOperationNotPermittedOnKeyVault),
		string(armappservice.KeyVaultSecretStatusAzureServiceUnauthorizedToAccessKeyVault),
		string(armappservice.KeyVaultSecretStatusKeyVaultDoesNotExist),
		string(armappservice.KeyVaultSecretStatusKeyVaultSecretDoesNotExist),
		string(armappservice.KeyVaultSecretStatusUnknownError):
		return statusFailed
	}
	return statusInactive
}

// orderStatus maps an App Service certificate order to the tls_certificate
// status enum. Expiry takes precedence over the order's lifecycle status.
func orderStatus(props *armcertificateregistration.AppServiceCertificateOrderProperties, expired bool) string {
	if expired {
		return statusExpired
	}
	if props == nil || props.Status == nil {
		return statusInactive
	}
	switch *props.Status {
	case armcertificateregistration.CertificateOrderStatusIssued:
		return statusIssued
	case armcertificateregistration.CertificateOrderStatusPendingissuance,
		armcertificateregistration.CertificateOrderStatusPendingRekey,
		armcertificateregistration.CertificateOrderStatusPendingrevocation:
		return statusPendingValidation
	case armcertificateregistration.CertificateOrderStatusExpired:
		return statusExpired
	case armcertificateregistration.CertificateOrderStatusRevoked:
		return statusRevoked
	default: // Canceled, Denied, NotSubmitted, Unused
		return statusInactive
	}
}

// orderDomain returns the certificate order's distinguished-name common name.
func orderDomain(props *armcertificateregistration.AppServiceCertificateOrderProperties) string {
	if props == nil {
		return ""
	}
	return cnFromDN(deref(props.DistinguishedName))
}

// cnFromDN extracts the common name (CN=) from an X.509 distinguished name like
// "CN=example.com, O=Contoso", returning the whole string when no CN is present.
func cnFromDN(dn string) string {
	const marker = "CN="
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if len(part) >= len(marker) && strings.EqualFold(part[:len(marker)], marker) {
			return part[len(marker):]
		}
	}
	return dn
}

func orderAutoRenew(props *armcertificateregistration.AppServiceCertificateOrderProperties) *bool {
	if props == nil {
		return nil
	}
	return props.AutoRenew
}

func productType(props *armcertificateregistration.AppServiceCertificateOrderProperties) string {
	if props == nil || props.ProductType == nil {
		return ""
	}
	return string(*props.ProductType)
}

func provisioningState(props *armcertificateregistration.AppServiceCertificateOrderProperties) string {
	if props == nil || props.ProvisioningState == nil {
		return ""
	}
	return string(*props.ProvisioningState)
}

func keyVaultSecretStatus(props *armappservice.AppCertificateProperties) string {
	if props == nil || props.KeyVaultSecretStatus == nil {
		return ""
	}
	return string(*props.KeyVaultSecretStatus)
}

func hostNames(in []*string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, h := range in {
		out = append(out, deref(h))
	}
	return out
}

// resourceGroupFromID extracts the resource group from an ARM resource id,
// case-insensitively (ARM sometimes returns "resourcegroups").
func resourceGroupFromID(id string) (string, error) {
	parts := strings.Split(id, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			if rg := parts[i+1]; rg != "" {
				return rg, nil
			}
		}
	}
	return "", fmt.Errorf("no resourceGroups segment in id %q", id)
}

// resourceGroupOrEmpty is resourceGroupFromID for payload context, returning ""
// (rather than an error) for a malformed id since the field is informational.
func resourceGroupOrEmpty(id string) string {
	rg, err := resourceGroupFromID(id)
	if err != nil {
		return ""
	}
	return rg
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefBool(b *bool) bool {
	return b != nil && *b
}

// --- real Azure adapter ---

// realCerts is the production implementation of API. It wraps the two ARM
// management-plane clients, both listed subscription-wide.
type realCerts struct {
	certs  *armappservice.CertificatesClient
	orders *armcertificateregistration.AppServiceCertificateOrdersClient
}

// newRealCerts builds the SDK clients. opts is nil in production; tests pass a
// *arm.ClientOptions pointing the clients at an httptest server.
func newRealCerts(subscriptionID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*realCerts, error) {
	certsClient, err := armappservice.NewCertificatesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.certs: certificates client: %w", err)
	}
	ordersClient, err := armcertificateregistration.NewAppServiceCertificateOrdersClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.certs: certificate orders client: %w", err)
	}
	return &realCerts{certs: certsClient, orders: ordersClient}, nil
}

func (r *realCerts) ListCertificates(ctx context.Context) ([]*armappservice.AppCertificate, error) {
	var out []*armappservice.AppCertificate
	pager := r.certs.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (r *realCerts) ListCertificateOrders(ctx context.Context) ([]*armcertificateregistration.AppServiceCertificateOrder, error) {
	var out []*armcertificateregistration.AppServiceCertificateOrder
	pager := r.orders.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
