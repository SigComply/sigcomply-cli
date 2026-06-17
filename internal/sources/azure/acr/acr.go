// Package acr implements the azure.acr source plugin: it lists Azure Container
// Registries in a subscription and emits one cross-vendor container_registry
// record per registry, so scan-on-push, public-exposure, and encryption
// policies evaluate against Azure exactly as they do against AWS ECR and GCP
// Artifact Registry — zero policy changes (Invariant #4).
//
// Field mapping (the schema-required fields id, name, scan_on_push_enabled,
// is_public, encryption_enabled are always present; the policies read
// scan_on_push_enabled and is_public via plain leaf clauses, so they must never
// be absent):
//
//   - is_public — from AnonymousPullEnabled. A registry is "publicly accessible"
//     in the schema's sense when anyone can pull images WITHOUT credentials, which
//     in ACR is exactly anonymous-pull. PublicNetworkAccess=Enabled (the default)
//     only means the endpoint is reachable from the internet but still requires
//     Azure AD / token auth — mapping THAT to is_public would false-fail nearly
//     every Azure registry (the over-flagging trap). The raw PublicNetworkAccess
//     posture rides in the public_network_access extra so it stays auditable.
//   - scan_on_push_enabled — from the quarantine policy. ACR exposes no
//     "scanningEnabled" property: image vulnerability scanning is Microsoft
//     Defender for Containers, a subscription-level capability (collected by
//     azure.defender's threat_detection_service), NOT a per-registry toggle. The
//     one per-registry signal that genuinely gates pulls on scanning is the
//     quarantine policy (pushed images are unpullable until an external scanner
//     marks them healthy), so scan_on_push_enabled is true iff that policy is
//     enabled, else false. Registries relying on Defender-for-Containers instead
//     cover the scan-on-push controls via a .sigcomply.yaml exception or manual
//     evidence — the honest-gap pattern used by azure.keyvault (secret rotation)
//     and azure.sql (deletion protection).
//   - encryption_enabled — a platform CONSTANT true. ACR always encrypts images
//     at rest (Microsoft-managed keys by default, cannot be disabled); the only
//     real toggle is platform-managed vs customer-managed keys, which rides in
//     the auditable cmek_enabled / kms_key_id / encryption_status extras (mirrors
//     azure.storage and azure.compute always-on encryption).
//
// A list failure (e.g. a missing-permission 403) is surfaced as an error
// (tagging only the azure.acr-bound policies `error`) rather than returning a
// partial or insecure-default result — never fabricate.
//
// Test injection: the API interface is the single seam and returns raw SDK types
// so 100% of the vendor→canonical mapping stays in Collect under fakeAPI unit
// tests; the real adapter (realACR) wraps the armcontainerregistry registries
// client. Collection is a single subscription-wide list call — there is no N+1
// (no per-registry property needs a follow-up GET).
package acr

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armcontainerregistry "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry/v3"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// EvidenceTypeID is the single evidence type this plugin emits.
const EvidenceTypeID = "container_registry"

// SourceID is the registered ID for the azure.acr plugin instance.
const SourceID = "azure.acr"

// API is the subset of the Azure container registry management plane this plugin
// uses. It returns raw SDK types so the vendor→canonical mapping is exercised by
// fakeAPI unit tests; the real adapter (realACR) wraps the SDK client.
type API interface {
	// ListRegistries returns every container registry in the subscription.
	ListRegistries(ctx context.Context) ([]*armcontainerregistry.Registry, error)
}

// Plugin is the in-process azure.acr source.
type Plugin struct {
	api            API
	subscriptionID string
	now            func() time.Time
}

// Options is the constructor input.
type Options struct {
	API            API
	SubscriptionID string
	// Now is injected so tests can produce deterministic CollectedAt values.
	// Production callers leave it nil → time.Now().UTC().
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

// NewFromAzure constructs a Plugin backed by the real armcontainerregistry SDK
// using the given credential (a DefaultAzureCredential) scoped to
// cfg.SubscriptionID.
func NewFromAzure(cred azcore.TokenCredential, cfg azcommon.Config) (*Plugin, error) {
	adapter, err := newRealACR(cfg.SubscriptionID, cred, nil)
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

// registryPayload is the cross-vendor container_registry shape with Azure
// enrichment fields in the additionalProperties tail. The schema-required fields
// (id, name, scan_on_push_enabled, is_public, encryption_enabled) are always
// present.
type registryPayload struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Provider          string `json:"provider"`
	Region            string `json:"region,omitempty"`
	ScanOnPushEnabled bool   `json:"scan_on_push_enabled"`
	IsPublic          bool   `json:"is_public"`
	EncryptionEnabled bool   `json:"encryption_enabled"`

	// Auditable Azure extras (additionalProperties).
	SKU                    string `json:"sku,omitempty"`
	LoginServer            string `json:"login_server,omitempty"`
	PublicNetworkAccess    string `json:"public_network_access,omitempty"`
	AnonymousPullEnabled   bool   `json:"anonymous_pull_enabled"`
	AdminUserEnabled       bool   `json:"admin_user_enabled"`
	CMEKEnabled            bool   `json:"cmek_enabled"`
	KMSKeyID               string `json:"kms_key_id,omitempty"`
	EncryptionStatus       string `json:"encryption_status,omitempty"`
	ZoneRedundancy         string `json:"zone_redundancy,omitempty"`
	QuarantinePolicyStatus string `json:"quarantine_policy_status,omitempty"`
	ResourceGroup          string `json:"resource_group,omitempty"`
}

// Collect lists registries in the subscription and emits one container_registry
// record per registry, sorted by ID (ARM resource id) so envelope bytes are
// stable across runs against stable state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("azure.acr: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	registries, err := p.api.ListRegistries(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.acr: list registries: %w", err)
	}
	var scope *core.RecordScope
	if p.subscriptionID != "" {
		scope = &core.RecordScope{Account: p.subscriptionID}
	}
	now := p.now()

	records := make([]core.EvidenceRecord, 0, len(registries))
	for _, reg := range registries {
		if reg == nil {
			continue
		}
		keyID := cmekKeyID(reg)
		payload := registryPayload{
			ID:                deref(reg.ID),
			Name:              deref(reg.Name),
			Provider:          "azure",
			Region:            deref(reg.Location),
			ScanOnPushEnabled: quarantineEnabled(reg),
			IsPublic:          anonymousPullEnabled(reg),
			EncryptionEnabled: true, // Azure ACR always encrypts images at rest.

			SKU:                    skuName(reg),
			LoginServer:            loginServer(reg),
			PublicNetworkAccess:    publicNetworkAccess(reg),
			AnonymousPullEnabled:   anonymousPullEnabled(reg),
			AdminUserEnabled:       adminUserEnabled(reg),
			CMEKEnabled:            keyID != "",
			KMSKeyID:               keyID,
			EncryptionStatus:       encryptionStatus(reg),
			ZoneRedundancy:         zoneRedundancy(reg),
			QuarantinePolicyStatus: quarantinePolicyStatus(reg),
			ResourceGroup:          resourceGroupOrEmpty(deref(reg.ID)),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("azure.acr: marshal registry payload for %q: %w", payload.ID, err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          payload.ID,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
			Scope:       scope,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// --- pure mapping helpers (unit-tested via table tests) ---

// anonymousPullEnabled reports whether unauthenticated image pulls are allowed —
// the honest "publicly accessible" signal for a container registry. nil → false.
func anonymousPullEnabled(reg *armcontainerregistry.Registry) bool {
	if reg.Properties == nil {
		return false
	}
	return derefBool(reg.Properties.AnonymousPullEnabled)
}

// quarantineEnabled reports whether the quarantine policy is enabled (pushed
// images are held unpullable until scanned/marked healthy) — the only
// per-registry scan-on-push gate ACR exposes. nil policy → false.
func quarantineEnabled(reg *armcontainerregistry.Registry) bool {
	if reg.Properties == nil || reg.Properties.Policies == nil || reg.Properties.Policies.QuarantinePolicy == nil {
		return false
	}
	st := reg.Properties.Policies.QuarantinePolicy.Status
	return st != nil && *st == armcontainerregistry.PolicyStatusEnabled
}

func quarantinePolicyStatus(reg *armcontainerregistry.Registry) string {
	if reg.Properties == nil || reg.Properties.Policies == nil || reg.Properties.Policies.QuarantinePolicy == nil {
		return ""
	}
	if st := reg.Properties.Policies.QuarantinePolicy.Status; st != nil {
		return string(*st)
	}
	return ""
}

func adminUserEnabled(reg *armcontainerregistry.Registry) bool {
	if reg.Properties == nil {
		return false
	}
	return derefBool(reg.Properties.AdminUserEnabled)
}

func publicNetworkAccess(reg *armcontainerregistry.Registry) string {
	if reg.Properties == nil || reg.Properties.PublicNetworkAccess == nil {
		return ""
	}
	return string(*reg.Properties.PublicNetworkAccess)
}

func encryptionStatus(reg *armcontainerregistry.Registry) string {
	if reg.Properties == nil || reg.Properties.Encryption == nil || reg.Properties.Encryption.Status == nil {
		return ""
	}
	return string(*reg.Properties.Encryption.Status)
}

func zoneRedundancy(reg *armcontainerregistry.Registry) string {
	if reg.Properties == nil || reg.Properties.ZoneRedundancy == nil {
		return ""
	}
	return string(*reg.Properties.ZoneRedundancy)
}

func loginServer(reg *armcontainerregistry.Registry) string {
	if reg.Properties == nil {
		return ""
	}
	return deref(reg.Properties.LoginServer)
}

func skuName(reg *armcontainerregistry.Registry) string {
	if reg.SKU == nil || reg.SKU.Name == nil {
		return ""
	}
	return string(*reg.SKU.Name)
}

// cmekKeyID returns the customer-managed key identifier when the registry is
// encrypted with a customer key (preferring the versioned identifier), or "" for
// the default Microsoft-managed-key encryption.
func cmekKeyID(reg *armcontainerregistry.Registry) string {
	if reg.Properties == nil || reg.Properties.Encryption == nil || reg.Properties.Encryption.KeyVaultProperties == nil {
		return ""
	}
	kv := reg.Properties.Encryption.KeyVaultProperties
	if id := deref(kv.VersionedKeyIdentifier); id != "" {
		return id
	}
	return deref(kv.KeyIdentifier)
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

// realACR is the production implementation of API. It wraps the
// armcontainerregistry RegistriesClient, listed subscription-wide.
type realACR struct {
	client *armcontainerregistry.RegistriesClient
}

// newRealACR builds the SDK client. opts is nil in production; tests pass a
// *arm.ClientOptions pointing the client at an httptest server.
func newRealACR(subscriptionID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*realACR, error) {
	client, err := armcontainerregistry.NewRegistriesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.acr: registries client: %w", err)
	}
	return &realACR{client: client}, nil
}

func (r *realACR) ListRegistries(ctx context.Context) ([]*armcontainerregistry.Registry, error) {
	var out []*armcontainerregistry.Registry
	pager := r.client.NewListPager(nil)
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
