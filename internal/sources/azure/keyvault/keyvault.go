// Package keyvault implements the azure.keyvault source plugin: it reads Azure
// Key Vault keys and secrets in a subscription and emits two cross-vendor types
// — kms_key (one per key — same type as aws.kms / gcp.kms) and secret (one per
// secret — same type as aws.secretsmanager / gcp.secretmanager) — so the key
// rotation, customer-managed-key, and secret rotation/encryption policies
// evaluate against Azure exactly as they do against AWS and GCP, with zero
// policy changes (Invariant #4).
//
// Management plane only. Vaults, keys, and secret *metadata* are all readable
// through ARM (`armkeyvault`) on Reader RBAC — no Key Vault data-plane access
// policies, and the mgmt plane never returns secret values (good for the
// non-custodial model). The one wrinkle: the keys *list* endpoint strips the
// rotation policy and key type, so each key needs a follow-up mgmt-plane Get
// (an N+1) to populate rotation_enabled and the HSM/software protection level.
//
// kms_key (from Key Vault keys):
//
//   - is_customer_managed is **always true** and key_manager is **always
//     "CUSTOMER"** — a Key Vault key is a customer-provisioned key by
//     definition (mirrors gcp.kms, whose keys are always CUSTOMER). Both are
//     load-bearing: the customer-managed-keys policy filters on
//     is_customer_managed and the rotation policy reads it as a guard.
//   - rotation_enabled is true iff the key's rotation policy has a `rotate`
//     lifetime action with a populated trigger. A `notify`-only policy warns on
//     expiry but does not auto-rotate, so it reads false.
//   - protection_level ("HSM"/"SOFTWARE") rides in additionalProperties,
//     derived from the key type's "-HSM" suffix.
//
// secret (from Key Vault secrets):
//
//   - rotation_enabled is **always false** — Azure Key Vault exposes no
//     API-readable native secret-rotation policy (rotation is implemented
//     externally via Event Grid near-expiry events + a Function). This is an
//     honest gap, not a fabricated value; customers who rotate via automation
//     cover the policy with an exception or manual evidence (the same pattern
//     azure.sql uses for deletion_protection). Reporting a guessed true would
//     be misleading pass evidence.
//   - kms_encrypted is **always true** — a Key Vault secret is always encrypted
//     at rest by the customer's own vault (the vault *is* the customer-managed
//     key store; there is no platform-vs-CMEK distinction as there is for blob
//     storage).
//   - never_rotated / last_rotated_days are best-effort: the mgmt plane exposes
//     no secret version history, so never_rotated is derived from whether the
//     secret has been updated since creation (a metadata-only edit also
//     advances "updated", so this is an upper bound — documented).
//
// A list/get failure (e.g. a missing-permission 403) is surfaced as an error
// (tagging only the azure.keyvault-bound policies `error`) rather than
// returning a partial or insecure-default result.
//
// Test injection: the API interface is the single seam and returns raw SDK
// types so 100% of the vendor→canonical mapping stays in Collect under fakeAPI
// unit tests; the real adapter (realKeyvault) wraps the armkeyvault clients.
package keyvault

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armkeyvault "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault/v2"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// Evidence type IDs this plugin emits.
const (
	EvidenceTypeKMSKey = "kms_key"
	EvidenceTypeSecret = "secret"
)

// SourceID is the registered ID for the azure.keyvault plugin instance.
const SourceID = "azure.keyvault"

// API is the subset of the Azure Key Vault management plane this plugin uses.
// It returns raw SDK types so the vendor→canonical mapping is exercised by
// fakeAPI unit tests; the real adapter (realKeyvault) wraps the armkeyvault
// clients. Keys need both a List (enumeration) and a per-key Get because the
// list endpoint strips the rotation policy and key type.
type API interface {
	// ListVaults returns every Key Vault in the subscription.
	ListVaults(ctx context.Context) ([]*armkeyvault.Vault, error)
	// ListKeys returns the keys in a vault (stripped: no rotation policy / kty).
	ListKeys(ctx context.Context, resourceGroup, vaultName string) ([]*armkeyvault.Key, error)
	// GetKey returns one key fully populated (rotation policy, kty, attributes).
	GetKey(ctx context.Context, resourceGroup, vaultName, keyName string) (*armkeyvault.Key, error)
	// ListSecrets returns the secret metadata in a vault (never the value).
	ListSecrets(ctx context.Context, resourceGroup, vaultName string) ([]*armkeyvault.Secret, error)
}

// Plugin is the in-process azure.keyvault source.
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

// NewFromAzure constructs a Plugin backed by the real armkeyvault SDK using the
// given credential (a DefaultAzureCredential) scoped to cfg.SubscriptionID.
func NewFromAzure(cred azcore.TokenCredential, cfg azcommon.Config) (*Plugin, error) {
	adapter, err := newRealKeyvault(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return New(Options{API: adapter, SubscriptionID: cfg.SubscriptionID}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeKMSKey, EvidenceTypeSecret} }

// Init is a no-op — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// keyPayload is the kms_key shape this plugin emits. key_id, rotation_enabled,
// and is_customer_managed are always present (load-bearing); the rest carry
// auditable context.
type keyPayload struct {
	KeyID             string `json:"key_id"`
	KeyManager        string `json:"key_manager"`
	IsCustomerManaged bool   `json:"is_customer_managed"`
	Enabled           bool   `json:"enabled"`
	RotationEnabled   bool   `json:"rotation_enabled"`
	Provider          string `json:"provider"`

	// Auditable Azure extras (additionalProperties).
	ProtectionLevel string `json:"protection_level,omitempty"`
	KeyType         string `json:"key_type,omitempty"`
	RotationPeriod  string `json:"rotation_period,omitempty"`
	VaultName       string `json:"vault_name,omitempty"`
	ResourceGroup   string `json:"resource_group,omitempty"`
}

// secretPayload is the secret shape this plugin emits. id, name,
// rotation_enabled, kms_encrypted, and never_rotated are always present
// (load-bearing); last_rotated_days is omitted when never rotated.
type secretPayload struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Provider        string `json:"provider"`
	RotationEnabled bool   `json:"rotation_enabled"`
	KMSEncrypted    bool   `json:"kms_encrypted"`
	NeverRotated    bool   `json:"never_rotated"`
	LastRotatedDays *int   `json:"last_rotated_days,omitempty"`

	// Auditable Azure extras (additionalProperties).
	ContentType   string `json:"content_type,omitempty"`
	Enabled       bool   `json:"enabled"`
	VaultName     string `json:"vault_name,omitempty"`
	ResourceGroup string `json:"resource_group,omitempty"`
}

// Collect emits kms_key records (from Key Vault keys) and/or secret records
// (from Key Vault secrets), per the slot's accepted types, grouped in Emits()
// order and each group sorted by ID so envelope bytes are stable across runs.
// Vaults are listed once and shared by both collectors.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	wantKeys := req.Accepts(EvidenceTypeKMSKey)
	wantSecrets := req.Accepts(EvidenceTypeSecret)
	if !wantKeys && !wantSecrets {
		return nil, fmt.Errorf("azure.keyvault: slot AcceptedTypes %v does not include emitted types %q, %q",
			req.AcceptedTypes, EvidenceTypeKMSKey, EvidenceTypeSecret)
	}
	var scope *core.RecordScope
	if p.subscriptionID != "" {
		scope = &core.RecordScope{Account: p.subscriptionID}
	}
	now := p.now()

	vaults, err := p.api.ListVaults(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.keyvault: list vaults: %w", err)
	}

	var records []core.EvidenceRecord
	if wantKeys {
		keyRecs, err := p.collectKeys(ctx, vaults, now, scope)
		if err != nil {
			return nil, err
		}
		records = append(records, keyRecs...)
	}
	if wantSecrets {
		secretRecs, err := p.collectSecrets(ctx, vaults, now, scope)
		if err != nil {
			return nil, err
		}
		records = append(records, secretRecs...)
	}
	return records, nil
}

// collectKeys enumerates each vault's keys and, for every key, fetches the full
// resource (List strips the rotation policy) to build a kms_key record, sorted
// by ID.
func (p *Plugin) collectKeys(ctx context.Context, vaults []*armkeyvault.Vault, now time.Time, scope *core.RecordScope) ([]core.EvidenceRecord, error) {
	var records []core.EvidenceRecord
	for _, vault := range vaults {
		if vault == nil {
			continue
		}
		vaultName := deref(vault.Name)
		rg, err := resourceGroupFromID(deref(vault.ID))
		if err != nil {
			return nil, fmt.Errorf("azure.keyvault: vault %q: %w", vaultName, err)
		}
		keys, err := p.api.ListKeys(ctx, rg, vaultName)
		if err != nil {
			return nil, fmt.Errorf("azure.keyvault: list keys in %q: %w", vaultName, err)
		}
		for _, k := range keys {
			if k == nil {
				continue
			}
			keyName := deref(k.Name)
			full, err := p.api.GetKey(ctx, rg, vaultName, keyName)
			if err != nil {
				return nil, fmt.Errorf("azure.keyvault: get key %q in %q: %w", keyName, vaultName, err)
			}
			if full == nil {
				continue
			}
			payload := buildKeyPayload(full, vaultName, rg)
			rec, err := record(EvidenceTypeKMSKey, payload, payload.KeyID, now, scope)
			if err != nil {
				return nil, err
			}
			records = append(records, rec)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// collectSecrets enumerates each vault's secret metadata and emits one secret
// record each, sorted by ID.
func (p *Plugin) collectSecrets(ctx context.Context, vaults []*armkeyvault.Vault, now time.Time, scope *core.RecordScope) ([]core.EvidenceRecord, error) {
	var records []core.EvidenceRecord
	for _, vault := range vaults {
		if vault == nil {
			continue
		}
		vaultName := deref(vault.Name)
		rg, err := resourceGroupFromID(deref(vault.ID))
		if err != nil {
			return nil, fmt.Errorf("azure.keyvault: vault %q: %w", vaultName, err)
		}
		secrets, err := p.api.ListSecrets(ctx, rg, vaultName)
		if err != nil {
			return nil, fmt.Errorf("azure.keyvault: list secrets in %q: %w", vaultName, err)
		}
		for _, s := range secrets {
			if s == nil {
				continue
			}
			payload := buildSecretPayload(s, vaultName, rg, now)
			rec, err := record(EvidenceTypeSecret, payload, payload.ID, now, scope)
			if err != nil {
				return nil, err
			}
			records = append(records, rec)
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// record marshals a payload into an EvidenceRecord. id is the stable sort key.
func record(typeID string, payload any, id string, now time.Time, scope *core.RecordScope) (core.EvidenceRecord, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("azure.keyvault: marshal %s payload for %q: %w", typeID, id, err)
	}
	return core.EvidenceRecord{
		Type:        typeID,
		ID:          id,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: now,
		Scope:       scope,
	}, nil
}

// --- pure mapping helpers (unit-tested via table tests) ---

// buildKeyPayload maps a fully-populated Key Vault key to a kms_key payload.
func buildKeyPayload(k *armkeyvault.Key, vaultName, rg string) keyPayload {
	p := keyPayload{
		KeyID:             deref(k.ID),
		KeyManager:        "CUSTOMER", // Key Vault keys are customer-provisioned by definition.
		IsCustomerManaged: true,
		Provider:          "azure",
		RotationEnabled:   rotationEnabled(k),
		VaultName:         vaultName,
		ResourceGroup:     rg,
	}
	if k.Properties != nil {
		if a := k.Properties.Attributes; a != nil {
			p.Enabled = derefBool(a.Enabled)
		}
		if k.Properties.Kty != nil {
			kty := string(*k.Properties.Kty)
			p.KeyType = kty
			p.ProtectionLevel = protectionLevel(kty)
		}
		p.RotationPeriod = rotationPeriod(k.Properties.RotationPolicy)
	}
	return p
}

// rotationEnabled reports whether the key has auto-rotation configured: a
// rotation policy with a `rotate` lifetime action and a populated trigger. A
// `notify`-only policy (expiry warning, no rotation) reads false.
func rotationEnabled(k *armkeyvault.Key) bool {
	if k == nil || k.Properties == nil || k.Properties.RotationPolicy == nil {
		return false
	}
	for _, la := range k.Properties.RotationPolicy.LifetimeActions {
		if la == nil || la.Action == nil || la.Action.Type == nil {
			continue
		}
		if *la.Action.Type == armkeyvault.KeyRotationPolicyActionTypeRotate &&
			la.Trigger != nil &&
			(la.Trigger.TimeAfterCreate != nil || la.Trigger.TimeBeforeExpiry != nil) {
			return true
		}
	}
	return false
}

// rotationPeriod returns the ISO-8601 trigger duration of the rotate action (an
// auditable extra), or "" when there is no rotate action.
func rotationPeriod(rp *armkeyvault.RotationPolicy) string {
	if rp == nil {
		return ""
	}
	for _, la := range rp.LifetimeActions {
		if la == nil || la.Action == nil || la.Action.Type == nil {
			continue
		}
		if *la.Action.Type == armkeyvault.KeyRotationPolicyActionTypeRotate && la.Trigger != nil {
			if la.Trigger.TimeAfterCreate != nil {
				return *la.Trigger.TimeAfterCreate
			}
			if la.Trigger.TimeBeforeExpiry != nil {
				return *la.Trigger.TimeBeforeExpiry
			}
		}
	}
	return ""
}

// protectionLevel maps a key type to "HSM" (the "-HSM" suffix) or "SOFTWARE".
func protectionLevel(kty string) string {
	if strings.HasSuffix(kty, "-HSM") {
		return "HSM"
	}
	return "SOFTWARE"
}

// buildSecretPayload maps Key Vault secret metadata to a secret payload. See
// the package doc for the rotation_enabled / kms_encrypted constants.
func buildSecretPayload(s *armkeyvault.Secret, vaultName, rg string, now time.Time) secretPayload {
	p := secretPayload{
		ID:              deref(s.ID),
		Name:            deref(s.Name),
		Provider:        "azure",
		RotationEnabled: false, // Azure KV has no API-readable native secret rotation.
		KMSEncrypted:    true,  // KV secrets are always encrypted by the customer's vault.
		NeverRotated:    true,
		VaultName:       vaultName,
		ResourceGroup:   rg,
	}
	if s.Properties != nil {
		if s.Properties.ContentType != nil {
			p.ContentType = *s.Properties.ContentType
		}
		if a := s.Properties.Attributes; a != nil {
			p.Enabled = derefBool(a.Enabled)
			p.NeverRotated = neverRotated(a)
			if !p.NeverRotated {
				p.LastRotatedDays = lastRotatedDays(a, now)
			}
		}
	}
	return p
}

// neverRotated derives, best-effort, whether a secret has ever been rotated.
// The mgmt plane exposes no version history, so this is true unless the secret
// has been updated after creation (a metadata-only edit also advances Updated,
// so this is an upper bound on "touched").
func neverRotated(a *armkeyvault.SecretAttributes) bool {
	if a == nil || a.Created == nil || a.Updated == nil {
		return true
	}
	return !a.Updated.After(*a.Created)
}

// lastRotatedDays returns whole days since the secret's last update, or nil when
// the update time is unknown.
func lastRotatedDays(a *armkeyvault.SecretAttributes, now time.Time) *int {
	if a == nil || a.Updated == nil {
		return nil
	}
	days := int(now.Sub(*a.Updated).Hours() / 24)
	if days < 0 {
		days = 0
	}
	return &days
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

func derefBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// --- real Azure adapter ---

// realKeyvault is the production implementation of API. It wraps the armkeyvault
// VaultsClient (subscription-wide vault list), KeysClient (per-vault list + get),
// and SecretsClient (per-vault secret-metadata list).
type realKeyvault struct {
	vaults  *armkeyvault.VaultsClient
	keys    *armkeyvault.KeysClient
	secrets *armkeyvault.SecretsClient
}

// newRealKeyvault builds the armkeyvault clients. opts is nil in production;
// tests pass a *arm.ClientOptions pointing the clients at an httptest server.
func newRealKeyvault(subscriptionID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*realKeyvault, error) {
	vaults, err := armkeyvault.NewVaultsClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.keyvault: vaults client: %w", err)
	}
	keys, err := armkeyvault.NewKeysClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.keyvault: keys client: %w", err)
	}
	secrets, err := armkeyvault.NewSecretsClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.keyvault: secrets client: %w", err)
	}
	return &realKeyvault{vaults: vaults, keys: keys, secrets: secrets}, nil
}

func (r *realKeyvault) ListVaults(ctx context.Context) ([]*armkeyvault.Vault, error) {
	var out []*armkeyvault.Vault
	pager := r.vaults.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (r *realKeyvault) ListKeys(ctx context.Context, resourceGroup, vaultName string) ([]*armkeyvault.Key, error) {
	var out []*armkeyvault.Key
	pager := r.keys.NewListPager(resourceGroup, vaultName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (r *realKeyvault) GetKey(ctx context.Context, resourceGroup, vaultName, keyName string) (*armkeyvault.Key, error) {
	resp, err := r.keys.Get(ctx, resourceGroup, vaultName, keyName, nil)
	if err != nil {
		return nil, err
	}
	return &resp.Key, nil
}

func (r *realKeyvault) ListSecrets(ctx context.Context, resourceGroup, vaultName string) ([]*armkeyvault.Secret, error) {
	var out []*armkeyvault.Secret
	pager := r.secrets.NewListPager(resourceGroup, vaultName, nil)
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
