// Package cosmos implements the azure.cosmos source plugin: it lists Azure
// Cosmos DB accounts in a subscription and emits one cross-vendor nosql_table
// record per account, so the encryption, point-in-time-recovery, and
// deletion-protection policies evaluate against Azure exactly as they do
// against AWS DynamoDB and GCP Firestore — zero policy changes (Invariant #4).
//
// Granularity: one record per Cosmos DB ACCOUNT (not per container). The three
// compliance signals the schema cares about — encryption at rest, PITR
// (continuous backup), and deletion protection — are all account-level
// properties in Cosmos DB, not per-container; emitting one-per-container would
// multiply identical records. This mirrors gcp.firestore (one record per
// database).
//
// Field mapping (the schema-required fields id, name, encryption_enabled,
// point_in_time_recovery_enabled, deletion_protection are always present; the
// policies read all three booleans via plain leaf clauses with no is_set guard,
// so they must never be absent — per WU-0.2 the evaluator errors on a
// referenced-but-absent field):
//
//   - encryption_enabled — a platform CONSTANT true. Cosmos DB always encrypts
//     data at rest (Microsoft-managed keys by default, cannot be disabled); the
//     only real toggle is platform-managed vs customer-managed keys, which rides
//     in the auditable cmek_enabled / kms_key_id extras (KeyVaultKeyURI).
//     Mirrors gcp.firestore (always-on) and azure.storage/azure.acr.
//   - point_in_time_recovery_enabled — true iff the account's BackupPolicy is
//     continuous mode (*ContinuousModeBackupPolicy, discriminator "Continuous").
//     Periodic mode (snapshot-only) and a nil/unknown policy → false. The
//     restore window (Continuous7Days / Continuous30Days) rides in the
//     continuous_backup_tier extra.
//   - deletion_protection — a CONSTANT false. Cosmos DB exposes no account-level
//     deletion-protection property; true deletion protection is an ARM resource
//     lock (Microsoft.Authorization/locks — a separate plane, not read here).
//     Customers cover that control via a resource lock + a .sigcomply.yaml
//     exception or manual evidence — the honest-gap pattern used by azure.sql
//     (deletion protection) and azure.keyvault (secret rotation). Neither
//     fabricating true (dishonest pass) nor reading locks (an extra plane and
//     N+1, out of this WU's scope) is done.
//
// A list failure (e.g. a missing-permission 403) is surfaced as an error
// (tagging only the azure.cosmos-bound policies `error`) rather than returning a
// partial or insecure-default result — never fabricate.
//
// Test injection: the API interface is the single seam and returns raw SDK types
// so 100% of the vendor→canonical mapping stays in Collect under fakeAPI unit
// tests; the real adapter (realCosmos) wraps the armcosmos DatabaseAccounts
// client. Collection is a single subscription-wide list call — there is no N+1.
package cosmos

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armcosmos "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v3"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// EvidenceTypeID is the single evidence type this plugin emits.
const EvidenceTypeID = "nosql_table"

// SourceID is the registered ID for the azure.cosmos plugin instance.
const SourceID = "azure.cosmos"

// API is the subset of the Azure Cosmos DB management plane this plugin uses. It
// returns raw SDK types so the vendor→canonical mapping is exercised by fakeAPI
// unit tests; the real adapter (realCosmos) wraps the SDK client.
type API interface {
	// ListAccounts returns every Cosmos DB account in the subscription.
	ListAccounts(ctx context.Context) ([]*armcosmos.DatabaseAccountGetResults, error)
}

// Plugin is the in-process azure.cosmos source.
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

// NewFromAzure constructs a Plugin backed by the real armcosmos SDK using the
// given credential (a DefaultAzureCredential) scoped to cfg.SubscriptionID.
func NewFromAzure(cred azcore.TokenCredential, cfg azcommon.Config) (*Plugin, error) {
	adapter, err := newRealCosmos(cfg.SubscriptionID, cred, nil)
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

// accountPayload is the cross-vendor nosql_table shape with Azure enrichment
// fields in the additionalProperties tail. The schema-required fields (id, name,
// encryption_enabled, point_in_time_recovery_enabled, deletion_protection) are
// always present.
type accountPayload struct {
	ID                         string `json:"id"`
	Name                       string `json:"name"`
	Provider                   string `json:"provider"`
	EncryptionEnabled          bool   `json:"encryption_enabled"`
	PointInTimeRecoveryEnabled bool   `json:"point_in_time_recovery_enabled"`
	DeletionProtection         bool   `json:"deletion_protection"`

	// Auditable Azure extras (additionalProperties).
	Kind                 string `json:"kind,omitempty"`
	Location             string `json:"location,omitempty"`
	ResourceGroup        string `json:"resource_group,omitempty"`
	BackupPolicyType     string `json:"backup_policy_type,omitempty"`
	ContinuousBackupTier string `json:"continuous_backup_tier,omitempty"`
	CMEKEnabled          bool   `json:"cmek_enabled"`
	KMSKeyID             string `json:"kms_key_id,omitempty"`
	PublicNetworkAccess  string `json:"public_network_access,omitempty"`
	LocalAuthDisabled    bool   `json:"local_auth_disabled"`
	VNetFilterEnabled    bool   `json:"vnet_filter_enabled"`
	ProvisioningState    string `json:"provisioning_state,omitempty"`
}

// Collect lists Cosmos DB accounts in the subscription and emits one nosql_table
// record per account, sorted by ID (ARM resource id) so envelope bytes are
// stable across runs against stable state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("azure.cosmos: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	accounts, err := p.api.ListAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.cosmos: list accounts: %w", err)
	}
	var scope *core.RecordScope
	if p.subscriptionID != "" {
		scope = &core.RecordScope{Account: p.subscriptionID}
	}
	now := p.now()

	records := make([]core.EvidenceRecord, 0, len(accounts))
	for _, acct := range accounts {
		if acct == nil {
			continue
		}
		keyID := cmekKeyID(acct)
		payload := accountPayload{
			ID:                         deref(acct.ID),
			Name:                       deref(acct.Name),
			Provider:                   "azure",
			EncryptionEnabled:          true, // Cosmos DB always encrypts data at rest.
			PointInTimeRecoveryEnabled: pitrEnabled(acct),
			DeletionProtection:         false, // no account-level property; ARM resource lock (not read here) is the mechanism.

			Kind:                 kind(acct),
			Location:             deref(acct.Location),
			ResourceGroup:        resourceGroupOrEmpty(deref(acct.ID)),
			BackupPolicyType:     backupPolicyType(acct),
			ContinuousBackupTier: continuousBackupTier(acct),
			CMEKEnabled:          keyID != "",
			KMSKeyID:             keyID,
			PublicNetworkAccess:  publicNetworkAccess(acct),
			LocalAuthDisabled:    localAuthDisabled(acct),
			VNetFilterEnabled:    vnetFilterEnabled(acct),
			ProvisioningState:    provisioningState(acct),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("azure.cosmos: marshal account payload for %q: %w", payload.ID, err)
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

// pitrEnabled reports whether the account uses continuous-mode backup
// (point-in-time restore). Periodic mode (snapshot-only) and a nil/unknown
// policy → false.
func pitrEnabled(acct *armcosmos.DatabaseAccountGetResults) bool {
	if acct.Properties == nil {
		return false
	}
	_, ok := acct.Properties.BackupPolicy.(*armcosmos.ContinuousModeBackupPolicy)
	return ok
}

// backupPolicyType returns the backup-policy discriminator ("Continuous" /
// "Periodic"), or "" when no policy is set.
func backupPolicyType(acct *armcosmos.DatabaseAccountGetResults) string {
	if acct.Properties == nil || acct.Properties.BackupPolicy == nil {
		return ""
	}
	if bp := acct.Properties.BackupPolicy.GetBackupPolicy(); bp != nil && bp.Type != nil {
		return string(*bp.Type)
	}
	return ""
}

// continuousBackupTier returns the continuous-backup restore window
// (Continuous7Days / Continuous30Days) when the account is in continuous mode,
// else "".
func continuousBackupTier(acct *armcosmos.DatabaseAccountGetResults) string {
	if acct.Properties == nil {
		return ""
	}
	cont, ok := acct.Properties.BackupPolicy.(*armcosmos.ContinuousModeBackupPolicy)
	if !ok || cont.ContinuousModeProperties == nil || cont.ContinuousModeProperties.Tier == nil {
		return ""
	}
	return string(*cont.ContinuousModeProperties.Tier)
}

// cmekKeyID returns the customer-managed Key Vault key URI when the account is
// encrypted with a customer key, or "" for the default Microsoft-managed-key
// encryption.
func cmekKeyID(acct *armcosmos.DatabaseAccountGetResults) string {
	if acct.Properties == nil {
		return ""
	}
	return deref(acct.Properties.KeyVaultKeyURI)
}

func publicNetworkAccess(acct *armcosmos.DatabaseAccountGetResults) string {
	if acct.Properties == nil || acct.Properties.PublicNetworkAccess == nil {
		return ""
	}
	return string(*acct.Properties.PublicNetworkAccess)
}

func localAuthDisabled(acct *armcosmos.DatabaseAccountGetResults) bool {
	if acct.Properties == nil {
		return false
	}
	return derefBool(acct.Properties.DisableLocalAuth)
}

func vnetFilterEnabled(acct *armcosmos.DatabaseAccountGetResults) bool {
	if acct.Properties == nil {
		return false
	}
	return derefBool(acct.Properties.IsVirtualNetworkFilterEnabled)
}

func provisioningState(acct *armcosmos.DatabaseAccountGetResults) string {
	if acct.Properties == nil {
		return ""
	}
	return deref(acct.Properties.ProvisioningState)
}

func kind(acct *armcosmos.DatabaseAccountGetResults) string {
	if acct.Kind == nil {
		return ""
	}
	return string(*acct.Kind)
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

// realCosmos is the production implementation of API. It wraps the armcosmos
// DatabaseAccountsClient, listed subscription-wide.
type realCosmos struct {
	client *armcosmos.DatabaseAccountsClient
}

// newRealCosmos builds the SDK client. opts is nil in production; tests pass a
// *arm.ClientOptions pointing the client at an httptest server.
func newRealCosmos(subscriptionID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*realCosmos, error) {
	client, err := armcosmos.NewDatabaseAccountsClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.cosmos: database accounts client: %w", err)
	}
	return &realCosmos{client: client}, nil
}

func (r *realCosmos) ListAccounts(ctx context.Context) ([]*armcosmos.DatabaseAccountGetResults, error) {
	var out []*armcosmos.DatabaseAccountGetResults
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
