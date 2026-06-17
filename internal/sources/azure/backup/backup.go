// Package backup implements the azure.backup source plugin: it enumerates Azure
// Recovery Services backup protection policies across a subscription and emits
// one cross-vendor backup_plan record per policy, so the backup_plan policy
// (soc2.a1.1.backup_plan_exists) evaluates against Azure exactly as it does
// against AWS Backup and GCP Backup — zero policy changes (Invariant #4).
//
// Collection is an N+1 walk: list every Recovery Services vault in the
// subscription (armrecoveryservices), then list the backup protection policies
// inside each vault (armrecoveryservicesbackup) — protection policies are a
// child resource of a vault, with no subscription-wide list endpoint.
//
// Field mapping (the schema-required fields id, name, is_active,
// has_retention_rule are always present; soc2.a1.1.backup_plan_exists reads
// is_active and has_retention_rule via plain leaf clauses with no is_set guard,
// so they must never be absent — per WU-0.2 the evaluator errors on a
// referenced-but-absent field):
//
//   - is_active — true iff the policy currently protects ≥1 item
//     (ProtectedItemsCount > 0). A backup policy has no enabled/state flag in
//     Azure: it either exists or not. The honest "actively backing up" signal is
//     that something is actually attached to it — a defined-but-unused policy
//     protecting zero items provides no backup coverage, so it reads inactive.
//     This is the same honest-state choice gcp.backup makes (State==ACTIVE),
//     stronger than aws.backup's "listed == active" (AWS exposes no such count).
//   - has_retention_rule — true iff the policy's resolved retention yields a
//     positive day count (retention_days > 0).
//   - retention_days — the maximum retention across the policy's schedules /
//     sub-policies, in days (a *int64 omitted, not 0, when no retention rule —
//     matches aws.backup / gcp.backup). Azure stores retention as count+unit
//     (Days/Weeks/Months/Years), not raw days, so Weeks/Months/Years are
//     converted with 7/30/365-day approximations (documented).
//   - covers_resource_types — the policy's BackupManagementType discriminator
//     (e.g. AzureIaasVM, AzureSql, AzureStorage, AzureWorkload) as a 1-element
//     slice (omitted when unknown).
//
// A vault-list or policy-list failure (e.g. a missing-permission 403) is
// surfaced as an error (tagging only the azure.backup-bound policies `error`)
// rather than returning a partial or insecure-default result — never fabricate.
//
// Test injection: the API interface is the single seam and returns raw SDK types
// so 100% of the vendor→canonical mapping stays in Collect under fakeAPI unit
// tests; the real adapter (realBackup) wraps the armrecoveryservices Vaults
// client and the armrecoveryservicesbackup BackupPolicies client.
package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservices"
	armbackup "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservicesbackup/v4"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// EvidenceTypeID is the single evidence type this plugin emits.
const EvidenceTypeID = "backup_plan"

// SourceID is the registered ID for the azure.backup plugin instance.
const SourceID = "azure.backup"

// API is the subset of the Azure Recovery Services management plane this plugin
// uses. It returns raw SDK types so the vendor→canonical mapping is exercised by
// fakeAPI unit tests; the real adapter (realBackup) wraps the SDK clients.
type API interface {
	// ListVaults returns every Recovery Services vault in the subscription.
	ListVaults(ctx context.Context) ([]*armrecoveryservices.Vault, error)
	// ListPolicies returns the backup protection policies inside one vault.
	ListPolicies(ctx context.Context, vaultName, resourceGroup string) ([]*armbackup.ProtectionPolicyResource, error)
}

// Plugin is the in-process azure.backup source.
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

// NewFromAzure constructs a Plugin backed by the real Recovery Services SDK
// clients using the given credential (a DefaultAzureCredential) scoped to
// cfg.SubscriptionID.
func NewFromAzure(cred azcore.TokenCredential, cfg azcommon.Config) (*Plugin, error) {
	adapter, err := newRealBackup(cfg.SubscriptionID, cred, nil)
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

// policyPayload is the cross-vendor backup_plan shape with Azure enrichment
// fields in the additionalProperties tail. The schema-required fields (id, name,
// is_active, has_retention_rule) are always present; retention_days is a pointer
// so it is omitted (not a 0 sentinel) when the policy has no retention rule.
type policyPayload struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Provider            string   `json:"provider"`
	IsActive            bool     `json:"is_active"`
	HasRetentionRule    bool     `json:"has_retention_rule"`
	RetentionDays       *int64   `json:"retention_days,omitempty"`
	CoversResourceTypes []string `json:"covers_resource_types,omitempty"`

	// Auditable Azure extras (additionalProperties).
	Location            string `json:"location,omitempty"`
	ResourceGroup       string `json:"resource_group,omitempty"`
	VaultName           string `json:"vault_name,omitempty"`
	ProtectedItemsCount int    `json:"protected_items_count"`
}

// Collect walks every vault in the subscription and emits one backup_plan record
// per protection policy, sorted by ID (ARM resource id) so envelope bytes are
// stable across runs against stable state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("azure.backup: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	vaults, err := p.api.ListVaults(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.backup: list vaults: %w", err)
	}
	var scope *core.RecordScope
	if p.subscriptionID != "" {
		scope = &core.RecordScope{Account: p.subscriptionID}
	}
	now := p.now()

	var records []core.EvidenceRecord
	for _, vault := range vaults {
		if vault == nil {
			continue
		}
		vaultName := deref(vault.Name)
		rg, err := resourceGroupFromID(deref(vault.ID))
		if err != nil {
			return nil, fmt.Errorf("azure.backup: vault %q: %w", vaultName, err)
		}
		policies, err := p.api.ListPolicies(ctx, vaultName, rg)
		if err != nil {
			return nil, fmt.Errorf("azure.backup: list policies in vault %q: %w", vaultName, err)
		}
		for _, pol := range policies {
			if pol == nil || pol.Properties == nil {
				continue
			}
			base := pol.Properties.GetProtectionPolicy()
			retDays := policyRetentionDays(pol.Properties)
			payload := policyPayload{
				ID:                  deref(pol.ID),
				Name:                deref(pol.Name),
				Provider:            "azure",
				IsActive:            protectedItemsCount(base) > 0,
				HasRetentionRule:    retDays > 0,
				CoversResourceTypes: coversResourceTypes(base),
				Location:            deref(pol.Location),
				ResourceGroup:       rg,
				VaultName:           vaultName,
				ProtectedItemsCount: protectedItemsCount(base),
			}
			if retDays > 0 {
				d := int64(retDays)
				payload.RetentionDays = &d
			}
			body, err := json.Marshal(payload)
			if err != nil {
				return nil, fmt.Errorf("azure.backup: marshal policy payload for %q: %w", payload.ID, err)
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
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// --- pure mapping helpers (unit-tested via table tests) ---

// protectedItemsCount returns the number of items the policy currently protects
// (nil-safe; the honest "is_active" signal).
func protectedItemsCount(base *armbackup.ProtectionPolicy) int {
	if base == nil || base.ProtectedItemsCount == nil {
		return 0
	}
	return int(*base.ProtectedItemsCount)
}

// coversResourceTypes returns the policy's BackupManagementType discriminator as
// a 1-element slice (e.g. ["AzureIaasVM"]), or nil when unknown.
func coversResourceTypes(base *armbackup.ProtectionPolicy) []string {
	if base == nil || base.BackupManagementType == nil || *base.BackupManagementType == "" {
		return nil
	}
	return []string{*base.BackupManagementType}
}

// policyRetentionDays returns the maximum retention (in days) defined anywhere in
// the policy, dispatching on the concrete protection-policy type. The IaaS-VM,
// SQL, and file-share policies carry a single top-level RetentionPolicy; the VM
// workload policy nests retention inside each sub-policy. Unknown/other types and
// policies with no retention → 0.
func policyRetentionDays(p armbackup.ProtectionPolicyClassification) int {
	switch v := p.(type) {
	case *armbackup.AzureIaaSVMProtectionPolicy:
		return retentionDays(v.RetentionPolicy)
	case *armbackup.AzureSQLProtectionPolicy:
		return retentionDays(v.RetentionPolicy)
	case *armbackup.AzureFileShareProtectionPolicy:
		return retentionDays(v.RetentionPolicy)
	case *armbackup.AzureVMWorkloadProtectionPolicy:
		best := 0
		for _, sub := range v.SubProtectionPolicy {
			if sub == nil {
				continue
			}
			if d := retentionDays(sub.RetentionPolicy); d > best {
				best = d
			}
		}
		return best
	default:
		return 0
	}
}

// retentionDays resolves a RetentionPolicy (long-term schedules or a simple
// duration) to its maximum retention in days.
func retentionDays(rp armbackup.RetentionPolicyClassification) int {
	switch v := rp.(type) {
	case *armbackup.LongTermRetentionPolicy:
		best := 0
		if v.DailySchedule != nil {
			best = max(best, durationToDays(v.DailySchedule.RetentionDuration))
		}
		if v.WeeklySchedule != nil {
			best = max(best, durationToDays(v.WeeklySchedule.RetentionDuration))
		}
		if v.MonthlySchedule != nil {
			best = max(best, durationToDays(v.MonthlySchedule.RetentionDuration))
		}
		if v.YearlySchedule != nil {
			best = max(best, durationToDays(v.YearlySchedule.RetentionDuration))
		}
		return best
	case *armbackup.SimpleRetentionPolicy:
		return durationToDays(v.RetentionDuration)
	default:
		return 0
	}
}

// durationToDays converts an Azure count+unit retention duration to an
// approximate day count (Weeks×7, Months×30, Years×365 — Azure exposes no raw
// day field). nil/incomplete → 0.
func durationToDays(d *armbackup.RetentionDuration) int {
	if d == nil || d.Count == nil || d.DurationType == nil {
		return 0
	}
	c := int(*d.Count)
	switch *d.DurationType {
	case armbackup.RetentionDurationTypeDays:
		return c
	case armbackup.RetentionDurationTypeWeeks:
		return c * 7
	case armbackup.RetentionDurationTypeMonths:
		return c * 30
	case armbackup.RetentionDurationTypeYears:
		return c * 365
	default:
		return 0
	}
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

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// --- real Azure adapter ---

// realBackup is the production implementation of API. It wraps the
// armrecoveryservices Vaults client (subscription-wide vault enumeration) and
// the armrecoveryservicesbackup BackupPolicies client (per-vault policy list).
type realBackup struct {
	vaults   *armrecoveryservices.VaultsClient
	policies *armbackup.BackupPoliciesClient
}

// newRealBackup builds the SDK clients. opts is nil in production; tests pass a
// *arm.ClientOptions pointing the clients at an httptest server.
func newRealBackup(subscriptionID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*realBackup, error) {
	vaults, err := armrecoveryservices.NewVaultsClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.backup: vaults client: %w", err)
	}
	policies, err := armbackup.NewBackupPoliciesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.backup: backup policies client: %w", err)
	}
	return &realBackup{vaults: vaults, policies: policies}, nil
}

func (r *realBackup) ListVaults(ctx context.Context) ([]*armrecoveryservices.Vault, error) {
	var out []*armrecoveryservices.Vault
	pager := r.vaults.NewListBySubscriptionIDPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (r *realBackup) ListPolicies(ctx context.Context, vaultName, resourceGroup string) ([]*armbackup.ProtectionPolicyResource, error) {
	var out []*armbackup.ProtectionPolicyResource
	pager := r.policies.NewListPager(vaultName, resourceGroup, nil)
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
