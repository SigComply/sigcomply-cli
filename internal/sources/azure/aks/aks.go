// Package aks implements the azure.aks source plugin: it lists Azure Kubernetes
// Service (AKS) managed clusters in a subscription and emits one cross-vendor
// kubernetes_cluster record per cluster, so secrets-encryption, logging, and
// network-isolation policies evaluate against Azure exactly as they do against
// AWS EKS and GCP GKE — zero policy changes (Invariant #4).
//
// Field mapping (the schema-required fields id, name, secrets_encryption_enabled,
// logging_enabled are always present; the sole shipped policy reads
// secrets_encryption_enabled via a plain leaf clause, so it must never be absent):
//
//   - secrets_encryption_enabled — from SecurityProfile.AzureKeyVaultKms.Enabled.
//     AKS always encrypts etcd at rest with Azure platform-managed keys, but the
//     compliance-meaningful, customer-controlled signal is the Key Vault KMS
//     envelope encryption of Kubernetes Secrets — the exact analog of GKE
//     application-layer secrets encryption (DatabaseEncryption + Cloud KMS) and
//     EKS envelope encryption (EncryptionConfig + KMS). nil → false. The KEK id
//     rides in the auditable kms_key_id extra.
//   - logging_enabled — control-plane audit logging is NOT a field on the cluster
//     object; AKS surfaces it through Azure Monitor diagnostic settings on the
//     cluster resource (the kube-audit / kube-audit-admin / guard log categories).
//     So logging_enabled requires a per-cluster diagnostic-settings read (an N+1)
//     and is true iff an enabled setting routes an audit log category (or the
//     audit / allLogs category group). This mirrors EKS control-plane logging and
//     GKE LoggingConfig — the omsagent (Container Insights) addon was deliberately
//     rejected as a proxy because it collects container/metric logs, not the
//     control-plane audit trail the schema field means. The matched categories
//     ride in the auditable audit_log_categories extra.
//   - is_private_endpoint — from APIServerAccessProfile.EnablePrivateCluster (the
//     API server has no public endpoint). nil → false.
//   - node_auto_upgrade_enabled — from AutoUpgradeProfile.UpgradeChannel set to
//     anything other than "none" (the cluster auto-upgrades its Kubernetes/node
//     version). nil/none → false; best-effort (no shipped policy reads it).
//
// A clusters-list or diagnostic-settings read failure (e.g. a missing-permission
// 403) is surfaced as an error (tagging only the azure.aks-bound policies `error`)
// rather than returning a partial or insecure-default result — never fabricate.
//
// Test injection: the API interface is the single seam and returns raw SDK types
// so 100% of the vendor→canonical mapping stays in Collect under fakeAPI unit
// tests; the real adapter (realAKS) wraps the armcontainerservice managed-clusters
// client (subscription-wide list) and the armmonitor diagnostic-settings client
// (per-cluster, resource-scoped).
package aks

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armcontainerservice "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v9"
	armmonitor "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// EvidenceTypeID is the single evidence type this plugin emits.
const EvidenceTypeID = "kubernetes_cluster"

// SourceID is the registered ID for the azure.aks plugin instance.
const SourceID = "azure.aks"

// API is the subset of the Azure management plane this plugin uses. It returns
// raw SDK types so the vendor→canonical mapping is exercised by fakeAPI unit
// tests; the real adapter (realAKS) wraps the SDK clients.
type API interface {
	// ListManagedClusters returns every AKS cluster in the subscription.
	ListManagedClusters(ctx context.Context) ([]*armcontainerservice.ManagedCluster, error)
	// ListClusterDiagnosticSettings returns the Azure Monitor diagnostic settings
	// attached to the given cluster ARM resource id.
	ListClusterDiagnosticSettings(ctx context.Context, resourceID string) ([]*armmonitor.DiagnosticSettingsResource, error)
}

// Plugin is the in-process azure.aks source.
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

// NewFromAzure constructs a Plugin backed by the real armcontainerservice and
// armmonitor SDKs using the given credential (a DefaultAzureCredential) scoped to
// cfg.SubscriptionID.
func NewFromAzure(cred azcore.TokenCredential, cfg azcommon.Config) (*Plugin, error) {
	adapter, err := newRealAKS(cfg.SubscriptionID, cred, nil)
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

// clusterPayload is the cross-vendor kubernetes_cluster shape (matching aws.eks /
// gcp.gke) with Azure enrichment fields in the additionalProperties tail. The
// schema-required fields (id, name, secrets_encryption_enabled, logging_enabled)
// are always present.
type clusterPayload struct {
	ID                       string `json:"id"`
	Name                     string `json:"name"`
	Provider                 string `json:"provider"`
	Version                  string `json:"version,omitempty"`
	SecretsEncryptionEnabled bool   `json:"secrets_encryption_enabled"`
	LoggingEnabled           bool   `json:"logging_enabled"`
	IsPrivateEndpoint        bool   `json:"is_private_endpoint"`
	NodeAutoUpgradeEnabled   bool   `json:"node_auto_upgrade_enabled"`

	// Auditable Azure extras (additionalProperties).
	ResourceGroup       string   `json:"resource_group,omitempty"`
	Location            string   `json:"location,omitempty"`
	PowerState          string   `json:"power_state,omitempty"`
	ProvisioningState   string   `json:"provisioning_state,omitempty"`
	SKUTier             string   `json:"sku_tier,omitempty"`
	RBACEnabled         bool     `json:"rbac_enabled"`
	NetworkPolicy       string   `json:"network_policy,omitempty"`
	NetworkPlugin       string   `json:"network_plugin,omitempty"`
	KMSKeyID            string   `json:"kms_key_id,omitempty"`
	DiskEncryptionSetID string   `json:"disk_encryption_set_id,omitempty"`
	EncryptionAtHost    bool     `json:"encryption_at_host"`
	AuditLogCategories  []string `json:"audit_log_categories,omitempty"`
	AuthorizedIPRanges  int      `json:"authorized_ip_range_count"`
}

// Collect lists managed clusters in the subscription and emits one
// kubernetes_cluster record per cluster, sorted by ID (ARM resource id) so
// envelope bytes are stable across runs against stable state. Each cluster's
// audit-logging posture is read from its diagnostic settings (an N+1).
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("azure.aks: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	clusters, err := p.api.ListManagedClusters(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.aks: list managed clusters: %w", err)
	}
	var scope *core.RecordScope
	if p.subscriptionID != "" {
		scope = &core.RecordScope{Account: p.subscriptionID}
	}
	now := p.now()

	records := make([]core.EvidenceRecord, 0, len(clusters))
	for _, mc := range clusters {
		if mc == nil {
			continue
		}
		id := deref(mc.ID)

		var loggingEnabled bool
		var auditCategories []string
		if id != "" {
			settings, err := p.api.ListClusterDiagnosticSettings(ctx, id)
			if err != nil {
				return nil, fmt.Errorf("azure.aks: list diagnostic settings for %q: %w", id, err)
			}
			loggingEnabled, auditCategories = auditLoggingEnabled(settings)
		}

		payload := clusterPayload{
			ID:                       id,
			Name:                     deref(mc.Name),
			Provider:                 "azure",
			Version:                  clusterVersion(mc),
			SecretsEncryptionEnabled: kmsSecretsEncryptionEnabled(mc),
			LoggingEnabled:           loggingEnabled,
			IsPrivateEndpoint:        privateCluster(mc),
			NodeAutoUpgradeEnabled:   autoUpgradeEnabled(mc),

			ResourceGroup:       resourceGroupFromID(id),
			Location:            deref(mc.Location),
			PowerState:          powerState(mc),
			ProvisioningState:   provisioningState(mc),
			SKUTier:             skuTier(mc),
			RBACEnabled:         rbacEnabled(mc),
			NetworkPolicy:       networkPolicy(mc),
			NetworkPlugin:       networkPlugin(mc),
			KMSKeyID:            kmsKeyID(mc),
			DiskEncryptionSetID: diskEncryptionSetID(mc),
			EncryptionAtHost:    allPoolsEncryptionAtHost(mc),
			AuditLogCategories:  auditCategories,
			AuthorizedIPRanges:  authorizedIPRangeCount(mc),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("azure.aks: marshal cluster payload for %q: %w", payload.ID, err)
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

// kmsSecretsEncryptionEnabled reports whether the cluster encrypts Kubernetes
// Secrets in etcd with an Azure Key Vault KMS key (customer-controlled envelope
// encryption) — the cross-vendor secrets-at-rest signal. nil → false.
func kmsSecretsEncryptionEnabled(mc *armcontainerservice.ManagedCluster) bool {
	kms := keyVaultKms(mc)
	return kms != nil && derefBool(kms.Enabled)
}

// kmsKeyID returns the Key Vault KMS key identifier when secrets encryption is
// configured, else "".
func kmsKeyID(mc *armcontainerservice.ManagedCluster) string {
	kms := keyVaultKms(mc)
	if kms == nil {
		return ""
	}
	return deref(kms.KeyID)
}

func keyVaultKms(mc *armcontainerservice.ManagedCluster) *armcontainerservice.AzureKeyVaultKms {
	if mc.Properties == nil || mc.Properties.SecurityProfile == nil {
		return nil
	}
	return mc.Properties.SecurityProfile.AzureKeyVaultKms
}

// privateCluster reports whether the API server endpoint is private. nil → false.
func privateCluster(mc *armcontainerservice.ManagedCluster) bool {
	if mc.Properties == nil || mc.Properties.APIServerAccessProfile == nil {
		return false
	}
	return derefBool(mc.Properties.APIServerAccessProfile.EnablePrivateCluster)
}

func authorizedIPRangeCount(mc *armcontainerservice.ManagedCluster) int {
	if mc.Properties == nil || mc.Properties.APIServerAccessProfile == nil {
		return 0
	}
	n := 0
	for _, r := range mc.Properties.APIServerAccessProfile.AuthorizedIPRanges {
		if r != nil && *r != "" {
			n++
		}
	}
	return n
}

// autoUpgradeEnabled reports whether the cluster has an auto-upgrade channel set
// to anything other than "none". nil/none → false.
func autoUpgradeEnabled(mc *armcontainerservice.ManagedCluster) bool {
	if mc.Properties == nil || mc.Properties.AutoUpgradeProfile == nil {
		return false
	}
	ch := mc.Properties.AutoUpgradeProfile.UpgradeChannel
	return ch != nil && *ch != armcontainerservice.UpgradeChannelNone
}

// clusterVersion prefers the running control-plane version, falling back to the
// configured version.
func clusterVersion(mc *armcontainerservice.ManagedCluster) string {
	if mc.Properties == nil {
		return ""
	}
	if v := deref(mc.Properties.CurrentKubernetesVersion); v != "" {
		return v
	}
	return deref(mc.Properties.KubernetesVersion)
}

func rbacEnabled(mc *armcontainerservice.ManagedCluster) bool {
	if mc.Properties == nil {
		return false
	}
	return derefBool(mc.Properties.EnableRBAC)
}

func powerState(mc *armcontainerservice.ManagedCluster) string {
	if mc.Properties == nil || mc.Properties.PowerState == nil || mc.Properties.PowerState.Code == nil {
		return ""
	}
	return string(*mc.Properties.PowerState.Code)
}

func provisioningState(mc *armcontainerservice.ManagedCluster) string {
	if mc.Properties == nil {
		return ""
	}
	return deref(mc.Properties.ProvisioningState)
}

func networkPolicy(mc *armcontainerservice.ManagedCluster) string {
	if mc.Properties == nil || mc.Properties.NetworkProfile == nil || mc.Properties.NetworkProfile.NetworkPolicy == nil {
		return ""
	}
	return string(*mc.Properties.NetworkProfile.NetworkPolicy)
}

func networkPlugin(mc *armcontainerservice.ManagedCluster) string {
	if mc.Properties == nil || mc.Properties.NetworkProfile == nil || mc.Properties.NetworkProfile.NetworkPlugin == nil {
		return ""
	}
	return string(*mc.Properties.NetworkProfile.NetworkPlugin)
}

func diskEncryptionSetID(mc *armcontainerservice.ManagedCluster) string {
	if mc.Properties == nil {
		return ""
	}
	return deref(mc.Properties.DiskEncryptionSetID)
}

func skuTier(mc *armcontainerservice.ManagedCluster) string {
	if mc.SKU == nil || mc.SKU.Tier == nil {
		return ""
	}
	return string(*mc.SKU.Tier)
}

// allPoolsEncryptionAtHost reports whether every agent pool has encryption-at-host
// enabled (VM temp-disk/cache encryption). An empty pool list → false.
func allPoolsEncryptionAtHost(mc *armcontainerservice.ManagedCluster) bool {
	if mc.Properties == nil || len(mc.Properties.AgentPoolProfiles) == 0 {
		return false
	}
	for _, pool := range mc.Properties.AgentPoolProfiles {
		if pool == nil || !derefBool(pool.EnableEncryptionAtHost) {
			return false
		}
	}
	return true
}

// auditLoggingEnabled reports whether any enabled diagnostic setting routes a
// control-plane audit log category (kube-audit, kube-audit-admin, guard) or a
// category group covering it (audit, allLogs), and returns the matched category
// names (deduped, sorted) for auditability.
func auditLoggingEnabled(settings []*armmonitor.DiagnosticSettingsResource) (enabled bool, categories []string) {
	seen := map[string]bool{}
	var cats []string
	for _, ds := range settings {
		if ds == nil || ds.Properties == nil {
			continue
		}
		for _, l := range ds.Properties.Logs {
			if l == nil || l.Enabled == nil || !*l.Enabled {
				continue
			}
			name := logCategory(l)
			if name == "" || !isAuditCategory(name) || seen[name] {
				continue
			}
			seen[name] = true
			cats = append(cats, name)
		}
	}
	sort.Strings(cats)
	return len(cats) > 0, cats
}

// isAuditCategory reports whether a diagnostic-settings log category (or category
// group) covers AKS control-plane audit logging, matched case-insensitively.
func isAuditCategory(name string) bool {
	switch strings.ToLower(name) {
	case "kube-audit", "kube-audit-admin", "guard", "audit", "alllogs":
		return true
	default:
		return false
	}
}

// logCategory returns the category (or category group) name of a log setting.
func logCategory(l *armmonitor.LogSettings) string {
	if l == nil {
		return ""
	}
	if c := deref(l.Category); c != "" {
		return c
	}
	return deref(l.CategoryGroup)
}

// resourceGroupFromID extracts the resource group from an ARM resource id,
// case-insensitively. resource_group is an auditable extra (not load-bearing), so
// a malformed id yields "" rather than an error.
func resourceGroupFromID(id string) string {
	parts := strings.Split(id, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") && parts[i+1] != "" {
			return parts[i+1]
		}
	}
	return ""
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

// realAKS is the production implementation of API. It wraps the
// armcontainerservice ManagedClustersClient (subscription-wide list) and the
// armmonitor DiagnosticSettingsClient (per-cluster, resource-scoped).
type realAKS struct {
	clusters    *armcontainerservice.ManagedClustersClient
	diagnostics *armmonitor.DiagnosticSettingsClient
}

// newRealAKS builds the SDK clients. opts is nil in production; tests pass a
// *arm.ClientOptions pointing the clients at an httptest server.
func newRealAKS(subscriptionID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*realAKS, error) {
	clusters, err := armcontainerservice.NewManagedClustersClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.aks: managed clusters client: %w", err)
	}
	diagnostics, err := armmonitor.NewDiagnosticSettingsClient(cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.aks: diagnostic settings client: %w", err)
	}
	return &realAKS{clusters: clusters, diagnostics: diagnostics}, nil
}

func (r *realAKS) ListManagedClusters(ctx context.Context) ([]*armcontainerservice.ManagedCluster, error) {
	var out []*armcontainerservice.ManagedCluster
	pager := r.clusters.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (r *realAKS) ListClusterDiagnosticSettings(ctx context.Context, resourceID string) ([]*armmonitor.DiagnosticSettingsResource, error) {
	var out []*armmonitor.DiagnosticSettingsResource
	pager := r.diagnostics.NewListPager(resourceID, nil)
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
