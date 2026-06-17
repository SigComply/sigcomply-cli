// Package monitor implements the azure.monitor source plugin: it reads Azure
// Monitor's logging surface in a subscription and emits two cross-vendor types —
// log_group (one per Log Analytics workspace) and audit_log_trail (one per
// subscription, the Activity Log) — so log-retention and audit-logging policies
// evaluate against Azure exactly as they do against AWS (CloudWatch Logs +
// CloudTrail) and GCP (log buckets + Cloud Audit Logs) — zero policy changes
// (Invariant #4).
//
// log_group (from Log Analytics workspaces):
//
//   - retention_days ← the workspace RetentionInDays; retention_set is true when
//     a positive retention is configured. The log-retention policies
//     (>=90d SOC 2, >=365d ISO 27001) read these two fields.
//   - Encryption at rest is platform-always-on for Log Analytics; customer-managed
//     keys (CMEK) are a per-cluster feature (a dedicated Azure Monitor cluster),
//     not a per-workspace property, so kms_encrypted is intentionally not emitted
//     in v1 (no log_group policy reads it). Resolving cluster CMEK is a documented
//     future enhancement.
//
// audit_log_trail (the subscription Activity Log):
//
//   - Azure's Activity Log is always-on and subscription-wide — it cannot be
//     disabled (unlike AWS CloudTrail, which is opt-in). One record is emitted per
//     subscription: is_enabled and is_multi_region are therefore both true, and
//     log_file_validation_enabled is true because the platform Activity Log is
//     append-only and immutable to users (the same platform-integrity basis on
//     which gcp.audit reports true for the locked _Required bucket).
//   - kms_encrypted is false: the native Activity Log platform retention uses
//     Microsoft-managed keys, not customer-managed. CMEK would require routing the
//     log (via a diagnostic setting) to a CMEK-enabled destination; resolving that
//     destination's key state is out of scope for v1, so this is a documented gap
//     (the audit_log_kms_encrypted control is covered for Azure via a routed CMEK
//     destination + a .sigcomply.yaml exception or manual evidence — the same
//     honest-gap pattern WU-5.6 used for Key Vault secret rotation).
//   - The subscription's diagnostic settings (which route the Activity Log to a
//     Log Analytics workspace / storage account for durable retention) are read to
//     populate auditable extras — exported, the enabled categories, and the
//     destination ids — proving whether the Activity Log is actually retained
//     beyond the platform's 90-day window.
//
// A list failure (e.g. a missing-permission 403) is surfaced as an error
// (tagging only the azure.monitor-bound policies `error`) rather than returning a
// partial or insecure-default result — the WU-5.x "don't fabricate" philosophy.
//
// Test injection: the API interface is the single seam and returns raw SDK types
// so 100% of the vendor→canonical mapping stays in Collect under fakeAPI unit
// tests; the real adapter (realMonitor) wraps the armoperationalinsights and
// armmonitor SDK clients.
//
// SDK note: armmonitor is pinned to v0.11.0 deliberately — v0.12.0 removed the
// subscription-scoped DiagnosticSettingsClient (replaced by a resource-scoped
// client with no list pager). A naive `go get -u` to v0.12.0 will not compile.
package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armmonitor "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	armoi "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights/v2"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// Evidence type IDs this plugin emits.
const (
	EvidenceTypeLogGroup      = "log_group"
	EvidenceTypeAuditLogTrail = "audit_log_trail"
)

// SourceID is the registered ID for the azure.monitor plugin instance.
const SourceID = "azure.monitor"

// API is the subset of the Azure Monitor management plane this plugin uses. It
// returns raw SDK types so the vendor→canonical mapping is exercised by fakeAPI
// unit tests; the real adapter (realMonitor) wraps the SDK clients.
type API interface {
	// ListWorkspaces returns every Log Analytics workspace in the subscription.
	ListWorkspaces(ctx context.Context) ([]*armoi.Workspace, error)
	// ListSubscriptionDiagnosticSettings returns the diagnostic settings on the
	// subscription resource (where Activity Log routing is configured).
	ListSubscriptionDiagnosticSettings(ctx context.Context) ([]*armmonitor.DiagnosticSettingsResource, error)
}

// Plugin is the in-process azure.monitor source.
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

// NewFromAzure constructs a Plugin backed by the real SDK clients using the given
// credential (a DefaultAzureCredential) scoped to cfg.SubscriptionID.
func NewFromAzure(cred azcore.TokenCredential, cfg azcommon.Config) (*Plugin, error) {
	adapter, err := newRealMonitor(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return New(Options{API: adapter, SubscriptionID: cfg.SubscriptionID}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeLogGroup, EvidenceTypeAuditLogTrail} }

// Init is a no-op — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// logGroupPayload is the log_group shape this plugin emits. id, name,
// retention_set, and retention_days are the schema-required fields; the rest are
// auditable extras (additionalProperties).
type logGroupPayload struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Provider      string `json:"provider"`
	RetentionSet  bool   `json:"retention_set"`
	RetentionDays int    `json:"retention_days"`

	// Auditable Azure extras.
	Location      string `json:"location,omitempty"`
	SKU           string `json:"sku,omitempty"`
	ResourceGroup string `json:"resource_group,omitempty"`
}

// auditTrailPayload is the audit_log_trail shape this plugin emits. id, name,
// is_enabled, is_multi_region, log_file_validation_enabled, and kms_encrypted are
// all read by the audit-logging policies, so all are emitted unconditionally
// (the evaluator errors on a referenced-but-absent field — WU-0.2). The diagnostic
// -settings-derived fields are auditable extras.
type auditTrailPayload struct {
	ID                       string `json:"id"`
	Name                     string `json:"name"`
	Provider                 string `json:"provider"`
	IsEnabled                bool   `json:"is_enabled"`
	IsMultiRegion            bool   `json:"is_multi_region"`
	LogFileValidationEnabled bool   `json:"log_file_validation_enabled"`
	KMSEncrypted             bool   `json:"kms_encrypted"`

	// Auditable Azure extras (the Activity Log export configuration).
	Exported                    bool     `json:"exported"`
	DiagnosticSettingCount      int      `json:"diagnostic_setting_count"`
	EnabledCategories           []string `json:"enabled_categories,omitempty"`
	DestinationWorkspaceID      string   `json:"destination_workspace_id,omitempty"`
	DestinationStorageAccountID string   `json:"destination_storage_account_id,omitempty"`
}

// Collect emits log_group records (from Log Analytics workspaces) and/or an
// audit_log_trail record (the subscription Activity Log), per the slot's accepted
// types, grouped in Emits() order and each group sorted by ID so envelope bytes
// are stable across runs.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	wantLog := req.Accepts(EvidenceTypeLogGroup)
	wantAudit := req.Accepts(EvidenceTypeAuditLogTrail)
	if !wantLog && !wantAudit {
		return nil, fmt.Errorf("azure.monitor: slot AcceptedTypes %v does not include emitted types %q, %q",
			req.AcceptedTypes, EvidenceTypeLogGroup, EvidenceTypeAuditLogTrail)
	}
	var scope *core.RecordScope
	if p.subscriptionID != "" {
		scope = &core.RecordScope{Account: p.subscriptionID}
	}
	now := p.now()

	var records []core.EvidenceRecord
	if wantLog {
		logRecs, err := p.collectLogGroups(ctx, now, scope)
		if err != nil {
			return nil, err
		}
		records = append(records, logRecs...)
	}
	if wantAudit {
		auditRecs, err := p.collectAuditTrails(ctx, now, scope)
		if err != nil {
			return nil, err
		}
		records = append(records, auditRecs...)
	}
	return records, nil
}

// collectLogGroups lists Log Analytics workspaces and emits one log_group record
// each, sorted by ID.
func (p *Plugin) collectLogGroups(ctx context.Context, now time.Time, scope *core.RecordScope) ([]core.EvidenceRecord, error) {
	workspaces, err := p.api.ListWorkspaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.monitor: list log analytics workspaces: %w", err)
	}
	records := make([]core.EvidenceRecord, 0, len(workspaces))
	for _, ws := range workspaces {
		if ws == nil {
			continue
		}
		days := retentionDays(ws)
		payload := logGroupPayload{
			ID:            deref(ws.ID),
			Name:          deref(ws.Name),
			Provider:      "azure",
			RetentionSet:  days > 0,
			RetentionDays: days,
			Location:      deref(ws.Location),
			SKU:           workspaceSKU(ws),
			ResourceGroup: resourceGroupFromID(deref(ws.ID)),
		}
		rec, err := record(EvidenceTypeLogGroup, payload, payload.ID, now, scope)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// collectAuditTrails emits exactly one audit_log_trail record for the
// subscription's always-on Activity Log, enriched with its diagnostic-settings
// export configuration.
func (p *Plugin) collectAuditTrails(ctx context.Context, now time.Time, scope *core.RecordScope) ([]core.EvidenceRecord, error) {
	settings, err := p.api.ListSubscriptionDiagnosticSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.monitor: list subscription diagnostic settings: %w", err)
	}
	exported, categories, workspaceID, storageID := summarizeDiagnosticSettings(settings)
	payload := auditTrailPayload{
		ID:                          fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Insights/activityLog", p.subscriptionID),
		Name:                        "Azure Activity Log",
		Provider:                    "azure",
		IsEnabled:                   true,  // Activity Log is always-on; cannot be disabled.
		IsMultiRegion:               true,  // Subscription-wide across all regions.
		LogFileValidationEnabled:    true,  // Platform Activity Log is append-only / immutable to users.
		KMSEncrypted:                false, // Native retention uses Microsoft-managed keys (see package doc).
		Exported:                    exported,
		DiagnosticSettingCount:      len(settings),
		EnabledCategories:           categories,
		DestinationWorkspaceID:      workspaceID,
		DestinationStorageAccountID: storageID,
	}
	rec, err := record(EvidenceTypeAuditLogTrail, payload, payload.ID, now, scope)
	if err != nil {
		return nil, err
	}
	return []core.EvidenceRecord{rec}, nil
}

// record marshals a payload into an EvidenceRecord. id is the stable sort key.
func record(typeID string, payload any, id string, now time.Time, scope *core.RecordScope) (core.EvidenceRecord, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return core.EvidenceRecord{}, fmt.Errorf("azure.monitor: marshal %s payload for %q: %w", typeID, id, err)
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

// retentionDays returns the workspace's configured retention in days, or 0 when
// unset (never-expire / not configured).
func retentionDays(ws *armoi.Workspace) int {
	if ws == nil || ws.Properties == nil || ws.Properties.RetentionInDays == nil {
		return 0
	}
	d := int(*ws.Properties.RetentionInDays)
	if d < 0 {
		return 0
	}
	return d
}

// workspaceSKU returns the workspace pricing-tier name, or "" when unset.
func workspaceSKU(ws *armoi.Workspace) string {
	if ws == nil || ws.Properties == nil || ws.Properties.SKU == nil || ws.Properties.SKU.Name == nil {
		return ""
	}
	return string(*ws.Properties.SKU.Name)
}

// summarizeDiagnosticSettings reduces the subscription's diagnostic settings to
// the Activity Log export posture: whether at least one enabled log category is
// routed to a destination, the union of enabled category names, and the first
// workspace / storage-account destination seen.
func summarizeDiagnosticSettings(settings []*armmonitor.DiagnosticSettingsResource) (exported bool, categories []string, workspaceID, storageID string) {
	seen := map[string]bool{}
	for _, ds := range settings {
		if ds == nil || ds.Properties == nil {
			continue
		}
		props := ds.Properties
		hasEnabledLog := false
		for _, cat := range enabledLogCategories(props.Logs) {
			hasEnabledLog = true
			if cat != "" && !seen[cat] {
				seen[cat] = true
				categories = append(categories, cat)
			}
		}
		if !hasEnabledLog {
			continue
		}
		// A routed, enabled diagnostic setting means the Activity Log is exported.
		if dest := deref(props.WorkspaceID); dest != "" {
			exported = true
			if workspaceID == "" {
				workspaceID = dest
			}
		}
		if dest := deref(props.StorageAccountID); dest != "" {
			exported = true
			if storageID == "" {
				storageID = dest
			}
		}
		if hasStreamingDestination(props) {
			exported = true
		}
	}
	sort.Strings(categories)
	return exported, categories, workspaceID, storageID
}

// enabledLogCategories returns the category name of every enabled log setting
// (an empty string for an enabled setting that carries neither a category nor a
// category group). An empty result means no log category is enabled.
func enabledLogCategories(logs []*armmonitor.LogSettings) []string {
	out := make([]string, 0, len(logs))
	for _, l := range logs {
		if l == nil || l.Enabled == nil || !*l.Enabled {
			continue
		}
		out = append(out, logCategory(l))
	}
	return out
}

// hasStreamingDestination reports whether the setting routes to an event hub or
// service bus (the non-storage/workspace destinations that still count as export).
func hasStreamingDestination(props *armmonitor.DiagnosticSettings) bool {
	return deref(props.EventHubName) != "" ||
		deref(props.EventHubAuthorizationRuleID) != "" ||
		deref(props.ServiceBusRuleID) != ""
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

// --- real Azure adapter ---

// realMonitor is the production implementation of API. It wraps the Log Analytics
// WorkspacesClient and the Azure Monitor DiagnosticSettingsClient.
type realMonitor struct {
	workspaces     *armoi.WorkspacesClient
	diagnostics    *armmonitor.DiagnosticSettingsClient
	subscriptionID string
}

// newRealMonitor builds the SDK clients. opts is nil in production; tests pass a
// *arm.ClientOptions pointing the clients at an httptest server.
func newRealMonitor(subscriptionID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*realMonitor, error) {
	workspaces, err := armoi.NewWorkspacesClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.monitor: workspaces client: %w", err)
	}
	diagnostics, err := armmonitor.NewDiagnosticSettingsClient(cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.monitor: diagnostic settings client: %w", err)
	}
	return &realMonitor{workspaces: workspaces, diagnostics: diagnostics, subscriptionID: subscriptionID}, nil
}

func (r *realMonitor) ListWorkspaces(ctx context.Context) ([]*armoi.Workspace, error) {
	var out []*armoi.Workspace
	pager := r.workspaces.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

func (r *realMonitor) ListSubscriptionDiagnosticSettings(ctx context.Context) ([]*armmonitor.DiagnosticSettingsResource, error) {
	resourceURI := fmt.Sprintf("/subscriptions/%s", r.subscriptionID)
	var out []*armmonitor.DiagnosticSettingsResource
	pager := r.diagnostics.NewListPager(resourceURI, nil)
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
