// Package policy implements the azure.policy source plugin: it emits a single
// config_change_tracking evidence record describing whether an Azure
// subscription has resource-configuration tracking configured — the same
// cloud-neutral type aws.config and gcp.asset emit, so the config-recording
// policies (SOC2 CC7.1, ISO A.8.9) span all three clouds with zero policy
// changes (Invariant #4, substitutability).
//
// Modeling choice — Azure Policy ASSIGNMENTS, not an always-on service.
// Azure has no literal "configuration recorder" on/off toggle like AWS Config.
// What plays the equivalent role is Azure Policy: assigning a policy (or
// initiative) makes Azure continuously evaluate and record the configuration
// compliance state of the subscription's resources. A policy *assignment* is
// the deliberately-configured, opt-in artifact — the act of configuration that
// mirrors enabling an AWS Config recorder or creating a GCP Cloud Asset feed.
// So an assignment existing is the only Azure signal that can honestly be false
// (a fresh subscription has none), which is exactly what makes it the right
// is_recording signal: mapping is_recording to an always-on facility (Resource
// Graph, Activity Log) would make the policy a tautology that can never fail.
//
// Cardinality — one record per subscription (a subscription-level singleton),
// like aws.config (one recorder per account) and gcp.asset (one per project).
// Cross-vendor substitutability requires every source to emit the same shape
// and cardinality so one all/none policy behaves identically on any cloud.
// Assignments are reduced to a single record.
//
// Field mapping (the policies read is_recording + all_resource_types, and the
// evaluator errors on a referenced-but-absent field, so both — plus the
// required id/name — are always emitted):
//   - is_recording ← len(assignments) > 0 (mirrors gcp.asset's len(feeds) > 0).
//   - all_resource_types ← at least one assignment is scoped at the
//     subscription root (/subscriptions/{id}). Azure Policy has no per-
//     assignment resource-type list (the analog of AWS Config's allSupported
//     or a GCP feed's empty AssetTypes), so coverage BREADTH is approximated by
//     assignment SCOPE: a subscription-scoped assignment evaluates resources
//     across the whole subscription, whereas resource-group-scoped assignments
//     cover only a subset. This is the honest available signal — not the AWS
//     literal "records all supported types". A subscription whose only
//     assignments are RG-scoped honestly reports false.
//   - id ← subscriptions/{subscriptionID}/configChangeTracking (synthetic,
//     stable); name ← the subscription id. We deliberately do NOT derive id or
//     name from an assignment (assignments are mutable and there can be many,
//     and an assignment id/scope is a resource identity we keep vault-side).
//
// Compliance-STATE enrichment (counts of compliant/non-compliant resources via
// armpolicyinsights) is a deliberate future enhancement: it backs no
// config_change_tracking schema field, and the assignment list alone carries
// every load-bearing signal. Keeping to one SDK (armpolicy) avoids a pre-1.0
// dependency for non-load-bearing data.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md §The plugin
// contract), the plugin caches nothing across Collect calls.
//
// Auth: the shared DefaultAzureCredential (azcommon). Reading policy
// assignments needs Microsoft.Authorization/policyAssignments/read, covered by
// the built-in subscription-level Reader role. See docs/configuration.md
// §Azure.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armpolicy "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "config_change_tracking"

// SourceID is the registered ID for the azure.policy plugin instance.
const SourceID = "azure.policy"

// API is the subset of the Azure Policy management plane this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting Azure;
// the real adapter wraps the armpolicy AssignmentsClient.
type API interface {
	// ListAssignments returns every policy assignment that applies to the
	// subscription (subscription-scoped plus those of contained resource
	// groups/resources).
	ListAssignments(ctx context.Context) ([]*armpolicy.Assignment, error)
}

// Plugin is the in-process azure.policy source.
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

// NewFromAzure constructs a Plugin backed by the real armpolicy SDK using the
// given credential (a DefaultAzureCredential) scoped to cfg.SubscriptionID.
func NewFromAzure(cred azcore.TokenCredential, cfg azcommon.Config) (*Plugin, error) {
	adapter, err := newRealPolicy(cfg.SubscriptionID, cred, nil)
	if err != nil {
		return nil, err
	}
	return New(Options{API: adapter, SubscriptionID: cfg.SubscriptionID}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op for this plugin — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// trackingPayload is the cross-vendor config_change_tracking shape (see
// internal/evidence_types/schemas/config_change_tracking.v1.json). The required
// fields (id, name, is_recording) plus all_resource_types (read by the coverage
// policies) are always emitted — the evaluator errors on any payload that omits
// a field a policy references. The trailing count fields are auditable Azure
// extras (additionalProperties) that make the boolean derivations checkable
// from the evidence alone; all are pure counts (no resource identities).
type trackingPayload struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Provider         string `json:"provider"`
	IsRecording      bool   `json:"is_recording"`
	AllResourceTypes bool   `json:"all_resource_types"`

	// AssignmentCount makes is_recording (count > 0) auditable.
	AssignmentCount int `json:"assignment_count"`
	// EnforcedCount is the number of assignments in enforcing mode (Default),
	// a governance signal distinct from audit-only (DoNotEnforce) assignments.
	EnforcedCount int `json:"enforced_count"`
	// SubscriptionScopedCount makes all_resource_types (> 0) auditable.
	SubscriptionScopedCount int `json:"subscription_scoped_count"`
}

// Collect returns the single config_change_tracking record for the configured
// subscription.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("azure.policy: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	assignments, err := p.api.ListAssignments(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure.policy: list assignments: %w", err)
	}
	payload := buildPayload(p.subscriptionID, assignments)
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("azure.policy: marshal payload: %w", err)
	}
	var scope *core.RecordScope
	if p.subscriptionID != "" {
		scope = &core.RecordScope{Account: p.subscriptionID}
	}
	return []core.EvidenceRecord{{
		Type:        EvidenceTypeID,
		ID:          payload.ID,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: p.now(),
		Scope:       scope,
	}}, nil
}

// buildPayload reduces a subscription's policy assignments into the single
// cross-vendor config_change_tracking shape. See the package doc for the
// mapping rationale.
func buildPayload(subscriptionID string, assignments []*armpolicy.Assignment) trackingPayload {
	wantScope := strings.ToLower("/subscriptions/" + subscriptionID)
	count := 0
	enforced := 0
	subScoped := 0
	for _, a := range assignments {
		if a == nil {
			continue
		}
		count++
		if assignmentEnforced(a) {
			enforced++
		}
		if assignmentSubscriptionScoped(a, wantScope) {
			subScoped++
		}
	}
	return trackingPayload{
		ID:                      fmt.Sprintf("subscriptions/%s/configChangeTracking", subscriptionID),
		Name:                    subscriptionID,
		Provider:                "azure",
		IsRecording:             count > 0,
		AllResourceTypes:        subScoped > 0,
		AssignmentCount:         count,
		EnforcedCount:           enforced,
		SubscriptionScopedCount: subScoped,
	}
}

// --- pure mapping helpers (unit-tested via table tests) ---

// assignmentEnforced reports whether an assignment enforces its policy effect.
// Azure's default enforcement mode is "Default" (enforced), so a nil mode
// counts as enforced; only an explicit DoNotEnforce (audit-only) or Enroll
// (staged) mode is not enforcing.
func assignmentEnforced(a *armpolicy.Assignment) bool {
	if a.Properties == nil || a.Properties.EnforcementMode == nil {
		return true
	}
	return *a.Properties.EnforcementMode == armpolicy.EnforcementModeDefault
}

// assignmentSubscriptionScoped reports whether an assignment is scoped at the
// subscription root (the breadth analog of AWS Config's allSupported). wantScope
// is the normalized "/subscriptions/{id}" (lowercased). nil scope → false.
func assignmentSubscriptionScoped(a *armpolicy.Assignment, wantScope string) bool {
	if a.Properties == nil || a.Properties.Scope == nil {
		return false
	}
	got := strings.ToLower(strings.TrimRight(*a.Properties.Scope, "/"))
	return got == wantScope
}

// --- real Azure adapter ---

// realPolicy is the production implementation of API. It wraps the armpolicy
// AssignmentsClient, listed subscription-wide.
type realPolicy struct {
	client *armpolicy.AssignmentsClient
}

// newRealPolicy builds the SDK client. opts is nil in production; tests pass a
// *arm.ClientOptions pointing the client at an httptest server.
func newRealPolicy(subscriptionID string, cred azcore.TokenCredential, opts *arm.ClientOptions) (*realPolicy, error) {
	client, err := armpolicy.NewAssignmentsClient(subscriptionID, cred, opts)
	if err != nil {
		return nil, fmt.Errorf("azure.policy: assignments client: %w", err)
	}
	return &realPolicy{client: client}, nil
}

func (r *realPolicy) ListAssignments(ctx context.Context) ([]*armpolicy.Assignment, error) {
	var out []*armpolicy.Assignment
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
