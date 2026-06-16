// Package asset implements the gcp.asset source plugin: it emits a single
// config_change_tracking evidence record describing whether a GCP project
// has resource-change tracking configured — the same cloud-neutral type
// aws.config emits, so the config-recording policies (SOC2 CC7.1, ISO
// A.8.9) span both clouds with zero changes (Invariant #4,
// substitutability).
//
// Modeling choice — Cloud Asset Inventory FEEDS, not the always-on
// inventory. GCP's Cloud Asset Inventory keeps current state plus ~35
// days of history for every project unconditionally; that is the analog
// of AWS's default service-state APIs, NOT of an AWS Config recorder. A
// Cloud Asset *feed* is the deliberately-configured, opt-in artifact that
// publishes real-time configuration-change events to Pub/Sub — the same
// act of configuration as enabling an AWS Config recorder. So a feed
// existing is the only GCP signal that can honestly be false (a fresh
// project has none), which is exactly what makes it the right
// is_recording signal: mapping is_recording to the always-on inventory
// would make the policy a tautology that can never fail.
//
// Cardinality — one record per project (a project-level singleton), like
// aws.config (one recorder per account). Cross-vendor substitutability
// requires both sources to emit the same shape and cardinality so one
// `all`/`none` policy behaves identically on either cloud. Feeds are
// reduced to a single record: is_recording ← any feed exists;
// all_resource_types ← any feed is unrestricted by asset type.
//
// Field mapping (the policies read is_recording + all_resource_types, and
// the evaluator errors on a referenced-but-absent field, so both — plus
// the required id/name — are always emitted):
//   - is_recording ← len(feeds) > 0.
//   - all_resource_types ← at least one feed places no asset-type
//     restriction (empty AssetTypes, or a catch-all wildcard) — the
//     analog of AWS Config's allSupported. A type-filtered feed tracks a
//     subset, so reports false.
//   - id ← projects/{project}/configChangeTracking (synthetic, stable);
//     name ← the project id. We deliberately do NOT derive id from a
//     feed name: GCP normalizes Feed.Name to projects/{NUMBER}/feeds/{id}
//     and there can be several feeds, neither of which suits a singleton.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect calls.
//
// Auth: Application Default Credentials. Cloud Asset Inventory exposes no
// read-only OAuth scope, so the plugin uses cloudasset.CloudPlatformScope
// and relies on the IAM layer for least privilege — grant
// roles/cloudasset.viewer (cloudasset.feeds.list). See
// docs/configuration.md §GCP.
package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	cloudasset "google.golang.org/api/cloudasset/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "config_change_tracking"

// SourceID is the registered ID for the gcp.asset plugin instance.
const SourceID = "gcp.asset"

// API is the subset of the Cloud Asset Inventory client this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting
// GCP; the real adapter wraps *cloudasset.Service.
type API interface {
	// ListFeeds returns every asset feed configured in the project.
	ListFeeds(ctx context.Context, project string) ([]*cloudasset.Feed, error)
}

// Plugin is the in-process gcp.asset source.
type Plugin struct {
	api       API
	projectID string
	now       func() time.Time
}

// Options is the constructor input.
type Options struct {
	API       API
	ProjectID string
	// Now is injected so tests can produce deterministic CollectedAt
	// values. Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation. Callers
// using the real GCP SDK should use NewFromGCP.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:       opts.API,
		projectID: opts.ProjectID,
		now:       now,
	}
}

// NewFromGCP constructs a Plugin backed by the real Cloud Asset Inventory
// API using Application Default Credentials. Cloud Asset Inventory has no
// read-only scope; restrict access at the IAM layer with
// roles/cloudasset.viewer.
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	svc, err := cloudasset.NewService(ctx, option.WithScopes(cloudasset.CloudPlatformScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.asset: new service: %w", err)
	}
	return New(Options{
		API:       &realAsset{svc: svc},
		ProjectID: projectID,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op for this plugin — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// trackingPayload is the cross-vendor config_change_tracking shape (see
// internal/evidence_types/schemas/config_change_tracking.v1.json). The
// required fields (id, name, is_recording) plus all_resource_types (read
// by the coverage policies) are always emitted — the evaluator errors on
// any payload that omits a field a policy references.
type trackingPayload struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Provider         string `json:"provider"`
	IsRecording      bool   `json:"is_recording"`
	AllResourceTypes bool   `json:"all_resource_types"`
	// GCP-specific extra (additionalProperties): the number of asset feeds
	// configured, making the is_recording derivation auditable.
	FeedCount int `json:"feed_count"`
}

// Collect returns the single config_change_tracking record for the
// configured project.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.asset: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	feeds, err := p.api.ListFeeds(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.asset: list feeds: %w", err)
	}
	payload := buildPayload(p.projectID, feeds)
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("gcp.asset: marshal payload: %w", err)
	}
	return []core.EvidenceRecord{{
		Type:        EvidenceTypeID,
		ID:          payload.ID,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: p.now(),
	}}, nil
}

// buildPayload reduces a project's asset feeds into the single
// cross-vendor config_change_tracking shape. See the package doc for the
// mapping rationale.
func buildPayload(project string, feeds []*cloudasset.Feed) trackingPayload {
	count := 0
	allTypes := false
	for _, f := range feeds {
		if f == nil {
			continue
		}
		count++
		if feedCoversAllTypes(f) {
			allTypes = true
		}
	}
	return trackingPayload{
		ID:               fmt.Sprintf("projects/%s/configChangeTracking", project),
		Name:             project,
		Provider:         "gcp",
		IsRecording:      count > 0,
		AllResourceTypes: allTypes,
		FeedCount:        count,
	}
}

// feedCoversAllTypes reports whether a feed places no asset-type
// restriction: an empty AssetTypes list, or a catch-all wildcard entry
// (".*" / "*"). This is the GCP analog of AWS Config's allSupported. A
// feed listing specific asset types tracks only that subset → false.
func feedCoversAllTypes(f *cloudasset.Feed) bool {
	if len(f.AssetTypes) == 0 {
		return true
	}
	for _, t := range f.AssetTypes {
		switch strings.TrimSpace(t) {
		case ".*", "*":
			return true
		}
	}
	return false
}

// realAsset is the production implementation of API. It wraps
// *cloudasset.Service. Feeds.List is not paginated — a single call
// returns every feed.
type realAsset struct {
	svc *cloudasset.Service
}

func (r *realAsset) ListFeeds(ctx context.Context, project string) ([]*cloudasset.Feed, error) {
	resp, err := r.svc.Feeds.List("projects/" + project).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp.Feeds, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
