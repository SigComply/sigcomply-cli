// Package logging implements the gcp.logging source plugin: lists Cloud
// Logging log buckets in one GCP project and emits one log_group evidence
// record per bucket, carrying the retention and encryption attributes the
// log-retention and log-encryption policies evaluate — the same
// cloud-neutral type aws.cloudwatch emits, so those policies span both
// clouds with zero changes (Invariant #4, substitutability).
//
// Retention mapping: unlike AWS (where a log group can be set to
// "never expire", RetentionInDays == nil → retention_set=false), every
// GCP log bucket has a finite retention period (RetentionDays — default
// 30 for _Default, fixed 400 for _Required, operator-configurable
// otherwise). So retention_set ← RetentionDays > 0 and retention_days ←
// RetentionDays; the shipped policies compare retention_days against
// their minimum (SOC2 CC7.1: ≥90, ISO A.8.15: ≥365). A bucket left at the
// 30-day default therefore honestly fails those policies.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Auth: Application Default Credentials with the logging.read scope
// (restrict access at the IAM layer with roles/logging.viewer, which
// grants logging.buckets.list / .get). See docs/configuration.md §GCP.
// The real adapter wraps *logging.Service and lists buckets across all
// locations (the "-" wildcard); unit tests inject an in-memory fake via
// the API interface seam.
package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	logging "google.golang.org/api/logging/v2"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "log_group"

// SourceID is the registered ID for the gcp.logging plugin instance.
const SourceID = "gcp.logging"

// API is the subset of the Cloud Logging client this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting
// GCP; the real adapter wraps *logging.Service and pages transparently.
type API interface {
	// ListLogBuckets returns every log bucket in the project across all
	// locations, flattened.
	ListLogBuckets(ctx context.Context, project string) ([]*logging.LogBucket, error)
}

// Plugin is the in-process gcp.logging source.
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

// NewFromGCP constructs a Plugin backed by the real Cloud Logging API
// using Application Default Credentials with the logging.read scope
// (restrict at the IAM layer with roles/logging.viewer).
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	svc, err := logging.NewService(ctx, option.WithScopes(logging.LoggingReadScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.logging: new service: %w", err)
	}
	return New(Options{
		API:       &realLogging{svc: svc},
		ProjectID: projectID,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op for this plugin — configuration is fixed at New.
// Preserved for symmetry with other plugins.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// logGroupPayload is the cross-vendor log_group shape (see
// internal/evidence_types/schemas/log_group.v1.json). The required fields
// (id, name, retention_set, retention_days) are always emitted — the
// evaluator errors on any payload that omits a field a policy references.
type logGroupPayload struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Provider      string `json:"provider"`
	RetentionSet  bool   `json:"retention_set"`
	RetentionDays int    `json:"retention_days"`
	KMSEncrypted  bool   `json:"kms_encrypted"`
	// GCP-specific extras (additionalProperties).
	Location string `json:"location,omitempty"`
	// Locked is the retention-lock / immutability signal (no shipped
	// policy reads it yet; emitted for auditability).
	Locked         bool   `json:"locked"`
	LifecycleState string `json:"lifecycle_state,omitempty"`
	KMSKeyName     string `json:"kms_key_name,omitempty"`
}

// Collect lists log buckets in the configured project and returns one
// log_group record per bucket. Records are sorted by ID before return so
// envelope bytes are stable across runs against stable project state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.logging: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	buckets, err := p.api.ListLogBuckets(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.logging: list log buckets: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(buckets))
	for _, b := range buckets {
		if b == nil {
			continue
		}
		payload := buildPayload(b)
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gcp.logging: marshal payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          payload.ID,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// buildPayload maps one log bucket into the cross-vendor log_group shape.
func buildPayload(b *logging.LogBucket) logGroupPayload {
	keyName := cmekKeyName(b)
	return logGroupPayload{
		ID:             b.Name,
		Name:           shortName(b.Name),
		Provider:       "gcp",
		RetentionSet:   b.RetentionDays > 0,
		RetentionDays:  int(b.RetentionDays),
		KMSEncrypted:   keyName != "",
		Location:       locationFromName(b.Name),
		Locked:         b.Locked,
		LifecycleState: b.LifecycleState,
		KMSKeyName:     keyName,
	}
}

// cmekKeyName returns the customer-managed KMS key configured on the
// bucket, or "" when Google-managed default encryption is in use.
func cmekKeyName(b *logging.LogBucket) string {
	if b.CmekSettings != nil {
		return b.CmekSettings.KmsKeyName
	}
	return ""
}

// shortName returns the trailing bucket id from a full resource name
// (projects/p/locations/global/buckets/_Default → _Default).
func shortName(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// locationFromName extracts the location segment from a bucket resource
// name (projects/p/locations/us-east1/buckets/b → us-east1), or "" when
// the name does not carry the expected shape.
func locationFromName(name string) string {
	const marker = "/locations/"
	i := strings.Index(name, marker)
	if i < 0 {
		return ""
	}
	rest := name[i+len(marker):]
	if j := strings.Index(rest, "/"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// realLogging is the production implementation of API. It wraps
// *logging.Service and pages buckets.list across all locations (the "-"
// wildcard).
type realLogging struct {
	svc *logging.Service
}

func (r *realLogging) ListLogBuckets(ctx context.Context, project string) ([]*logging.LogBucket, error) {
	var out []*logging.LogBucket
	parent := fmt.Sprintf("projects/%s/locations/-", project)
	err := r.svc.Projects.Locations.Buckets.List(parent).Pages(ctx, func(resp *logging.ListBucketsResponse) error {
		out = append(out, resp.Buckets...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
