// Package storage implements the gcp.storage source plugin: lists all
// GCS buckets in a project and emits a gcs_bucket evidence record per
// bucket so SOC 2 storage-hardening policies (uniform-bucket-level
// access, versioning, retention, public access prevention) can check
// configuration.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect
// calls. N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by
// internal/sources/aws/iam — the real GCS adapter satisfies it, and
// unit tests inject an in-memory fake.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	gcs "cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the single evidence type this plugin emits today.
const EvidenceTypeID = "gcs_bucket"

// SourceID is the registered ID for the gcp.storage plugin instance.
const SourceID = "gcp.storage"

// API is the subset of the GCS client this plugin uses. Defining it as
// an interface lets tests inject a fake without hitting GCS; the real
// adapter wraps *storage.Client.
type API interface {
	ListBuckets(ctx context.Context, project string) ([]*gcs.BucketAttrs, error)
}

// Plugin is the in-process gcp.storage source.
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

// New constructs a Plugin around an explicit API implementation.
// Callers using the real GCS SDK should use NewFromGCP.
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

// NewFromGCP constructs a Plugin backed by the real GCS SDK using
// Application Default Credentials. M6 does not exercise this path
// under integration tests.
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	client, err := gcs.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.storage: new client: %w", err)
	}
	return New(Options{
		API:       &realGCS{client: client},
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

// bucketPayload is the shape of the JSON payload inside each
// gcs_bucket record.
type bucketPayload struct {
	Name                     string    `json:"name"`
	Location                 string    `json:"location"`
	StorageClass             string    `json:"storage_class"`
	UniformBucketLevelAccess bool      `json:"uniform_bucket_level_access"`
	PublicAccessPrevention   string    `json:"public_access_prevention"`
	VersioningEnabled        bool      `json:"versioning_enabled"`
	RequesterPays            bool      `json:"requester_pays"`
	Created                  time.Time `json:"created_at,omitempty"`
}

// Collect lists buckets in the configured project and emits one
// gcs_bucket record per bucket. Records are sorted by ID (bucket name)
// before return so envelope bytes are stable across runs against
// stable project state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.storage: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	buckets, err := p.api.ListBuckets(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.storage: list buckets: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(buckets))
	for _, b := range buckets {
		if b == nil {
			continue
		}
		payload := bucketPayload{
			Name:                     b.Name,
			Location:                 b.Location,
			StorageClass:             b.StorageClass,
			UniformBucketLevelAccess: b.UniformBucketLevelAccess.Enabled,
			PublicAccessPrevention:   b.PublicAccessPrevention.String(),
			VersioningEnabled:        b.VersioningEnabled,
			RequesterPays:            b.RequesterPays,
			Created:                  b.Created,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gcp.storage: marshal bucket payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          b.Name,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// realGCS is the production implementation of API. It wraps
// *storage.Client and iterates buckets via the GCS Buckets() iterator.
type realGCS struct {
	client *gcs.Client
}

func (r *realGCS) ListBuckets(ctx context.Context, project string) ([]*gcs.BucketAttrs, error) {
	it := r.client.Buckets(ctx, project)
	return drainBucketIterator(it.Next)
}

// drainBucketIterator pumps a GCS bucket iterator until iterator.Done.
// Extracted so the loop is testable without a live *storage.Client.
func drainBucketIterator(next func() (*gcs.BucketAttrs, error)) ([]*gcs.BucketAttrs, error) {
	var out []*gcs.BucketAttrs
	for {
		attrs, err := next()
		if errors.Is(err, iterator.Done) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, attrs)
	}
}

var _ core.SourcePlugin = (*Plugin)(nil)
