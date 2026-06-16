// Package gke implements the gcp.gke source plugin: lists GKE (Google
// Kubernetes Engine) clusters across every location in one GCP project
// and emits one kubernetes_cluster evidence record per cluster, carrying
// the secrets-encryption, logging, and network-isolation attributes the
// kubernetes_cluster policies evaluate — the same cloud-neutral type
// aws.eks emits, so those policies span both clouds with zero changes
// (Invariant #4, substitutability).
//
// One list call covers the project: the Projects.Locations.Clusters.List
// method accepts the all-locations wildcard (locations/-), returning both
// regional and zonal clusters in a single, non-paginated response. (The
// older Projects.Zones.Clusters.List path is deprecated; this plugin does
// not use it.)
//
// Field mapping (the two required booleans are emitted unconditionally —
// the evaluator errors on any payload that omits a field a policy clause
// references):
//   - secrets_encryption_enabled ← DatabaseEncryption.State == "ENCRYPTED".
//     This is GKE Application-layer Secrets Encryption: Kubernetes Secret
//     objects in etcd are envelope-encrypted with a customer Cloud KMS key.
//     It is NOT etcd-at-rest disk encryption, which Google always applies
//     with Google-managed keys and which cannot be disabled — so mapping
//     the customer-KMS feature (the thing an auditor judges) is the honest
//     translation, matching aws.eks's secrets-envelope-encryption mapping.
//     A nil DatabaseEncryption (feature never configured) → false. The raw
//     desired State and CurrentState ride in extras for auditability.
//   - logging_enabled ← the cluster has control-plane logging on: the
//     newer LoggingConfig.ComponentConfig.EnableComponents is non-empty,
//     or (legacy fallback) LoggingService is set and not "none".
//   - is_private_endpoint ← PrivateClusterConfig.EnablePrivateEndpoint (the
//     control-plane API endpoint uses the master's internal IP only).
//   - node_auto_upgrade_enabled ← every node pool has node auto-upgrade on
//     (and at least one node pool exists) — the conservative "all nodes
//     are kept patched" semantics; a cluster with any manual-upgrade pool
//     reports false.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Auth: Application Default Credentials with the container read-only scope;
// restrict access at the IAM layer with roles/container.viewer (grants
// container.clusters.list). See docs/configuration.md §GCP. The real
// adapter wraps *container.Service and unit tests inject an in-memory fake
// via the API interface seam.
package gke

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	container "google.golang.org/api/container/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "kubernetes_cluster"

// SourceID is the registered ID for the gcp.gke plugin instance.
const SourceID = "gcp.gke"

// encryptedState is the DatabaseEncryption.State value that means
// application-layer Secrets encryption with a customer KMS key is on.
const encryptedState = "ENCRYPTED"

// loggingDisabled is the legacy LoggingService value that means
// control-plane logging is off.
const loggingDisabled = "none"

// API is the subset of the GKE client this plugin uses. Defining it as an
// interface lets tests inject a fake without hitting GCP; the real adapter
// wraps *container.Service and lists clusters across all locations in one
// call.
type API interface {
	// ListClusters returns every cluster across all zones and regions in the
	// project (the locations/- wildcard), in one non-paginated response.
	ListClusters(ctx context.Context, project string) ([]*container.Cluster, error)
}

// Plugin is the in-process gcp.gke source.
type Plugin struct {
	api       API
	projectID string
	now       func() time.Time
}

// Options is the constructor input.
type Options struct {
	API       API
	ProjectID string
	// Now is injected so tests can produce deterministic CollectedAt values.
	// Production callers leave it nil → time.Now().UTC().
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

// NewFromGCP constructs a Plugin backed by the real GKE API using
// Application Default Credentials with the container read-only scope.
// Restrict access at the IAM layer with roles/container.viewer.
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	svc, err := container.NewService(ctx, option.WithScopes(container.ContainerReadOnlyScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.gke: new service: %w", err)
	}
	return New(Options{
		API:       &realGKE{svc: svc},
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

// clusterPayload is the cross-vendor kubernetes_cluster shape (see
// internal/evidence_types/schemas/kubernetes_cluster.v1.json). The four
// required fields plus the two cross-vendor optionals (is_private_endpoint,
// node_auto_upgrade_enabled) are always emitted — the evaluator errors on
// any payload that omits a field a policy clause references.
type clusterPayload struct {
	ID                       string `json:"id"`
	Name                     string `json:"name"`
	Provider                 string `json:"provider"`
	Version                  string `json:"version,omitempty"`
	SecretsEncryptionEnabled bool   `json:"secrets_encryption_enabled"`
	LoggingEnabled           bool   `json:"logging_enabled"`
	IsPrivateEndpoint        bool   `json:"is_private_endpoint"`
	NodeAutoUpgradeEnabled   bool   `json:"node_auto_upgrade_enabled"`
	// GCP-specific extras (additionalProperties). location identifies the
	// cluster; status surfaces operational state; kms_key_name and
	// encryption_state make the secrets_encryption_enabled derivation
	// auditable (encryption_state is the desired State, current_state the
	// output-only actual state so a transient PENDING/ERROR is visible);
	// release_channel records the upgrade track.
	Location        string `json:"location,omitempty"`
	Status          string `json:"status,omitempty"`
	KMSKeyName      string `json:"kms_key_name,omitempty"`
	EncryptionState string `json:"encryption_state,omitempty"`
	CurrentState    string `json:"current_encryption_state,omitempty"`
	ReleaseChannel  string `json:"release_channel,omitempty"`
}

// Collect lists GKE clusters in the configured project and returns one
// kubernetes_cluster record per cluster. Records are sorted by ID before
// return so envelope bytes are stable across runs against stable project
// state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.gke: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	clusters, err := p.api.ListClusters(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.gke: list clusters: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(clusters))
	for _, c := range clusters {
		if c == nil {
			continue
		}
		payload := buildPayload(c)
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gcp.gke: marshal payload: %w", err)
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

// buildPayload maps one GKE cluster into the cross-vendor
// kubernetes_cluster shape.
func buildPayload(c *container.Cluster) clusterPayload {
	enabled, keyName, state, currentState := secretsEncryption(c)
	id := c.SelfLink
	if id == "" {
		// SelfLink is always set by the API; fall back to name only so a
		// hand-built fake without a SelfLink still yields a stable ID.
		id = c.Name
	}
	return clusterPayload{
		ID:                       id,
		Name:                     c.Name,
		Provider:                 "gcp",
		Version:                  c.CurrentMasterVersion,
		SecretsEncryptionEnabled: enabled,
		LoggingEnabled:           loggingEnabled(c),
		IsPrivateEndpoint:        privateEndpoint(c),
		NodeAutoUpgradeEnabled:   nodeAutoUpgradeEnabled(c),
		Location:                 c.Location,
		Status:                   c.Status,
		KMSKeyName:               keyName,
		EncryptionState:          state,
		CurrentState:             currentState,
		ReleaseChannel:           releaseChannel(c),
	}
}

// secretsEncryption reports whether application-layer Secrets encryption
// with a customer KMS key is enabled, along with the key name and the raw
// desired/actual states for auditability.
func secretsEncryption(c *container.Cluster) (enabled bool, keyName, state, currentState string) {
	if c.DatabaseEncryption == nil {
		return false, "", "", ""
	}
	de := c.DatabaseEncryption
	return de.State == encryptedState, de.KeyName, de.State, de.CurrentState
}

// loggingEnabled reports whether control-plane logging is on, preferring
// the granular LoggingConfig and falling back to the legacy
// LoggingService string.
func loggingEnabled(c *container.Cluster) bool {
	if c.LoggingConfig != nil && c.LoggingConfig.ComponentConfig != nil &&
		len(c.LoggingConfig.ComponentConfig.EnableComponents) > 0 {
		return true
	}
	return c.LoggingService != "" && c.LoggingService != loggingDisabled
}

// privateEndpoint reports whether the cluster's control-plane API endpoint
// is private (internal IP only).
func privateEndpoint(c *container.Cluster) bool {
	return c.PrivateClusterConfig != nil && c.PrivateClusterConfig.EnablePrivateEndpoint
}

// nodeAutoUpgradeEnabled reports whether every node pool has node
// auto-upgrade enabled (and at least one node pool exists) — the
// conservative "all nodes are kept patched" reading.
func nodeAutoUpgradeEnabled(c *container.Cluster) bool {
	if len(c.NodePools) == 0 {
		return false
	}
	for _, np := range c.NodePools {
		if np == nil || np.Management == nil || !np.Management.AutoUpgrade {
			return false
		}
	}
	return true
}

// releaseChannel returns the configured release channel, omitting the
// UNSPECIFIED sentinel (no channel selected).
func releaseChannel(c *container.Cluster) string {
	if c.ReleaseChannel == nil || c.ReleaseChannel.Channel == "UNSPECIFIED" {
		return ""
	}
	return c.ReleaseChannel.Channel
}

// realGKE is the production implementation of API. It wraps
// *container.Service and lists every cluster in the project across all
// locations in one call.
type realGKE struct {
	svc *container.Service
}

func (r *realGKE) ListClusters(ctx context.Context, project string) ([]*container.Cluster, error) {
	parent := fmt.Sprintf("projects/%s/locations/-", project)
	resp, err := r.svc.Projects.Locations.Clusters.List(parent).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return resp.Clusters, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
