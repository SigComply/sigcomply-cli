// Package secretmanager implements the gcp.secretmanager source plugin:
// lists Secret Manager secrets in one GCP project and emits one secret
// evidence record per secret, carrying the rotation and encryption
// attributes the secrets-rotation and secrets-encryption policies
// evaluate — the same cloud-neutral type aws.secretsmanager emits, so
// those policies span both clouds with zero changes (Invariant #4,
// substitutability).
//
// GCP exposes no last-rotation timestamp on the Secret resource, so the
// plugin lists each secret's versions to derive never_rotated and
// last_rotated_days honestly: a secret with one version has never been
// rotated; with more, the newest version's create time is the last
// rotation. (rotation_enabled — the field the shipped policies read —
// comes from the secret's rotation policy, not from version history.)
//
// CMEK (customer-managed encryption) is configured on the secret's
// replication, so kms_encrypted checks the automatic, per-replica
// user-managed, and top-level (regionalized) encryption paths.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Auth: Application Default Credentials with the cloud-platform scope
// (Secret Manager exposes no narrower read-only scope; restrict access at
// the IAM layer with roles/secretmanager.viewer, which grants
// secrets.list and versions.list). See docs/configuration.md §GCP. The
// real adapter wraps *secretmanager.Service and unit tests inject an
// in-memory fake via the API interface seam.
package secretmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/api/option"
	secretmanager "google.golang.org/api/secretmanager/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "secret"

// SourceID is the registered ID for the gcp.secretmanager plugin instance.
const SourceID = "gcp.secretmanager"

const hoursPerDay = 24

// API is the subset of the Secret Manager client this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting
// GCP; the real adapter wraps *secretmanager.Service and pages
// transparently. A second call lists each secret's versions because the
// Secret resource itself carries no rotation history.
type API interface {
	// ListSecrets returns every secret in the project, flattened.
	ListSecrets(ctx context.Context, project string) ([]*secretmanager.Secret, error)
	// ListSecretVersions returns every version of one secret (newest first),
	// used to derive never_rotated / last_rotated_days.
	ListSecretVersions(ctx context.Context, secretName string) ([]*secretmanager.SecretVersion, error)
}

// Plugin is the in-process gcp.secretmanager source.
type Plugin struct {
	api       API
	projectID string
	now       func() time.Time
}

// Options is the constructor input.
type Options struct {
	API       API
	ProjectID string
	// Now is injected so tests can produce deterministic CollectedAt /
	// last_rotated_days values. Production callers leave it nil → time.Now().UTC().
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

// NewFromGCP constructs a Plugin backed by the real Secret Manager API
// using Application Default Credentials with the cloud-platform scope
// (Secret Manager has no narrower read-only scope; restrict at the IAM
// layer with roles/secretmanager.viewer).
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	svc, err := secretmanager.NewService(ctx, option.WithScopes(secretmanager.CloudPlatformScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.secretmanager: new service: %w", err)
	}
	return New(Options{
		API:       &realSM{svc: svc},
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

// secretPayload is the cross-vendor secret shape (see
// internal/evidence_types/schemas/secret.v1.json). The three required
// booleans (rotation_enabled, kms_encrypted, never_rotated) are always
// emitted — the evaluator errors on any payload that omits a field a
// policy clause references.
type secretPayload struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Provider        string `json:"provider"`
	RotationEnabled bool   `json:"rotation_enabled"`
	KMSEncrypted    bool   `json:"kms_encrypted"`
	NeverRotated    bool   `json:"never_rotated"`
	// LastRotatedDays is a pointer so it is omitted (not emitted as 0) when
	// the secret has never been rotated; NeverRotated then carries the signal.
	LastRotatedDays *int `json:"last_rotated_days,omitempty"`
	// VersionCount is a GCP-specific extra (additionalProperties) that makes
	// the never_rotated derivation auditable.
	VersionCount int `json:"version_count"`
}

// Collect lists secrets in the configured project and returns one secret
// record per secret. Records are sorted by ID before return so envelope
// bytes are stable across runs against stable project state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.secretmanager: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	secrets, err := p.api.ListSecrets(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.secretmanager: list secrets: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(secrets))
	for _, s := range secrets {
		if s == nil {
			continue
		}
		versions, err := p.api.ListSecretVersions(ctx, s.Name)
		if err != nil {
			return nil, fmt.Errorf("gcp.secretmanager: list versions for %s: %w", s.Name, err)
		}
		payload := buildPayload(s, versions, now)
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gcp.secretmanager: marshal payload: %w", err)
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

// buildPayload maps one secret + its versions into the cross-vendor
// secret shape.
func buildPayload(s *secretmanager.Secret, versions []*secretmanager.SecretVersion, now time.Time) secretPayload {
	return secretPayload{
		ID:              s.Name,
		Name:            shortName(s.Name),
		Provider:        "gcp",
		RotationEnabled: rotationEnabled(s),
		KMSEncrypted:    cmekEnabled(s),
		NeverRotated:    len(versions) <= 1,
		LastRotatedDays: lastRotatedDays(versions, now),
		VersionCount:    len(versions),
	}
}

// rotationEnabled reports whether an automatic rotation policy is attached.
// NextRotationTime is set iff a rotation policy exists (RotationPeriod is
// input-only and does not round-trip on reads, so it cannot be relied on).
func rotationEnabled(s *secretmanager.Secret) bool {
	return s.Rotation != nil && s.Rotation.NextRotationTime != ""
}

// cmekEnabled reports whether the secret is encrypted with a
// customer-managed KMS key, checking every replication shape GCP exposes:
// automatic replication, per-replica user-managed, and the top-level
// (regionalized) configuration. Absent all three, Google-managed default
// encryption is in use → false (matching aws.secretsmanager, which reports
// false for the default aws/secretsmanager key).
func cmekEnabled(s *secretmanager.Secret) bool {
	if r := s.Replication; r != nil {
		if r.Automatic != nil && hasKey(r.Automatic.CustomerManagedEncryption) {
			return true
		}
		if r.UserManaged != nil {
			for _, rep := range r.UserManaged.Replicas {
				if rep != nil && hasKey(rep.CustomerManagedEncryption) {
					return true
				}
			}
		}
	}
	return hasKey(s.CustomerManagedEncryption)
}

func hasKey(c *secretmanager.CustomerManagedEncryption) bool {
	return c != nil && c.KmsKeyName != ""
}

// lastRotatedDays returns whole days since the most recent version's create
// time when the secret has been rotated (more than one version), else nil so
// the field is omitted (never_rotated then carries the signal).
func lastRotatedDays(versions []*secretmanager.SecretVersion, now time.Time) *int {
	if len(versions) <= 1 {
		return nil
	}
	var newest time.Time
	for _, v := range versions {
		if v == nil {
			continue
		}
		t, err := time.Parse(time.RFC3339, v.CreateTime)
		if err != nil {
			continue
		}
		if t.After(newest) {
			newest = t
		}
	}
	if newest.IsZero() {
		return nil
	}
	days := int(now.Sub(newest).Hours() / hoursPerDay)
	return &days
}

// shortName returns the trailing secret id from a full resource name
// (projects/p/secrets/db-pass → db-pass).
func shortName(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// realSM is the production implementation of API. It wraps
// *secretmanager.Service and pages secrets.list and versions.list.
type realSM struct {
	svc *secretmanager.Service
}

func (r *realSM) ListSecrets(ctx context.Context, project string) ([]*secretmanager.Secret, error) {
	var out []*secretmanager.Secret
	parent := fmt.Sprintf("projects/%s", project)
	err := r.svc.Projects.Secrets.List(parent).Pages(ctx, func(resp *secretmanager.ListSecretsResponse) error {
		out = append(out, resp.Secrets...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *realSM) ListSecretVersions(ctx context.Context, secretName string) ([]*secretmanager.SecretVersion, error) {
	var out []*secretmanager.SecretVersion
	err := r.svc.Projects.Secrets.Versions.List(secretName).Pages(ctx, func(resp *secretmanager.ListSecretVersionsResponse) error {
		out = append(out, resp.Versions...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
