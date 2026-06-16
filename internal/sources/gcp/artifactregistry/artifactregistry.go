// Package artifactregistry implements the gcp.artifactregistry source
// plugin: lists Artifact Registry repositories across every location in
// one GCP project and emits one container_registry evidence record per
// repository, carrying the scan-on-push, public-exposure, immutability,
// and encryption attributes the container-registry policies evaluate —
// the same cloud-neutral type aws.ecr emits, so those policies span both
// clouds with zero changes (Invariant #4, substitutability).
//
// Artifact Registry repositories are regional and there is no
// all-locations aggregated list, so the real adapter walks the project's
// locations (locations.list) and lists repositories per location, exactly
// as gcp.kms walks its location/keyRing hierarchy.
//
// Field mapping (all booleans are emitted unconditionally — the evaluator
// errors on any payload that omits a field a policy clause references):
//   - scan_on_push_enabled ← VulnerabilityScanningConfig.EnablementState
//     == "SCANNING_ACTIVE" (the output-only state already combines the
//     per-repo config and the project API enablement). A nil config or a
//     non-Docker / unsupported repo → false (scanning is genuinely not
//     active); the raw state rides in the scanning_state extra.
//   - is_public ← the repository IAM policy grants allUsers or
//     allAuthenticatedUsers. Artifact Registry exposes no "public" flag,
//     so the plugin makes one getIamPolicy call per repository (N+1, like
//     gcp.secretmanager's per-secret versions.list) and surfaces a failure
//     rather than silently reporting false (getIamPolicy is in
//     roles/artifactregistry.reader, so a failure is a config error).
//   - encryption_enabled ← always true. Artifact Registry encrypts every
//     repository at rest unconditionally (Google-managed by default, or a
//     customer-managed key), so there is no unencrypted state — matching
//     aws.ecr, which reports encryption_enabled true for the same reason.
//     The customer-managed-vs-default distinction is the is_customer_managed
//     extra (KmsKeyName set), not encryption_enabled.
//   - image_immutability_enabled ← DockerConfig.ImmutableTags (Docker
//     repositories only; nil config → false).
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Auth: Application Default Credentials with the cloud-platform read-only
// scope; restrict access at the IAM layer with roles/artifactregistry.reader
// (grants repositories.list/.get and .getIamPolicy). See
// docs/configuration.md §GCP. The real adapter wraps *artifactregistry.Service
// and unit tests inject an in-memory fake via the API interface seam.
package artifactregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	artifactregistry "google.golang.org/api/artifactregistry/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "container_registry"

// SourceID is the registered ID for the gcp.artifactregistry plugin instance.
const SourceID = "gcp.artifactregistry"

// scanningActive is the VulnerabilityScanningConfig.EnablementState value
// that means images are actively scanned for vulnerabilities.
const scanningActive = "SCANNING_ACTIVE"

// memberAllUsers / memberAllAuthenticatedUsers are the IAM member
// identifiers that make a repository publicly accessible.
const (
	memberAllUsers              = "allUsers"
	memberAllAuthenticatedUsers = "allAuthenticatedUsers"
)

// API is the subset of the Artifact Registry client this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting
// GCP; the real adapter wraps *artifactregistry.Service, walks the
// project's locations transparently, and reads each repository's IAM
// policy to determine public exposure.
type API interface {
	// ListRepositories returns every repository across all locations in the
	// project, flattened into one slice.
	ListRepositories(ctx context.Context, project string) ([]*artifactregistry.Repository, error)
	// GetIamPolicy returns the IAM policy for one repository, used to derive
	// is_public.
	GetIamPolicy(ctx context.Context, repoName string) (*artifactregistry.Policy, error)
}

// Plugin is the in-process gcp.artifactregistry source.
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

// NewFromGCP constructs a Plugin backed by the real Artifact Registry API
// using Application Default Credentials with the cloud-platform read-only
// scope (listing, get, and getIamPolicy are all reads). Restrict access at
// the IAM layer with roles/artifactregistry.reader.
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	svc, err := artifactregistry.NewService(ctx, option.WithScopes(artifactregistry.CloudPlatformReadOnlyScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.artifactregistry: new service: %w", err)
	}
	return New(Options{
		API:       &realAR{svc: svc},
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

// registryPayload is the cross-vendor container_registry shape (see
// internal/evidence_types/schemas/container_registry.v1.json). The five
// required fields plus image_immutability_enabled are always emitted — the
// evaluator errors on any payload that omits a field a policy clause
// references.
type registryPayload struct {
	ID                       string `json:"id"`
	Name                     string `json:"name"`
	Provider                 string `json:"provider"`
	ScanOnPushEnabled        bool   `json:"scan_on_push_enabled"`
	ImageImmutabilityEnabled bool   `json:"image_immutability_enabled"`
	IsPublic                 bool   `json:"is_public"`
	EncryptionEnabled        bool   `json:"encryption_enabled"`
	// GCP-specific extras (additionalProperties). is_customer_managed
	// distinguishes a CMEK repository from the Google-managed default (both
	// are encrypted at rest); scanning_state surfaces the raw scan
	// enablement state for auditability; format/mode/registry_uri identify
	// the repository.
	Format            string `json:"format,omitempty"`
	Mode              string `json:"mode,omitempty"`
	IsCustomerManaged bool   `json:"is_customer_managed"`
	KMSKeyName        string `json:"kms_key_name,omitempty"`
	ScanningState     string `json:"scanning_state,omitempty"`
	RegistryURI       string `json:"registry_uri,omitempty"`
}

// Collect lists Artifact Registry repositories in the configured project
// and returns one container_registry record per repository. Records are
// sorted by ID before return so envelope bytes are stable across runs
// against stable project state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.artifactregistry: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	repos, err := p.api.ListRepositories(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.artifactregistry: list repositories: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(repos))
	for _, repo := range repos {
		if repo == nil {
			continue
		}
		policy, err := p.api.GetIamPolicy(ctx, repo.Name)
		if err != nil {
			return nil, fmt.Errorf("gcp.artifactregistry: get IAM policy for %s: %w", repo.Name, err)
		}
		payload := buildPayload(repo, policy)
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gcp.artifactregistry: marshal payload: %w", err)
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

// buildPayload maps one Artifact Registry repository + its IAM policy into
// the cross-vendor container_registry shape.
func buildPayload(repo *artifactregistry.Repository, policy *artifactregistry.Policy) registryPayload {
	scanState := ""
	scanOnPush := false
	if repo.VulnerabilityScanningConfig != nil {
		scanState = repo.VulnerabilityScanningConfig.EnablementState
		scanOnPush = scanState == scanningActive
	}
	return registryPayload{
		ID:                       repo.Name,
		Name:                     shortName(repo.Name),
		Provider:                 "gcp",
		ScanOnPushEnabled:        scanOnPush,
		ImageImmutabilityEnabled: repo.DockerConfig != nil && repo.DockerConfig.ImmutableTags,
		IsPublic:                 isPublic(policy),
		// Artifact Registry always encrypts at rest (Google-managed default
		// or CMEK); there is no unencrypted state, so this is always true —
		// matching aws.ecr. The CMEK distinction is is_customer_managed.
		EncryptionEnabled: true,
		Format:            repo.Format,
		Mode:              repo.Mode,
		IsCustomerManaged: repo.KmsKeyName != "",
		KMSKeyName:        repo.KmsKeyName,
		ScanningState:     scanState,
		RegistryURI:       repo.RegistryUri,
	}
}

// isPublic reports whether the repository IAM policy grants access to
// allUsers or allAuthenticatedUsers in any binding.
func isPublic(policy *artifactregistry.Policy) bool {
	if policy == nil {
		return false
	}
	for _, b := range policy.Bindings {
		if b == nil {
			continue
		}
		for _, m := range b.Members {
			if m == memberAllUsers || m == memberAllAuthenticatedUsers {
				return true
			}
		}
	}
	return false
}

// shortName returns the trailing repository id from a full resource name
// (projects/p/locations/us/repositories/images → images).
func shortName(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// realAR is the production implementation of API. It wraps
// *artifactregistry.Service, walks the project's locations →
// repositories (paging at each level), and reads per-repository IAM policies.
type realAR struct {
	svc *artifactregistry.Service
}

func (r *realAR) ListRepositories(ctx context.Context, project string) ([]*artifactregistry.Repository, error) {
	var out []*artifactregistry.Repository
	locParent := fmt.Sprintf("projects/%s", project)
	err := r.svc.Projects.Locations.List(locParent).Pages(ctx, func(lp *artifactregistry.ListLocationsResponse) error {
		for _, loc := range lp.Locations {
			repoParent := fmt.Sprintf("projects/%s/locations/%s", project, loc.LocationId)
			if err := r.svc.Projects.Locations.Repositories.List(repoParent).Pages(ctx, func(rr *artifactregistry.ListRepositoriesResponse) error {
				out = append(out, rr.Repositories...)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *realAR) GetIamPolicy(ctx context.Context, repoName string) (*artifactregistry.Policy, error) {
	return r.svc.Projects.Locations.Repositories.GetIamPolicy(repoName).Context(ctx).Do()
}

var _ core.SourcePlugin = (*Plugin)(nil)
