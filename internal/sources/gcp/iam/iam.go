// Package iam implements the gcp.iam source plugin: fetches the
// project-level IAM policy from Cloud Resource Manager and emits one
// gcp_iam_binding evidence record per (role, member) pair so SOC 2
// least-privilege policies can flag (e.g.) `roles/owner` granted to
// individual users.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect
// calls. N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by
// internal/sources/aws/iam — the real SDK adapter satisfies it, and
// unit tests inject an in-memory fake. The real adapter has no
// integration tests at M6 (deferred).
package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	crm "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the single evidence type this plugin emits today.
const EvidenceTypeID = "gcp_iam_binding"

// SourceID is the registered ID for the gcp.iam plugin instance.
const SourceID = "gcp.iam"

// API is the subset of the Cloud Resource Manager client this plugin
// uses. Defining it as an interface lets tests inject a fake without
// hitting Google; the real adapter wraps *crm.Service.
type API interface {
	GetIamPolicy(ctx context.Context, project string) (*crm.Policy, error)
}

// Plugin is the in-process gcp.iam source.
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
// Callers using the real GCP SDK should use NewFromGCP.
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

// NewFromGCP constructs a Plugin backed by the real Cloud Resource
// Manager API using Application Default Credentials. M6 does not
// exercise this path under integration tests.
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	svc, err := crm.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.iam: new service: %w", err)
	}
	return New(Options{
		API:       &realCRM{svc: svc},
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

// bindingPayload is the shape of the JSON payload inside each
// gcp_iam_binding record.
type bindingPayload struct {
	Role         string `json:"role"`
	Member       string `json:"member"`
	MemberType   string `json:"member_type"`
	ProjectID    string `json:"project_id"`
	HasCondition bool   `json:"has_condition"`
}

// Collect fetches the project's IAM policy and emits one record per
// (role, member) pair. Records are sorted by ID before return so
// envelope bytes are stable across runs against stable project state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.iam: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	policy, err := p.api.GetIamPolicy(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.iam: get iam policy: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0)
	for _, b := range policy.Bindings {
		if b == nil {
			continue
		}
		hasCondition := b.Condition != nil
		for _, member := range b.Members {
			payload := bindingPayload{
				Role:         b.Role,
				Member:       member,
				MemberType:   memberType(member),
				ProjectID:    p.projectID,
				HasCondition: hasCondition,
			}
			body, err := json.Marshal(payload)
			if err != nil {
				return nil, fmt.Errorf("gcp.iam: marshal binding payload: %w", err)
			}
			records = append(records, core.EvidenceRecord{
				Type:        EvidenceTypeID,
				ID:          fmt.Sprintf("%s|%s", b.Role, member),
				IdentityKey: identityKey(member),
				Payload:     body,
				SourceID:    SourceID,
				CollectedAt: now,
			})
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// memberType extracts the principal prefix from a GCP member string —
// the part before the first colon ("user:alice@a.com" → "user").
// Returns "" when the member string is unparseable.
func memberType(member string) string {
	for i := 0; i < len(member); i++ {
		if member[i] == ':' {
			return member[:i]
		}
	}
	return ""
}

// identityKey returns a stable cross-source identity for the member —
// the email portion for user/group/serviceAccount/domain principals,
// or the raw value for allUsers/allAuthenticatedUsers.
func identityKey(member string) string {
	for i := 0; i < len(member); i++ {
		if member[i] == ':' {
			return member[i+1:]
		}
	}
	return member
}

// realCRM is the production implementation of API. It wraps
// *cloudresourcemanager.Service.
type realCRM struct {
	svc *crm.Service
}

func (r *realCRM) GetIamPolicy(ctx context.Context, project string) (*crm.Policy, error) {
	return r.svc.Projects.GetIamPolicy(project, &crm.GetIamPolicyRequest{}).Context(ctx).Do()
}

var _ core.SourcePlugin = (*Plugin)(nil)
