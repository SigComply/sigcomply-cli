// Package backup implements the gcp.backup source plugin: lists Backup and
// DR Service backup plans across every location in one GCP project and
// emits one backup_plan evidence record per plan, carrying the active /
// retention attributes the backup_plan policies evaluate — the same
// cloud-neutral type aws.backup emits, so those policies span both clouds
// with zero changes (Invariant #4, substitutability).
//
// Backup and DR Service is GCP's centralized backup product and the direct
// analog of AWS Backup: project-level backup plans, each containing backup
// rules that bind a schedule to a retention policy, stored in a backup
// vault. It spans Compute, Disk, Cloud SQL, AlloyDB, and Filestore — far
// broader than the GKE-only Backup-for-GKE service or per-instance Cloud
// SQL backup toggles, so it is the honest cross-vendor mapping. (A future
// gkebackup source could emit the same backup_plan type for GKE workloads —
// exactly the substitutability the plugin model is designed for.)
//
// One list call covers the project: Projects.Locations.BackupPlans.List
// accepts the all-locations wildcard (locations/-), returning plans from
// every region. The response carries Unreachable locations; the real
// adapter errors on any unreachable location rather than silently dropping
// plans — a partial list could make an all-quantifier policy misbehave.
//
// Field mapping (the two required booleans are emitted unconditionally —
// the evaluator errors on any payload that omits a field a policy clause
// references):
//   - is_active ← State == "ACTIVE". Backup and DR exposes an explicit
//     plan state enum (ACTIVE/INACTIVE/CREATING/…), so this is a real
//     signal — unlike aws.backup, which has no per-plan disabled flag and
//     reports every listed plan active.
//   - has_retention_rule ← at least one BackupRule has BackupRetentionDays
//     > 0. (BackupRetentionDays is a required field with a minimum of 1 on
//     every rule, so in practice any rule implies retention; the explicit
//     > 0 check is the self-documenting predicate.)
//   - retention_days ← the maximum BackupRetentionDays across the plan's
//     rules; a pointer, omitted when no retention rule exists (matching
//     aws.backup, which records the max DeleteAfterDays).
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect calls.
// N policies bound to this plugin → N invocations of Collect.
//
// Auth: Application Default Credentials with the cloud-platform scope
// (Backup and DR exposes no dedicated read-only scope); restrict access at
// the IAM layer with roles/backupdr.viewer (grants backupdr.backupPlans.
// list/get). See docs/configuration.md §GCP. The real adapter wraps
// *backupdr.Service and unit tests inject an in-memory fake via the API
// interface seam.
package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	backupdr "google.golang.org/api/backupdr/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "backup_plan"

// SourceID is the registered ID for the gcp.backup plugin instance.
const SourceID = "gcp.backup"

// stateActive is the BackupPlan.State value that means the plan is active
// and running scheduled backups.
const stateActive = "ACTIVE"

// API is the subset of the Backup and DR client this plugin uses. Defining
// it as an interface lets tests inject a fake without hitting GCP; the real
// adapter wraps *backupdr.Service and lists plans across all locations.
type API interface {
	// ListBackupPlans returns every backup plan across all locations in the
	// project (the locations/- wildcard), paginated into one slice.
	ListBackupPlans(ctx context.Context, project string) ([]*backupdr.BackupPlan, error)
}

// Plugin is the in-process gcp.backup source.
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

// NewFromGCP constructs a Plugin backed by the real Backup and DR API using
// Application Default Credentials with the cloud-platform scope (there is
// no narrower read-only scope). Restrict access at the IAM layer with
// roles/backupdr.viewer.
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	svc, err := backupdr.NewService(ctx, option.WithScopes(backupdr.CloudPlatformScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.backup: new service: %w", err)
	}
	return New(Options{
		API:       &realBackupDR{svc: svc},
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

// planPayload is the cross-vendor backup_plan shape (see
// internal/evidence_types/schemas/backup_plan.v1.json). The two required
// booleans are always emitted — the evaluator errors on any payload that
// omits a field a policy clause references. retention_days is a pointer so
// it is omitted (not zero) when no retention rule exists.
type planPayload struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Provider            string   `json:"provider"`
	IsActive            bool     `json:"is_active"`
	HasRetentionRule    bool     `json:"has_retention_rule"`
	RetentionDays       *int64   `json:"retention_days,omitempty"`
	CoversResourceTypes []string `json:"covers_resource_types,omitempty"`
	// GCP-specific extras (additionalProperties). state carries the raw plan
	// state so an INACTIVE/CREATING is distinguishable from ACTIVE;
	// backup_vault records where backups land; rule_count makes the
	// has_retention_rule derivation auditable.
	State       string `json:"state,omitempty"`
	BackupVault string `json:"backup_vault,omitempty"`
	RuleCount   int    `json:"rule_count,omitempty"`
}

// Collect lists Backup and DR backup plans in the configured project and
// returns one backup_plan record per plan. Records are sorted by ID before
// return so envelope bytes are stable across runs against stable project
// state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.backup: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	plans, err := p.api.ListBackupPlans(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.backup: list backup plans: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(plans))
	for _, plan := range plans {
		if plan == nil {
			continue
		}
		payload := buildPayload(plan)
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gcp.backup: marshal payload: %w", err)
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

// buildPayload maps one Backup and DR backup plan into the cross-vendor
// backup_plan shape.
func buildPayload(plan *backupdr.BackupPlan) planPayload {
	has, maxDays := retention(plan)
	p := planPayload{
		ID:               plan.Name,
		Name:             backupPlanShortName(plan.Name),
		Provider:         "gcp",
		IsActive:         plan.State == stateActive,
		HasRetentionRule: has,
		RetentionDays:    maxDays,
		State:            plan.State,
		BackupVault:      plan.BackupVault,
		RuleCount:        len(plan.BackupRules),
	}
	if plan.ResourceType != "" {
		p.CoversResourceTypes = []string{plan.ResourceType}
	}
	return p
}

// retention reports whether the plan has at least one rule with a positive
// retention period, and the maximum such period (a pointer, nil when no
// retention rule exists).
func retention(plan *backupdr.BackupPlan) (has bool, maxDays *int64) {
	for _, r := range plan.BackupRules {
		if r == nil || r.BackupRetentionDays <= 0 {
			continue
		}
		has = true
		if maxDays == nil || r.BackupRetentionDays > *maxDays {
			d := r.BackupRetentionDays
			maxDays = &d
		}
	}
	return has, maxDays
}

// backupPlanShortName returns the trailing plan id from a resource name of
// the form "projects/{p}/locations/{loc}/backupPlans/{plan}". It falls back
// to the full name when the name does not contain the "/backupPlans/"
// segment.
func backupPlanShortName(name string) string {
	if i := strings.LastIndex(name, "/backupPlans/"); i >= 0 {
		return name[i+len("/backupPlans/"):]
	}
	return name
}

// realBackupDR is the production implementation of API. It wraps
// *backupdr.Service and lists every backup plan in the project across all
// locations, paginating the response.
type realBackupDR struct {
	svc *backupdr.Service
}

func (r *realBackupDR) ListBackupPlans(ctx context.Context, project string) ([]*backupdr.BackupPlan, error) {
	parent := fmt.Sprintf("projects/%s/locations/-", project)
	var plans []*backupdr.BackupPlan
	var unreachable []string
	err := r.svc.Projects.Locations.BackupPlans.List(parent).Pages(ctx,
		func(resp *backupdr.ListBackupPlansResponse) error {
			plans = append(plans, resp.BackupPlans...)
			unreachable = append(unreachable, resp.Unreachable...)
			return nil
		})
	if err != nil {
		return nil, err
	}
	// A location Backup and DR couldn't reach means its plans are missing
	// from the list. Surfacing this as an error (rather than returning a
	// partial set) keeps quantifier policies honest.
	if len(unreachable) > 0 {
		return nil, fmt.Errorf("unreachable locations: %s", strings.Join(unreachable, ", "))
	}
	return plans, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
