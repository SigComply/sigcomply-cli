// Package compute implements the gcp.compute source plugin: lists
// Compute Engine VM instances across every zone in a project and emits
// one compute_instance evidence record per VM so SOC 2 policies can
// flag misconfigurations (default service account, shielded-VM off,
// public IP, OS-Login disabled, …).
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect
// calls. N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by
// internal/sources/aws/iam — the real Compute adapter satisfies it,
// and unit tests inject an in-memory fake.
package compute

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	gce "google.golang.org/api/compute/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the single evidence type this plugin emits today.
const EvidenceTypeID = "compute_instance"

// SourceID is the registered ID for the gcp.compute plugin instance.
const SourceID = "gcp.compute"

// API is the subset of the Compute Engine client this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting
// GCP; the real adapter wraps *compute.Service.
type API interface {
	// AggregatedListInstances returns every Compute instance in the
	// project across all zones, paginated transparently.
	AggregatedListInstances(ctx context.Context, project string) ([]*gce.Instance, error)
}

// Plugin is the in-process gcp.compute source.
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

// NewFromGCP constructs a Plugin backed by the real Compute Engine API
// using Application Default Credentials. M6 does not exercise this
// path under integration tests.
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	svc, err := gce.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.compute: new service: %w", err)
	}
	return New(Options{
		API:       &realCompute{svc: svc},
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

// instancePayload is the shape of the JSON payload inside each
// compute_instance record.
type instancePayload struct {
	Name                      string   `json:"name"`
	ID                        uint64   `json:"id,omitempty"`
	Zone                      string   `json:"zone"`
	MachineType               string   `json:"machine_type"`
	Status                    string   `json:"status"`
	ServiceAccountEmails      []string `json:"service_account_emails"`
	UsesDefaultServiceAccount bool     `json:"uses_default_service_account"`
	HasPublicIP               bool     `json:"has_public_ip"`
	ShieldedVMEnabled         bool     `json:"shielded_vm_enabled"`
	CanIPForward              bool     `json:"can_ip_forward"`
	DeletionProtection        bool     `json:"deletion_protection"`
	CreationTimestamp         string   `json:"creation_timestamp,omitempty"`
}

// Collect lists instances in the configured project and emits one
// compute_instance record per VM. Records are sorted by ID (instance
// name) before return so envelope bytes are stable across runs against
// stable project state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if req.EvidenceType != EvidenceTypeID {
		return nil, fmt.Errorf("gcp.compute: unsupported evidence type %q (only %q)", req.EvidenceType, EvidenceTypeID)
	}
	instances, err := p.api.AggregatedListInstances(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.compute: aggregated list instances: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(instances))
	for _, inst := range instances {
		if inst == nil {
			continue
		}
		emails := serviceAccountEmails(inst)
		payload := instancePayload{
			Name:                      inst.Name,
			ID:                        inst.Id,
			Zone:                      shortZone(inst.Zone),
			MachineType:               shortName(inst.MachineType),
			Status:                    inst.Status,
			ServiceAccountEmails:      emails,
			UsesDefaultServiceAccount: usesDefaultSA(emails, p.projectID),
			HasPublicIP:               hasPublicIP(inst),
			ShieldedVMEnabled:         shieldedEnabled(inst),
			CanIPForward:              inst.CanIpForward,
			DeletionProtection:        inst.DeletionProtection,
			CreationTimestamp:         inst.CreationTimestamp,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gcp.compute: marshal instance payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          inst.Name,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

func serviceAccountEmails(inst *gce.Instance) []string {
	out := make([]string, 0, len(inst.ServiceAccounts))
	for _, sa := range inst.ServiceAccounts {
		if sa == nil {
			continue
		}
		out = append(out, sa.Email)
	}
	return out
}

// usesDefaultSA reports whether any attached service account is the
// project's default Compute service account (PROJECT_NUMBER-
// compute@developer.gserviceaccount.com) — exact project-number match
// isn't possible without an extra API call, so we accept either the
// developer.gserviceaccount.com suffix or an explicit "default" SA.
func usesDefaultSA(emails []string, _ string) bool {
	for _, e := range emails {
		if e == "default" {
			return true
		}
		// The canonical default form ends with -compute@developer.gserviceaccount.com.
		if endsWith(e, "-compute@developer.gserviceaccount.com") {
			return true
		}
	}
	return false
}

func endsWith(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}

func hasPublicIP(inst *gce.Instance) bool {
	for _, ni := range inst.NetworkInterfaces {
		if ni == nil {
			continue
		}
		for _, ac := range ni.AccessConfigs {
			if ac != nil && ac.NatIP != "" {
				return true
			}
		}
	}
	return false
}

func shieldedEnabled(inst *gce.Instance) bool {
	if inst.ShieldedInstanceConfig == nil {
		return false
	}
	c := inst.ShieldedInstanceConfig
	return c.EnableSecureBoot || c.EnableVtpm || c.EnableIntegrityMonitoring
}

// shortName strips the GCE URL prefix from machine-type / zone URLs:
//
//	"projects/p/zones/us-central1-a/machineTypes/n1-standard-1" → "n1-standard-1".
func shortName(url string) string {
	if url == "" {
		return ""
	}
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == '/' {
			return url[i+1:]
		}
	}
	return url
}

// shortZone is shortName specialized for zones. Kept separately for
// readability — the URL shape is identical so the implementation is
// the same.
func shortZone(url string) string { return shortName(url) }

// realCompute is the production implementation of API. It wraps
// *compute.Service and uses AggregatedList for cross-zone enumeration.
type realCompute struct {
	svc *gce.Service
}

func (r *realCompute) AggregatedListInstances(ctx context.Context, project string) ([]*gce.Instance, error) {
	var out []*gce.Instance
	err := r.svc.Instances.AggregatedList(project).Pages(ctx, func(page *gce.InstanceAggregatedList) error {
		for _, scoped := range page.Items {
			out = append(out, scoped.Instances...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
