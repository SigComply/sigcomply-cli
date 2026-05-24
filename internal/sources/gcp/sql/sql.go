// Package sql implements the gcp.sql source plugin: lists Cloud SQL
// instances in a project and emits one cloudsql_instance evidence
// record per instance so SOC 2 database-hardening policies can flag
// missing SSL enforcement, public IPv4, automated backups off, etc.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect
// calls. N policies bound to this plugin → N invocations of Collect.
//
// Test injection: the API interface mirrors the pattern used by
// internal/sources/aws/iam — the real Cloud SQL adapter satisfies it,
// and unit tests inject an in-memory fake.
package sql

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	sqladmin "google.golang.org/api/sqladmin/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the single evidence type this plugin emits today.
const EvidenceTypeID = "cloudsql_instance"

// SourceID is the registered ID for the gcp.sql plugin instance.
const SourceID = "gcp.sql"

// API is the subset of the Cloud SQL Admin client this plugin uses.
// Defining it as an interface lets tests inject a fake without hitting
// GCP; the real adapter wraps *sqladmin.Service.
type API interface {
	ListInstances(ctx context.Context, project string) ([]*sqladmin.DatabaseInstance, error)
}

// Plugin is the in-process gcp.sql source.
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

// NewFromGCP constructs a Plugin backed by the real Cloud SQL Admin
// API using Application Default Credentials. M6 does not exercise this
// path under integration tests.
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	svc, err := sqladmin.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp.sql: new service: %w", err)
	}
	return New(Options{
		API:       &realSQL{svc: svc},
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
// cloudsql_instance record.
type instancePayload struct {
	Name                string `json:"name"`
	DatabaseVersion     string `json:"database_version"`
	Region              string `json:"region"`
	State               string `json:"state"`
	RequireSSL          bool   `json:"require_ssl"`
	SSLMode             string `json:"ssl_mode,omitempty"`
	Ipv4Enabled         bool   `json:"ipv4_enabled"`
	BackupConfigEnabled bool   `json:"backup_config_enabled"`
	PITREnabled         bool   `json:"pitr_enabled"`
	AvailabilityType    string `json:"availability_type,omitempty"`
	DeletionProtection  bool   `json:"deletion_protection"`
}

// Collect lists Cloud SQL instances in the configured project and
// emits one cloudsql_instance record per instance. Records are sorted
// by ID (instance name) before return so envelope bytes are stable
// across runs against stable project state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if req.EvidenceType != EvidenceTypeID {
		return nil, fmt.Errorf("gcp.sql: unsupported evidence type %q (only %q)", req.EvidenceType, EvidenceTypeID)
	}
	instances, err := p.api.ListInstances(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.sql: list instances: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(instances))
	for _, inst := range instances {
		if inst == nil {
			continue
		}
		payload := instancePayload{
			Name:                inst.Name,
			DatabaseVersion:     inst.DatabaseVersion,
			Region:              inst.Region,
			State:               inst.State,
			RequireSSL:          ipCfgRequireSSL(inst),
			SSLMode:             ipCfgSSLMode(inst),
			Ipv4Enabled:         ipCfgIpv4Enabled(inst),
			BackupConfigEnabled: backupEnabled(inst),
			PITREnabled:         pitrEnabled(inst),
			AvailabilityType:    availabilityType(inst),
			DeletionProtection:  deletionProtection(inst),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gcp.sql: marshal instance payload: %w", err)
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

func ipCfgRequireSSL(inst *sqladmin.DatabaseInstance) bool {
	if inst.Settings == nil || inst.Settings.IpConfiguration == nil {
		return false
	}
	return inst.Settings.IpConfiguration.RequireSsl
}

func ipCfgSSLMode(inst *sqladmin.DatabaseInstance) string {
	if inst.Settings == nil || inst.Settings.IpConfiguration == nil {
		return ""
	}
	return inst.Settings.IpConfiguration.SslMode
}

func ipCfgIpv4Enabled(inst *sqladmin.DatabaseInstance) bool {
	if inst.Settings == nil || inst.Settings.IpConfiguration == nil {
		return false
	}
	return inst.Settings.IpConfiguration.Ipv4Enabled
}

func backupEnabled(inst *sqladmin.DatabaseInstance) bool {
	if inst.Settings == nil || inst.Settings.BackupConfiguration == nil {
		return false
	}
	return inst.Settings.BackupConfiguration.Enabled
}

func pitrEnabled(inst *sqladmin.DatabaseInstance) bool {
	if inst.Settings == nil || inst.Settings.BackupConfiguration == nil {
		return false
	}
	return inst.Settings.BackupConfiguration.PointInTimeRecoveryEnabled
}

func availabilityType(inst *sqladmin.DatabaseInstance) string {
	if inst.Settings == nil {
		return ""
	}
	return inst.Settings.AvailabilityType
}

func deletionProtection(inst *sqladmin.DatabaseInstance) bool {
	if inst.Settings == nil {
		return false
	}
	return inst.Settings.DeletionProtectionEnabled
}

// realSQL is the production implementation of API. It wraps
// *sqladmin.Service and uses the Instances.List endpoint.
type realSQL struct {
	svc *sqladmin.Service
}

func (r *realSQL) ListInstances(ctx context.Context, project string) ([]*sqladmin.DatabaseInstance, error) {
	var out []*sqladmin.DatabaseInstance
	err := r.svc.Instances.List(project).Pages(ctx, func(page *sqladmin.InstancesListResponse) error {
		out = append(out, page.Items...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
