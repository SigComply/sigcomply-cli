// Package audit implements the gcp.audit source plugin: it emits a single
// audit_log_trail evidence record describing a GCP project's Cloud Audit
// Logs posture — the same cloud-neutral type aws.cloudtrail emits, so the
// audit-logging policies (SOC2 CC7.1, ISO A.8.15) span both clouds with
// zero changes (Invariant #4, substitutability).
//
// Modeling choice — one project-level trail, not per-sink. GCP audit
// logging has two pieces: the IAM audit *configuration* (auditConfigs on
// the project IAM policy — what is recorded) and log *sinks* (where logs
// are exported). The honest analog of an AWS CloudTrail "trail" is the
// project-level audit posture, not each sink (a sink can route non-audit
// logs and its absence does not disable audit logging — logs still flow
// to the _Default/_Required buckets). So this plugin emits exactly one
// audit_log_trail per project.
//
// Required-field mapping — these are GCP platform facts, not derived
// toggles (so they are emitted as documented constants, the same pattern
// gcp.kms uses for is_customer_managed):
//   - is_enabled = true. Admin Activity audit logs (the management-event
//     analog of CloudTrail's IsLogging) are always on in GCP and cannot
//     be disabled.
//   - is_multi_region = true. Cloud Audit Logs are global / project-wide;
//     GCP has no per-region trail and so no "missing region" concept.
//   - log_file_validation_enabled = true. GCP guarantees audit-log
//     integrity structurally: Admin Activity logs route to the _Required
//     bucket, which is locked and immutable (fixed 400-day retention, not
//     deletable). That is the integrity guarantee CloudTrail's digest
//     files provide, achieved by platform design rather than a toggle.
//   - kms_encrypted ← a customer-managed CMEK key is configured on the
//     project's Cloud Logging settings (Google-managed default → false,
//     matching aws.cloudtrail reporting false for the default key).
//
// The plugin makes two read-only calls so the record is grounded in real
// project state (and fails honestly when access is missing): Cloud
// Resource Manager GetIamPolicy (drives the data_access_logging_enabled
// extra and proves project access) and Cloud Logging GetCmekSettings
// (drives kms_encrypted).
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect calls.
//
// Auth: Application Default Credentials. GetIamPolicy needs
// resourcemanager.projects.getIamPolicy (roles/iam.securityReviewer);
// GetCmekSettings needs logging.cmekSettings.get (roles/logging.viewer).
// See docs/configuration.md §GCP.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/api/cloudresourcemanager/v3"
	logging "google.golang.org/api/logging/v2"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "audit_log_trail"

// SourceID is the registered ID for the gcp.audit plugin instance.
const SourceID = "gcp.audit"

// API is the subset of the GCP clients this plugin uses. Defining it as
// an interface lets tests inject a fake without hitting GCP; the real
// adapter wraps the Cloud Resource Manager and Cloud Logging services.
type API interface {
	// GetAuditConfigs returns the project IAM policy's audit configs (one
	// per audited service), or an empty slice when none are configured.
	GetAuditConfigs(ctx context.Context, project string) ([]*cloudresourcemanager.AuditConfig, error)
	// GetCMEKKeyName returns the customer-managed KMS key configured on the
	// project's Cloud Logging settings, or "" for the Google-managed default.
	GetCMEKKeyName(ctx context.Context, project string) (string, error)
}

// Plugin is the in-process gcp.audit source.
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

// NewFromGCP constructs a Plugin backed by the real GCP APIs using
// Application Default Credentials with read-only scopes.
func NewFromGCP(ctx context.Context, projectID string) (*Plugin, error) {
	crm, err := cloudresourcemanager.NewService(ctx, option.WithScopes(cloudresourcemanager.CloudPlatformReadOnlyScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.audit: new resource manager service: %w", err)
	}
	log, err := logging.NewService(ctx, option.WithScopes(logging.LoggingReadScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.audit: new logging service: %w", err)
	}
	return New(Options{
		API:       &realAudit{crm: crm, log: log},
		ProjectID: projectID,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op for this plugin — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// trailPayload is the cross-vendor audit_log_trail shape (see
// internal/evidence_types/schemas/audit_log_trail.v1.json). The required
// fields (id, name, is_enabled, kms_encrypted) plus the CloudTrail-shaped
// optionals the policies read (is_multi_region, log_file_validation_enabled)
// are always emitted — the evaluator errors on any payload that omits a
// field a policy references.
type trailPayload struct {
	ID                       string `json:"id"`
	Name                     string `json:"name"`
	Provider                 string `json:"provider"`
	IsEnabled                bool   `json:"is_enabled"`
	IsMultiRegion            bool   `json:"is_multi_region"`
	LogFileValidationEnabled bool   `json:"log_file_validation_enabled"`
	KMSEncrypted             bool   `json:"kms_encrypted"`
	// GCP-specific extras (additionalProperties).
	// DataAccessLoggingEnabled makes the GetIamPolicy call auditable: it
	// reports whether optional Data Access / Admin Read logging is on
	// (off by default in GCP). No shipped policy reads it yet.
	DataAccessLoggingEnabled bool   `json:"data_access_logging_enabled"`
	AuditedServices          int    `json:"audited_services"`
	KMSKeyName               string `json:"kms_key_name,omitempty"`
}

// Collect returns the single audit_log_trail record for the configured
// project.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("gcp.audit: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	configs, err := p.api.GetAuditConfigs(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.audit: get audit configs: %w", err)
	}
	cmekKey, err := p.api.GetCMEKKeyName(ctx, p.projectID)
	if err != nil {
		return nil, fmt.Errorf("gcp.audit: get cmek settings: %w", err)
	}
	payload := buildPayload(p.projectID, configs, cmekKey)
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("gcp.audit: marshal payload: %w", err)
	}
	return []core.EvidenceRecord{{
		Type:        EvidenceTypeID,
		ID:          payload.ID,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: p.now(),
	}}, nil
}

// buildPayload maps a project's audit posture into the cross-vendor
// audit_log_trail shape. See the package doc for the constant mappings.
func buildPayload(project string, configs []*cloudresourcemanager.AuditConfig, cmekKey string) trailPayload {
	return trailPayload{
		ID:                       fmt.Sprintf("projects/%s/cloudAuditLogs", project),
		Name:                     project,
		Provider:                 "gcp",
		IsEnabled:                true, // Admin Activity audit logs are always-on.
		IsMultiRegion:            true, // Cloud Audit Logs are global, not regional.
		LogFileValidationEnabled: true, // Integrity via immutable, locked _Required bucket.
		KMSEncrypted:             cmekKey != "",
		DataAccessLoggingEnabled: dataAccessLoggingEnabled(configs),
		AuditedServices:          auditedServiceCount(configs),
		KMSKeyName:               cmekKey,
	}
}

// dataAccessLoggingEnabled reports whether any service has an audit log
// config (ADMIN_READ / DATA_READ / DATA_WRITE) with no exempted members —
// i.e. optional data-access auditing is genuinely on for everyone.
func dataAccessLoggingEnabled(configs []*cloudresourcemanager.AuditConfig) bool {
	for _, c := range configs {
		if c == nil {
			continue
		}
		for _, lc := range c.AuditLogConfigs {
			if lc == nil {
				continue
			}
			switch lc.LogType {
			case "ADMIN_READ", "DATA_READ", "DATA_WRITE":
				if len(lc.ExemptedMembers) == 0 {
					return true
				}
			}
		}
	}
	return false
}

// auditedServiceCount counts services carrying at least one audit log
// config (auditability for the data_access_logging_enabled derivation).
func auditedServiceCount(configs []*cloudresourcemanager.AuditConfig) int {
	n := 0
	for _, c := range configs {
		if c != nil && len(c.AuditLogConfigs) > 0 {
			n++
		}
	}
	return n
}

// realAudit is the production implementation of API. It wraps the Cloud
// Resource Manager and Cloud Logging services.
type realAudit struct {
	crm *cloudresourcemanager.Service
	log *logging.Service
}

func (r *realAudit) GetAuditConfigs(ctx context.Context, project string) ([]*cloudresourcemanager.AuditConfig, error) {
	// RequestedPolicyVersion 3 is required for auditConfigs to be returned.
	req := &cloudresourcemanager.GetIamPolicyRequest{
		Options: &cloudresourcemanager.GetPolicyOptions{RequestedPolicyVersion: 3},
	}
	policy, err := r.crm.Projects.GetIamPolicy("projects/"+project, req).Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	return policy.AuditConfigs, nil
}

func (r *realAudit) GetCMEKKeyName(ctx context.Context, project string) (string, error) {
	settings, err := r.log.Projects.GetCmekSettings("projects/" + project).Context(ctx).Do()
	if err != nil {
		return "", err
	}
	return settings.KmsKeyName, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
