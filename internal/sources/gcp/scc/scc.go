// Package scc implements the gcp.scc source plugin: it reads Google
// Security Command Center (SCC) and emits three cross-vendor evidence
// types so SCC-backed GCP customers satisfy the same controls as AWS
// customers with zero policy changes (Invariant #4, substitutability):
//
//   - threat_detection_service ← Event Threat Detection (ETD) enablement.
//     The GCP analog of an AWS GuardDuty detector. is_enabled is true iff
//     ETD's ServiceEnablementState is ENABLED. Satisfies the
//     threat-detection-enabled policies (SOC2 CC6.8/CC7.2, ISO A.8.7/8.16).
//
//   - security_service (service_type "siem") ← Security Health Analytics
//     (SHA) enablement. SCC is GCP's centralized security findings
//     service — the functional analog of AWS Security Hub (the "siem"
//     service_type), so it is mapped there and satisfies the
//     security-aggregation policies (SOC2 CC7.1 securityhub_enabled, ISO
//     A.8.16 security_aggregation_enabled). SHA is SCC's foundational
//     built-in detector; if SHA is ENABLED, SCC is actively producing the
//     aggregated security findings, which is the honest readable signal
//     that "centralized security monitoring" is on. (SHA is technically a
//     CSPM, but no shipped policy reads service_type "cspm"; emitting it
//     as "siem" is the substitutability-correct mapping, not a CSPM record
//     that no control consumes.)
//
//   - vulnerability_finding ← active SCC findings of class VULNERABILITY
//     or MISCONFIGURATION. The GCP analog of AWS Inspector findings.
//     Satisfies the no-critical/high-findings policies (SOC2 CC6.8/CC7.4,
//     ISO A.8.7/8.8).
//
// Org scope (divergence from other gcp.* plugins). SCC is an
// organization-level product: tier and per-service enablement are set at
// the org and findings surface across the whole org. So this plugin takes
// an organization_id config key (not the project_id the other gcp.*
// plugins use) and reads at organizations/{org}/... The cost is an
// org-level IAM grant (roles/securitycenter.findingsViewer +
// roles/securitycenter.settingsViewer, or roles/securitycenter.adminViewer)
// that a project-scoped CI service account may lack — documented in
// docs/configuration.md §GCP as the likely setup gotcha.
//
// Two SDK surfaces, both subpackages of the already-vendored
// google.golang.org/api (no go.mod change):
//   - securitycenter/v1 lists findings (Organizations.Sources.Findings.List).
//   - securitycenter/v1beta2 reads service enablement
//     (GetEventThreatDetectionSettings / GetSecurityHealthAnalyticsSettings).
//     This v1beta2 settings surface is the only REST path that exposes
//     ServiceEnablementState — the newer Security Center *Management* API
//     ships no REST Go client (gRPC only), and securitycenter/v1's
//     settings services expose custom modules, not service on/off state.
//
// Auth: Application Default Credentials with CloudPlatformScope (SCC
// exposes no read-only OAuth scope; least privilege is enforced at the
// IAM layer). Per the KISS-no-DRY axiom the plugin caches nothing across
// Collect calls.
package scc

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	securitycenter "google.golang.org/api/securitycenter/v1"
	sccsettings "google.golang.org/api/securitycenter/v1beta2"

	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// SourceID is the registered ID for the gcp.scc plugin instance.
const SourceID = "gcp.scc"

// The three cross-vendor evidence types this plugin emits.
const (
	EvidenceTypeThreatService   = "threat_detection_service"
	EvidenceTypeSecurityService = "security_service"
	EvidenceTypeVulnFinding     = "vulnerability_finding"
)

// enablementStateEnabled is the v1beta2 ServiceEnablementState value that
// means a service is on (the enum also has INHERITED / DISABLED /
// ENABLEMENT_STATE_UNSPECIFIED, all of which map to is_enabled=false).
const enablementStateEnabled = "ENABLED"

// serviceTypeSIEM is the security_service category SCC maps to — the
// centralized security findings aggregation slot (the AWS Security Hub
// analog) the security-aggregation policies compare against.
const serviceTypeSIEM = "siem"

// resourceTypeFallback labels a finding whose SCC resource wrapper omits a
// type (the schema requires a non-empty resource_type).
const resourceTypeFallback = "gcp_resource"

// Finding is the plugin-local projection of an SCC finding (decoupled from
// the SDK type so the API seam stays fakeable). The real adapter fills it
// from securitycenter/v1's Finding plus its ListFindingsResult.Resource.
type Finding struct {
	Name           string // full resource name; the record ID
	ResourceName   string // affected resource path
	ResourceType   string // SCC resource wrapper type (e.g. google.compute.Instance)
	Category       string // finding category, used as the title
	Severity       string // raw SCC severity enum
	State          string // raw SCC state enum
	Mute           string // raw SCC mute enum (MUTED ⇒ SUPPRESSED)
	FindingClass   string // VULNERABILITY / MISCONFIGURATION / ...
	CVEID          string // from vulnerability.cve.id, if any
	CVSSScore      float64
	HasRemediation bool // next-steps text present
}

// API is the subset of SCC this plugin uses. Defining it as an interface
// lets tests inject a fake without hitting GCP; the real adapter wraps the
// securitycenter/v1 and /v1beta2 services.
type API interface {
	// EventThreatDetectionState returns the org's ETD ServiceEnablementState.
	EventThreatDetectionState(ctx context.Context, org string) (string, error)
	// SecurityHealthAnalyticsState returns the org's SHA ServiceEnablementState.
	SecurityHealthAnalyticsState(ctx context.Context, org string) (string, error)
	// ListActiveFindings returns active VULNERABILITY/MISCONFIGURATION findings.
	ListActiveFindings(ctx context.Context, org string) ([]Finding, error)
}

// Plugin is the in-process gcp.scc source.
type Plugin struct {
	api   API
	orgID string
	now   func() time.Time
}

// Options is the constructor input.
type Options struct {
	API   API
	OrgID string
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
	return &Plugin{api: opts.API, orgID: opts.OrgID, now: now}
}

// NewFromGCP constructs a Plugin backed by the real SCC APIs using
// Application Default Credentials. SCC has no read-only scope, so the
// CloudPlatformScope is used and access is constrained by IAM.
func NewFromGCP(ctx context.Context, orgID string) (*Plugin, error) {
	findings, err := securitycenter.NewService(ctx, option.WithScopes(securitycenter.CloudPlatformScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.scc: new security center service: %w", err)
	}
	settings, err := sccsettings.NewService(ctx, option.WithScopes(sccsettings.CloudPlatformScope))
	if err != nil {
		return nil, fmt.Errorf("gcp.scc: new security center settings service: %w", err)
	}
	return New(Options{
		API:   &realSCC{findings: findings, settings: settings},
		OrgID: orgID,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string {
	return []string{EvidenceTypeThreatService, EvidenceTypeSecurityService, EvidenceTypeVulnFinding}
}

// Init is a no-op for this plugin — configuration is fixed at New.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// threatServicePayload is the cross-vendor threat_detection_service shape.
type threatServicePayload struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	IsEnabled bool   `json:"is_enabled"`
	// Extra (additionalProperties): the raw state, so the is_enabled
	// derivation is auditable (e.g. INHERITED is recorded, not hidden).
	ServiceEnablementState string `json:"service_enablement_state"`
}

// securityServicePayload is the cross-vendor security_service shape.
type securityServicePayload struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	Provider               string `json:"provider"`
	ServiceType            string `json:"service_type"`
	IsEnabled              bool   `json:"is_enabled"`
	ServiceEnablementState string `json:"service_enablement_state"`
}

// vulnFindingPayload is the cross-vendor vulnerability_finding shape. The
// required fields (id, resource_id, resource_type, severity, status) are
// always emitted — the evaluator errors on a referenced-but-absent field.
type vulnFindingPayload struct {
	ID                   string  `json:"id"`
	ResourceID           string  `json:"resource_id"`
	ResourceType         string  `json:"resource_type"`
	Title                string  `json:"title,omitempty"`
	Severity             string  `json:"severity"`
	Status               string  `json:"status"`
	CVEID                string  `json:"cve_id,omitempty"`
	Score                float64 `json:"score,omitempty"`
	RemediationAvailable bool    `json:"remediation_available"`
	// Extras (additionalProperties).
	Provider     string `json:"provider"`
	FindingClass string `json:"finding_class"`
}

// Collect dispatches on which of the three emitted types the slot accepts,
// returning the union of the requested records (each group sorted by ID).
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	wantThreat := req.Accepts(EvidenceTypeThreatService)
	wantSecurity := req.Accepts(EvidenceTypeSecurityService)
	wantFindings := req.Accepts(EvidenceTypeVulnFinding)

	if !wantThreat && !wantSecurity && !wantFindings {
		return nil, fmt.Errorf("gcp.scc: slot AcceptedTypes %v does not include emitted types %q, %q, %q",
			req.AcceptedTypes, EvidenceTypeThreatService, EvidenceTypeSecurityService, EvidenceTypeVulnFinding)
	}

	var out []core.EvidenceRecord

	if wantThreat {
		rs, err := p.collectThreatService(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	if wantSecurity {
		rs, err := p.collectSecurityService(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	if wantFindings {
		rs, err := p.collectFindings(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}

	return out, nil
}

// collectThreatService emits the single Event Threat Detection record.
func (p *Plugin) collectThreatService(ctx context.Context) ([]core.EvidenceRecord, error) {
	state, err := p.api.EventThreatDetectionState(ctx, p.orgID)
	if err != nil {
		return nil, fmt.Errorf("gcp.scc: event threat detection settings: %w", err)
	}
	payload := threatServicePayload{
		ID:                     fmt.Sprintf("organizations/%s/eventThreatDetectionSettings", p.orgID),
		Name:                   "Event Threat Detection",
		Provider:               "gcp",
		IsEnabled:              state == enablementStateEnabled,
		ServiceEnablementState: state,
	}
	return p.singleRecord(EvidenceTypeThreatService, payload.ID, payload)
}

// collectSecurityService emits the single Security Command Center record
// (mapped to service_type "siem"; see the package doc).
func (p *Plugin) collectSecurityService(ctx context.Context) ([]core.EvidenceRecord, error) {
	state, err := p.api.SecurityHealthAnalyticsState(ctx, p.orgID)
	if err != nil {
		return nil, fmt.Errorf("gcp.scc: security health analytics settings: %w", err)
	}
	payload := securityServicePayload{
		ID:                     fmt.Sprintf("organizations/%s/securityHealthAnalyticsSettings", p.orgID),
		Name:                   "Google Security Command Center",
		Provider:               "gcp",
		ServiceType:            serviceTypeSIEM,
		IsEnabled:              state == enablementStateEnabled,
		ServiceEnablementState: state,
	}
	return p.singleRecord(EvidenceTypeSecurityService, payload.ID, payload)
}

// collectFindings emits one vulnerability_finding record per active
// VULNERABILITY/MISCONFIGURATION finding, sorted by ID.
func (p *Plugin) collectFindings(ctx context.Context) ([]core.EvidenceRecord, error) {
	findings, err := p.api.ListActiveFindings(ctx, p.orgID)
	if err != nil {
		return nil, fmt.Errorf("gcp.scc: list findings: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(findings))
	for i := range findings {
		f := findings[i]
		resourceType := f.ResourceType
		if resourceType == "" {
			resourceType = resourceTypeFallback
		}
		payload := vulnFindingPayload{
			ID:                   f.Name,
			ResourceID:           f.ResourceName,
			ResourceType:         resourceType,
			Title:                f.Category,
			Severity:             mapSeverity(f.Severity),
			Status:               mapStatus(f.State, f.Mute),
			CVEID:                f.CVEID,
			Score:                f.CVSSScore,
			RemediationAvailable: f.HasRemediation,
			Provider:             "gcp",
			FindingClass:         f.FindingClass,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("gcp.scc: marshal finding payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeVulnFinding,
			ID:          payload.ID,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// singleRecord marshals a service-enablement payload into a one-record slice.
func (p *Plugin) singleRecord(evidenceType, id string, payload any) ([]core.EvidenceRecord, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("gcp.scc: marshal %s payload: %w", evidenceType, err)
	}
	return []core.EvidenceRecord{{
		Type:        evidenceType,
		ID:          id,
		Payload:     body,
		SourceID:    SourceID,
		CollectedAt: p.now(),
	}}, nil
}

// mapSeverity maps SCC's severity enum to the vulnerability_finding schema
// enum (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL). SEVERITY_UNSPECIFIED and
// any unknown value map to INFORMATIONAL.
func mapSeverity(s string) string {
	switch s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return s
	default:
		return "INFORMATIONAL"
	}
}

// mapStatus maps SCC's state + mute to the schema status enum. A muted
// finding is SUPPRESSED regardless of state; otherwise ACTIVE state maps
// to ACTIVE and anything else (INACTIVE / unspecified) to RESOLVED.
func mapStatus(state, mute string) string {
	if mute == "MUTED" {
		return "SUPPRESSED"
	}
	if state == "ACTIVE" {
		return "ACTIVE"
	}
	return "RESOLVED"
}

// realSCC is the production implementation of API. It wraps the
// securitycenter/v1 (findings) and /v1beta2 (settings) services.
type realSCC struct {
	findings *securitycenter.Service
	settings *sccsettings.Service
}

func (r *realSCC) EventThreatDetectionState(ctx context.Context, org string) (string, error) {
	name := fmt.Sprintf("organizations/%s/eventThreatDetectionSettings", org)
	s, err := r.settings.Organizations.GetEventThreatDetectionSettings(name).Context(ctx).Do()
	if err != nil {
		return "", err
	}
	return s.ServiceEnablementState, nil
}

func (r *realSCC) SecurityHealthAnalyticsState(ctx context.Context, org string) (string, error) {
	name := fmt.Sprintf("organizations/%s/securityHealthAnalyticsSettings", org)
	s, err := r.settings.Organizations.GetSecurityHealthAnalyticsSettings(name).Context(ctx).Do()
	if err != nil {
		return "", err
	}
	return s.ServiceEnablementState, nil
}

func (r *realSCC) ListActiveFindings(ctx context.Context, org string) ([]Finding, error) {
	parent := fmt.Sprintf("organizations/%s/sources/-", org)
	const filter = `state="ACTIVE" AND (finding_class="VULNERABILITY" OR finding_class="MISCONFIGURATION")`
	var out []Finding
	call := r.findings.Organizations.Sources.Findings.List(parent).Filter(filter).PageSize(1000)
	err := call.Pages(ctx, func(resp *securitycenter.ListFindingsResponse) error {
		for _, res := range resp.ListFindingsResults {
			if res == nil || res.Finding == nil {
				continue
			}
			out = append(out, toFinding(res.Finding, res.Resource))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// toFinding projects an SCC v1 finding (plus its result-wrapper resource)
// into the plugin-local Finding.
func toFinding(f *securitycenter.Finding, res *securitycenter.Resource) Finding {
	out := Finding{
		Name:           f.Name,
		ResourceName:   f.ResourceName,
		Category:       f.Category,
		Severity:       f.Severity,
		State:          f.State,
		Mute:           f.Mute,
		FindingClass:   f.FindingClass,
		HasRemediation: f.NextSteps != "",
	}
	if res != nil {
		out.ResourceType = res.Type
	}
	if f.Vulnerability != nil && f.Vulnerability.Cve != nil {
		out.CVEID = f.Vulnerability.Cve.Id
		if f.Vulnerability.Cve.Cvssv3 != nil {
			out.CVSSScore = f.Vulnerability.Cve.Cvssv3.BaseScore
		}
	}
	return out
}

var _ core.SourcePlugin = (*Plugin)(nil)
