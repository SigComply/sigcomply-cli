// Package inspector implements the aws.inspector source plugin: lists AWS
// Inspector2 findings and emits vulnerability_finding evidence records with
// cross-vendor severity, status, CVE, and remediation attributes.
package inspector

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	inspector2 "github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspector2types "github.com/aws/aws-sdk-go-v2/service/inspector2/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "vulnerability_finding"

// SourceID is the registered ID for the aws.inspector plugin instance.
const SourceID = "aws.inspector"

// Normalized severity values (must match the vulnerability_finding schema enum).
const (
	severityCritical      = "CRITICAL"
	severityHigh          = "HIGH"
	severityMedium        = "MEDIUM"
	severityLow           = "LOW"
	severityInformational = "INFORMATIONAL"
)

// Normalized status values (must match the vulnerability_finding schema enum).
const (
	statusActive     = "ACTIVE"
	statusSuppressed = "SUPPRESSED"
	statusResolved   = "RESOLVED"
)

// API is the subset of the Inspector2 client this plugin uses.
type API interface {
	ListFindings(ctx context.Context, params *inspector2.ListFindingsInput, optFns ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error)
}

// Plugin is the in-process aws.inspector source.
type Plugin struct {
	api    API
	region string
	now    func() time.Time
}

// Options is the constructor input.
type Options struct {
	API    API
	Region string
	Now    func() time.Time
}

// New constructs a Plugin around an explicit API implementation.
func New(opts Options) *Plugin {
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Plugin{
		api:    opts.API,
		region: opts.Region,
		now:    now,
	}
}

// NewFromAWS constructs a Plugin backed by the real AWS SDK.
func NewFromAWS(ctx context.Context, region string) (*Plugin, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws.inspector: load AWS config: %w", err)
	}
	return New(Options{
		API:    inspector2.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// findingPayload is the cross-vendor vulnerability_finding shape.
type findingPayload struct {
	ID                   string   `json:"id"`
	ResourceID           string   `json:"resource_id"`
	ResourceType         string   `json:"resource_type"`
	Title                string   `json:"title,omitempty"`
	Severity             string   `json:"severity"`
	Status               string   `json:"status"`
	CVEID                string   `json:"cve_id,omitempty"`
	Score                *float64 `json:"score,omitempty"`
	RemediationAvailable bool     `json:"remediation_available"`
	Provider             string   `json:"provider"`
}

// Collect lists Inspector2 findings and returns one vulnerability_finding record per finding.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.inspector: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	findings, err := p.listAllFindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.inspector: list findings: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		id := safeString(f.FindingArn)
		if id == "" {
			continue
		}
		payload := toPayload(f)
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.inspector: marshal payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          id,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// toPayload maps an Inspector2 finding to the cross-vendor schema shape.
func toPayload(f *inspector2types.Finding) findingPayload {
	resourceID, resourceType := firstResource(f)
	return findingPayload{
		ID:                   safeString(f.FindingArn),
		ResourceID:           resourceID,
		ResourceType:         resourceType,
		Title:                safeString(f.Title),
		Severity:             normalizeSeverity(f.Severity),
		Status:               normalizeStatus(f.Status),
		CVEID:                cveID(f),
		Score:                f.InspectorScore,
		RemediationAvailable: remediationAvailable(f),
		Provider:             "aws",
	}
}

func (p *Plugin) listAllFindings(ctx context.Context) ([]inspector2types.Finding, error) {
	var (
		out       []inspector2types.Finding
		nextToken *string
	)
	for {
		page, err := p.api.ListFindings(ctx, &inspector2.ListFindingsInput{NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Findings...)
		if page.NextToken != nil && *page.NextToken != "" {
			nextToken = page.NextToken
			continue
		}
		return out, nil
	}
}

// firstResource returns the ID and type of the first affected resource.
func firstResource(f *inspector2types.Finding) (id, resourceType string) {
	if f == nil || len(f.Resources) == 0 {
		return "", ""
	}
	r := &f.Resources[0]
	return safeString(r.Id), string(r.Type)
}

// normalizeSeverity maps an Inspector2 severity to the schema enum. UNTRIAGED
// (vendor has not yet assigned a severity) maps to INFORMATIONAL.
func normalizeSeverity(s inspector2types.Severity) string {
	switch s {
	case inspector2types.SeverityCritical:
		return severityCritical
	case inspector2types.SeverityHigh:
		return severityHigh
	case inspector2types.SeverityMedium:
		return severityMedium
	case inspector2types.SeverityLow:
		return severityLow
	case inspector2types.SeverityInformational, inspector2types.SeverityUntriaged:
		return severityInformational
	default:
		return severityInformational
	}
}

// normalizeStatus maps an Inspector2 finding status to the schema enum.
// CLOSED maps to RESOLVED.
func normalizeStatus(s inspector2types.FindingStatus) string {
	switch s {
	case inspector2types.FindingStatusActive:
		return statusActive
	case inspector2types.FindingStatusSuppressed:
		return statusSuppressed
	case inspector2types.FindingStatusClosed:
		return statusResolved
	default:
		return statusActive
	}
}

// cveID returns the package-vulnerability CVE identifier when present.
func cveID(f *inspector2types.Finding) string {
	if f == nil || f.PackageVulnerabilityDetails == nil {
		return ""
	}
	return safeString(f.PackageVulnerabilityDetails.VulnerabilityId)
}

// remediationAvailable reports whether the finding carries a remediation
// recommendation text.
func remediationAvailable(f *inspector2types.Finding) bool {
	if f == nil || f.Remediation == nil || f.Remediation.Recommendation == nil {
		return false
	}
	return safeString(f.Remediation.Recommendation.Text) != ""
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var _ core.SourcePlugin = (*Plugin)(nil)
