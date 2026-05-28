// Package guardduty implements the aws.guardduty source plugin: lists
// GuardDuty detectors in one AWS account along with each detector's
// status, and emits threat_detection_service evidence records suitable for
// SOC 2 threat-detection policies (GuardDuty enabled).
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect
// calls.
//
// Test injection: the API interface mirrors the pattern used by
// internal/sources/aws/iam — the concrete *guardduty.Client satisfies
// it, and unit tests inject an in-memory fake.
package guardduty

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the cross-vendor evidence type this plugin emits.
const EvidenceTypeID = "threat_detection_service"

// SourceID is the registered ID for the aws.guardduty plugin instance.
const SourceID = "aws.guardduty"

// API is the subset of the GuardDuty client this plugin uses. Defining
// it as an interface lets tests inject a fake; the concrete
// *guardduty.Client satisfies it.
type API interface {
	ListDetectors(ctx context.Context, params *gd.ListDetectorsInput, optFns ...func(*gd.Options)) (*gd.ListDetectorsOutput, error)
	GetDetector(ctx context.Context, params *gd.GetDetectorInput, optFns ...func(*gd.Options)) (*gd.GetDetectorOutput, error)
}

// Plugin is the in-process aws.guardduty source.
type Plugin struct {
	api    API
	region string
	now    func() time.Time
}

// Options is the constructor input.
type Options struct {
	API    API
	Region string
	// Now is injected so tests can produce deterministic CollectedAt
	// values. Production callers leave it nil → time.Now().UTC().
	Now func() time.Time
}

// New constructs a Plugin around an explicit API implementation.
// Callers using the real AWS SDK should use NewFromAWS.
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

// NewFromAWS constructs a Plugin backed by the real AWS SDK using the
// default credential chain.
func NewFromAWS(ctx context.Context, region string) (*Plugin, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws.guardduty: load AWS config: %w", err)
	}
	return New(Options{
		API:    gd.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init accepts plugin config (currently just region) but the
// constructor already has it; this is a no-op preserved for symmetry.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// detectorPayload is the cross-vendor threat_detection_service shape.
type detectorPayload struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	Region    string `json:"region,omitempty"`
	IsEnabled bool   `json:"is_enabled"`
	// AWS-specific extras
	Status                     string `json:"status,omitempty"`
	ServiceRole                string `json:"service_role,omitempty"`
	FindingPublishingFrequency string `json:"finding_publishing_frequency,omitempty"`
}

// Collect lists GuardDuty detectors in the configured region and
// returns one threat_detection_service record per detector, sorted by ID
// before return so envelope bytes are stable across runs against
// stable account state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.guardduty: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	ids, err := p.listAllDetectorIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.guardduty: list detectors: %w", err)
	}
	records := make([]core.EvidenceRecord, 0, len(ids))
	now := p.now()
	for _, id := range ids {
		detID := id
		out, err := p.api.GetDetector(ctx, &gd.GetDetectorInput{DetectorId: &detID})
		if err != nil {
			return nil, fmt.Errorf("aws.guardduty: get detector %s: %w", id, err)
		}
		payload := detectorPayload{
			ID:                         id,
			Name:                       id,
			Provider:                   "aws",
			Region:                     p.region,
			IsEnabled:                  out.Status == gdtypes.DetectorStatusEnabled,
			Status:                     string(out.Status),
			ServiceRole:                safeStr(out.ServiceRole),
			FindingPublishingFrequency: string(out.FindingPublishingFrequency),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.guardduty: marshal detector payload: %w", err)
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

func (p *Plugin) listAllDetectorIDs(ctx context.Context) ([]string, error) {
	var (
		out   []string
		token *string
	)
	for {
		page, err := p.api.ListDetectors(ctx, &gd.ListDetectorsInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		out = append(out, page.DetectorIds...)
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}

func safeStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var _ core.SourcePlugin = (*Plugin)(nil)
