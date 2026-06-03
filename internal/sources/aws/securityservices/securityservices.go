// Package securityservices implements the aws.security_services source
// plugin: probes account-level enablement of AWS Macie, Inspector, and
// SecurityHub and emits one security_service evidence record per service.
package securityservices

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspectortypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	macietypes "github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	securityhubtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "security_service"

// SourceID is the registered ID for the aws.security_services plugin instance.
const SourceID = "aws.security_services"

// service_type literals — must match the values the consuming policies
// compare against (soc2 cc6.8/cc7.1, iso27001 8.16).
const (
	serviceTypeDLP                  = "dlp"
	serviceTypeSIEM                 = "siem"
	serviceTypeVulnerabilityScanner = "vulnerability_scanner"
)

// statusEnabled is the SDK enum string shared by Macie and Inspector for an
// active service.
const statusEnabled = "ENABLED"

// Per-service record identifiers and human-readable names.
const (
	idMacie       = "aws-macie"
	idInspector   = "aws-inspector"
	idSecurityHub = "aws-securityhub"

	nameMacie       = "Amazon Macie"
	nameInspector   = "Amazon Inspector"
	nameSecurityHub = "AWS Security Hub"
)

// API is the subset of the AWS clients this plugin uses. Injecting one
// interface lets tests substitute a single fake for all three services.
type API interface {
	GetMacieSession(ctx context.Context, params *macie2.GetMacieSessionInput, optFns ...func(*macie2.Options)) (*macie2.GetMacieSessionOutput, error)
	BatchGetAccountStatus(ctx context.Context, params *inspector2.BatchGetAccountStatusInput, optFns ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error)
	DescribeHub(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error)
}

// Plugin is the in-process aws.security_services source.
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

// awsClients bundles the three real SDK clients behind the API interface.
type awsClients struct {
	macie       *macie2.Client
	inspector   *inspector2.Client
	securityhub *securityhub.Client
}

func (c *awsClients) GetMacieSession(ctx context.Context, params *macie2.GetMacieSessionInput, optFns ...func(*macie2.Options)) (*macie2.GetMacieSessionOutput, error) {
	return c.macie.GetMacieSession(ctx, params, optFns...)
}

func (c *awsClients) BatchGetAccountStatus(ctx context.Context, params *inspector2.BatchGetAccountStatusInput, optFns ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error) {
	return c.inspector.BatchGetAccountStatus(ctx, params, optFns...)
}

func (c *awsClients) DescribeHub(ctx context.Context, params *securityhub.DescribeHubInput, optFns ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
	return c.securityhub.DescribeHub(ctx, params, optFns...)
}

// NewFromAWS constructs a Plugin backed by the real AWS SDK.
func NewFromAWS(ctx context.Context, region string) (*Plugin, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws.security_services: load AWS config: %w", err)
	}
	return New(Options{
		API: &awsClients{
			macie:       macie2.NewFromConfig(cfg),
			inspector:   inspector2.NewFromConfig(cfg),
			securityhub: securityhub.NewFromConfig(cfg),
		},
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// servicePayload is the cross-vendor security_service shape.
type servicePayload struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	ServiceType string `json:"service_type"`
	IsEnabled   bool   `json:"is_enabled"`
}

// Collect probes each security service's account-level enablement and
// returns exactly one record per service (3 records, sorted by ID).
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.security_services: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}

	macieEnabled, err := p.macieEnabled(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.security_services: macie status: %w", err)
	}
	inspectorEnabled, err := p.inspectorEnabled(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.security_services: inspector status: %w", err)
	}
	securityHubEnabled, err := p.securityHubEnabled(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.security_services: securityhub status: %w", err)
	}

	payloads := []servicePayload{
		{ID: idMacie, Name: nameMacie, Provider: "aws", ServiceType: serviceTypeDLP, IsEnabled: macieEnabled},
		{ID: idInspector, Name: nameInspector, Provider: "aws", ServiceType: serviceTypeVulnerabilityScanner, IsEnabled: inspectorEnabled},
		{ID: idSecurityHub, Name: nameSecurityHub, Provider: "aws", ServiceType: serviceTypeSIEM, IsEnabled: securityHubEnabled},
	}

	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(payloads))
	for i := range payloads {
		body, err := json.Marshal(payloads[i])
		if err != nil {
			return nil, fmt.Errorf("aws.security_services: marshal payload: %w", err)
		}
		records = append(records, core.EvidenceRecord{
			Type:        EvidenceTypeID,
			ID:          payloads[i].ID,
			Payload:     body,
			SourceID:    SourceID,
			CollectedAt: now,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })
	return records, nil
}

// macieEnabled reports whether Macie is active on the account. A
// disabled account answers with AccessDeniedException (Macie not enabled)
// or PAUSED status — both map to is_enabled=false, not a hard error.
func (p *Plugin) macieEnabled(ctx context.Context) (bool, error) {
	out, err := p.api.GetMacieSession(ctx, &macie2.GetMacieSessionInput{})
	if err != nil {
		var accessDenied *macietypes.AccessDeniedException
		var notFound *macietypes.ResourceNotFoundException
		if errors.As(err, &accessDenied) || errors.As(err, &notFound) {
			return false, nil
		}
		return false, err
	}
	return string(out.Status) == statusEnabled, nil
}

// inspectorEnabled reports whether Inspector is active for the calling
// account. An empty AccountIds list scopes the call to the caller.
func (p *Plugin) inspectorEnabled(ctx context.Context) (bool, error) {
	out, err := p.api.BatchGetAccountStatus(ctx, &inspector2.BatchGetAccountStatusInput{})
	if err != nil {
		var accessDenied *inspectortypes.AccessDeniedException
		if errors.As(err, &accessDenied) {
			return false, nil
		}
		return false, err
	}
	for i := range out.Accounts {
		acct := &out.Accounts[i]
		if acct.State != nil && string(acct.State.Status) == statusEnabled {
			return true, nil
		}
	}
	return false, nil
}

// securityHubEnabled reports whether Security Hub is active. A disabled
// account answers DescribeHub with ResourceNotFoundException or
// InvalidAccessException — both map to is_enabled=false, not a hard error.
func (p *Plugin) securityHubEnabled(ctx context.Context) (bool, error) {
	_, err := p.api.DescribeHub(ctx, &securityhub.DescribeHubInput{})
	if err != nil {
		var notFound *securityhubtypes.ResourceNotFoundException
		var invalidAccess *securityhubtypes.InvalidAccessException
		if errors.As(err, &notFound) || errors.As(err, &invalidAccess) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

var _ core.SourcePlugin = (*Plugin)(nil)
