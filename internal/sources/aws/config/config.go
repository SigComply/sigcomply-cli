// Package config implements the aws.config source plugin: lists AWS
// Config configuration recorders along with their recording status, and
// emits config_recorder evidence records suitable for SOC 2
// change-tracking policies (Config recorder enabled and recording).
//
// The "config" package name collides with Go's idiomatic name for
// project-config types — within this codebase it is referenced from the
// orchestrator with an alias such as `awsconfigsrc` to disambiguate
// from internal/spec and the AWS SDK's awsconfig import.
//
// Per the KISS-no-DRY axiom (docs/architecture/04-source-plugins.md
// §The plugin contract), the plugin caches nothing across Collect
// calls.
//
// Test injection: the API interface mirrors the pattern used by
// internal/sources/aws/iam — the concrete *configservice.Client
// satisfies it, and unit tests inject an in-memory fake.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	cfgsvc "github.com/aws/aws-sdk-go-v2/service/configservice"
	cfgtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the single evidence type this plugin emits today.
const EvidenceTypeID = "config_recorder"

// SourceID is the registered ID for the aws.config plugin instance.
const SourceID = "aws.config"

// API is the subset of the AWS Config client this plugin uses. Defining
// it as an interface lets tests inject a fake; the concrete
// *configservice.Client satisfies it.
type API interface {
	DescribeConfigurationRecorders(ctx context.Context, params *cfgsvc.DescribeConfigurationRecordersInput, optFns ...func(*cfgsvc.Options)) (*cfgsvc.DescribeConfigurationRecordersOutput, error)
	DescribeConfigurationRecorderStatus(ctx context.Context, params *cfgsvc.DescribeConfigurationRecorderStatusInput, optFns ...func(*cfgsvc.Options)) (*cfgsvc.DescribeConfigurationRecorderStatusOutput, error)
}

// Plugin is the in-process aws.config source.
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
		return nil, fmt.Errorf("aws.config: load AWS config: %w", err)
	}
	return New(Options{
		API:    cfgsvc.NewFromConfig(cfg),
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

// recorderPayload is the shape of the JSON payload inside each
// config_recorder record.
type recorderPayload struct {
	Name             string `json:"name"`
	ARN              string `json:"arn,omitempty"`
	Recording        bool   `json:"recording"`
	LastStatus       string `json:"last_status,omitempty"`
	LastErrorCode    string `json:"last_error_code,omitempty"`
	LastErrorMessage string `json:"last_error_message,omitempty"`
}

// Collect lists Configuration Recorders in the configured region and
// returns one config_recorder per recorder. Records are sorted by ID
// before return so envelope bytes are stable across runs against
// stable account state.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if req.EvidenceType != EvidenceTypeID {
		return nil, fmt.Errorf("aws.config: unsupported evidence type %q (only %q)", req.EvidenceType, EvidenceTypeID)
	}
	descOut, err := p.api.DescribeConfigurationRecorders(ctx, &cfgsvc.DescribeConfigurationRecordersInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.config: describe recorders: %w", err)
	}
	statusOut, err := p.api.DescribeConfigurationRecorderStatus(ctx, &cfgsvc.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return nil, fmt.Errorf("aws.config: describe recorder status: %w", err)
	}
	statusByName := make(map[string]cfgtypes.ConfigurationRecorderStatus, len(statusOut.ConfigurationRecordersStatus))
	for i := range statusOut.ConfigurationRecordersStatus {
		s := statusOut.ConfigurationRecordersStatus[i]
		if s.Name != nil {
			statusByName[*s.Name] = s
		}
	}

	records := make([]core.EvidenceRecord, 0, len(descOut.ConfigurationRecorders))
	now := p.now()
	for i := range descOut.ConfigurationRecorders {
		r := &descOut.ConfigurationRecorders[i]
		name := safeStr(r.Name)
		arn := safeStr(r.Arn)
		id := arn
		if id == "" {
			id = name
		}
		s := statusByName[name]
		payload := recorderPayload{
			Name:             name,
			ARN:              arn,
			Recording:        s.Recording,
			LastStatus:       string(s.LastStatus),
			LastErrorCode:    safeStr(s.LastErrorCode),
			LastErrorMessage: safeStr(s.LastErrorMessage),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.config: marshal recorder payload: %w", err)
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

func safeStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var _ core.SourcePlugin = (*Plugin)(nil)
