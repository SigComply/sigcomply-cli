// Package lambda implements the aws.lambda source plugin: lists AWS Lambda
// functions and emits serverless_function evidence records with cross-vendor
// VPC-placement, tracing, and environment-variable-encryption attributes.
package lambda

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// EvidenceTypeID is the evidence type this plugin emits.
const EvidenceTypeID = "serverless_function"

// SourceID is the registered ID for the aws.lambda plugin instance.
const SourceID = "aws.lambda"

// tracingModeActive is the TracingConfig mode that means active tracing.
const tracingModeActive = "Active"

// API is the subset of the Lambda client this plugin uses.
type API interface {
	ListFunctions(ctx context.Context, params *awslambda.ListFunctionsInput, optFns ...func(*awslambda.Options)) (*awslambda.ListFunctionsOutput, error)
}

// Plugin is the in-process aws.lambda source.
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
		return nil, fmt.Errorf("aws.lambda: load AWS config: %w", err)
	}
	return New(Options{
		API:    awslambda.NewFromConfig(cfg),
		Region: region,
	}), nil
}

// ID returns the registered plugin ID.
func (*Plugin) ID() string { return SourceID }

// Emits returns the evidence types this plugin can produce.
func (*Plugin) Emits() []string { return []string{EvidenceTypeID} }

// Init is a no-op; configuration is supplied to the constructor.
func (*Plugin) Init(context.Context, map[string]any) error { return nil }

// functionPayload is the cross-vendor serverless_function shape.
//
// reserved_concurrency_set is intentionally NOT emitted: it is an
// AWS-Lambda-specific knob (requires a per-function GetFunctionConcurrency
// call) that is not universally measurable across GCP Cloud Functions /
// Azure Functions, so it is neither required by the schema nor read by any
// policy.
type functionPayload struct {
	ID                            string `json:"id"`
	Name                          string `json:"name"`
	Provider                      string `json:"provider"`
	Runtime                       string `json:"runtime"`
	IsInVPC                       bool   `json:"is_in_vpc"`
	TracingEnabled                bool   `json:"tracing_enabled"`
	EnvironmentVariablesEncrypted bool   `json:"environment_variables_encrypted"`
}

// Collect lists functions and returns one serverless_function record per function.
func (p *Plugin) Collect(ctx context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	if !req.Accepts(EvidenceTypeID) {
		return nil, fmt.Errorf("aws.lambda: slot AcceptedTypes %v does not include %q", req.AcceptedTypes, EvidenceTypeID)
	}
	functions, err := p.listAllFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws.lambda: list functions: %w", err)
	}
	now := p.now()
	records := make([]core.EvidenceRecord, 0, len(functions))
	for i := range functions {
		fn := &functions[i]
		id := safeString(fn.FunctionName)
		if id == "" {
			continue
		}
		payload := functionPayload{
			ID:                            id,
			Name:                          id,
			Provider:                      "aws",
			Runtime:                       string(fn.Runtime),
			IsInVPC:                       isInVPC(fn),
			TracingEnabled:                tracingEnabled(fn),
			EnvironmentVariablesEncrypted: safeString(fn.KMSKeyArn) != "",
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("aws.lambda: marshal payload: %w", err)
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

func (p *Plugin) listAllFunctions(ctx context.Context) ([]lambdatypes.FunctionConfiguration, error) {
	var (
		out    []lambdatypes.FunctionConfiguration
		marker *string
	)
	for {
		page, err := p.api.ListFunctions(ctx, &awslambda.ListFunctionsInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Functions...)
		if page.NextMarker != nil && *page.NextMarker != "" {
			marker = page.NextMarker
			continue
		}
		return out, nil
	}
}

// isInVPC reports whether the function is attached to a VPC (has subnets).
func isInVPC(fn *lambdatypes.FunctionConfiguration) bool {
	if fn == nil || fn.VpcConfig == nil {
		return false
	}
	return len(fn.VpcConfig.SubnetIds) > 0
}

// tracingEnabled reports whether active distributed tracing is configured.
func tracingEnabled(fn *lambdatypes.FunctionConfiguration) bool {
	if fn == nil || fn.TracingConfig == nil {
		return false
	}
	return string(fn.TracingConfig.Mode) == tracingModeActive
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

var _ core.SourcePlugin = (*Plugin)(nil)
