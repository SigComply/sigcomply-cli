package aws

import (
	"context"
	"encoding/json"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// LambdaClient defines the interface for Lambda operations.
type LambdaClient interface {
	ListFunctions(ctx context.Context, params *lambda.ListFunctionsInput, optFns ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
	GetPolicy(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}

// LambdaFunction represents a Lambda function with security configuration.
type LambdaFunction struct {
	Name               string `json:"name"`
	ARN                string `json:"arn"`
	Runtime            string `json:"runtime"`
	RuntimeDeprecated  bool `json:"runtime_deprecated"`
	VPCConfigured      bool `json:"vpc_configured"`
	HasDLQ               bool `json:"has_dlq"`
	PubliclyAccessible   bool `json:"publicly_accessible"`
	CodeSigningEnabled   bool `json:"code_signing_enabled"`
	ReservedConcurrency  int  `json:"reserved_concurrency"`
	TracingMode          string `json:"tracing_mode"`
}

// deprecatedRuntimes lists known deprecated Lambda runtimes.
var deprecatedRuntimes = map[string]bool{
	"python2.7":    true,
	"python3.6":    true,
	"python3.7":    true,
	"python3.8":    true,
	"nodejs10.x":   true,
	"nodejs12.x":   true,
	"nodejs14.x":   true,
	"dotnetcore2.1": true,
	"dotnetcore3.1": true,
	"dotnet5.0":     true,
	"ruby2.5":       true,
	"ruby2.7":       true,
	"java8":         true,
	"go1.x":         true,
}

// ToEvidence converts a LambdaFunction to Evidence.
func (f *LambdaFunction) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(f) //nolint:errcheck
	ev := evidence.New("aws", "aws:lambda:function", f.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// LambdaCollector collects Lambda function data.
type LambdaCollector struct {
	client LambdaClient
}

// NewLambdaCollector creates a new Lambda collector.
func NewLambdaCollector(client LambdaClient) *LambdaCollector {
	return &LambdaCollector{client: client}
}

// CollectFunctions retrieves all Lambda functions with security info.
func (c *LambdaCollector) CollectFunctions(ctx context.Context) ([]LambdaFunction, error) {
	var functions []LambdaFunction
	var marker *string

	for {
		output, err := c.client.ListFunctions(ctx, &lambda.ListFunctionsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, err
		}

		for _, fn := range output.Functions {
			f := LambdaFunction{
				Name:    awssdk.ToString(fn.FunctionName),
				ARN:     awssdk.ToString(fn.FunctionArn),
				Runtime: string(fn.Runtime),
			}
			f.RuntimeDeprecated = deprecatedRuntimes[f.Runtime]
			f.VPCConfigured = fn.VpcConfig != nil && len(fn.VpcConfig.SubnetIds) > 0
			f.HasDLQ = fn.DeadLetterConfig != nil && awssdk.ToString(fn.DeadLetterConfig.TargetArn) != ""
			f.CodeSigningEnabled = false // Not available in ListFunctions, would need GetFunction
			f.ReservedConcurrency = -1  // Not available in ListFunctions, would need GetFunctionConcurrency

			if fn.TracingConfig != nil {
				f.TracingMode = string(fn.TracingConfig.Mode)
			}

			// Check if publicly accessible via resource policy
			c.enrichPublicAccess(ctx, &f)

			functions = append(functions, f)
		}

		if output.NextMarker == nil {
			break
		}
		marker = output.NextMarker
	}

	return functions, nil
}

// enrichPublicAccess checks if the function has a public resource policy.
func (c *LambdaCollector) enrichPublicAccess(ctx context.Context, fn *LambdaFunction) {
	output, err := c.client.GetPolicy(ctx, &lambda.GetPolicyInput{
		FunctionName: awssdk.String(fn.Name),
	})
	if err != nil {
		return // No policy or access denied
	}

	policy := awssdk.ToString(output.Policy)
	if strings.Contains(policy, `"Principal":"*"`) || strings.Contains(policy, `"Principal": "*"`) {
		fn.PubliclyAccessible = true
	}
}

// CollectEvidence collects Lambda functions as evidence.
func (c *LambdaCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	functions, err := c.CollectFunctions(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(functions))
	for i := range functions {
		evidenceList = append(evidenceList, functions[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
