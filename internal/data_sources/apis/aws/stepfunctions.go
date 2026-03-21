package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// StepFunctionsClient defines the interface for Step Functions operations.
type StepFunctionsClient interface {
	ListStateMachines(ctx context.Context, params *sfn.ListStateMachinesInput, optFns ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error)
	DescribeStateMachine(ctx context.Context, params *sfn.DescribeStateMachineInput, optFns ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error)
}

// StepFunctionsStateMachine represents a Step Functions state machine.
type StepFunctionsStateMachine struct {
	Name           string `json:"name"`
	ARN            string `json:"arn"`
	LoggingEnabled bool   `json:"logging_enabled"`
	TracingEnabled bool   `json:"tracing_enabled"`
}

// ToEvidence converts a StepFunctionsStateMachine to Evidence.
func (sm *StepFunctionsStateMachine) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(sm) //nolint:errcheck
	ev := evidence.New("aws", "aws:stepfunctions:state-machine", sm.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// StepFunctionsCollector collects Step Functions state machine data.
type StepFunctionsCollector struct {
	client StepFunctionsClient
}

// NewStepFunctionsCollector creates a new Step Functions collector.
func NewStepFunctionsCollector(client StepFunctionsClient) *StepFunctionsCollector {
	return &StepFunctionsCollector{client: client}
}

// CollectStateMachines retrieves all Step Functions state machines.
func (c *StepFunctionsCollector) CollectStateMachines(ctx context.Context) ([]StepFunctionsStateMachine, error) {
	var stateMachines []StepFunctionsStateMachine
	var nextToken *string

	for {
		output, err := c.client.ListStateMachines(ctx, &sfn.ListStateMachinesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list Step Functions state machines: %w", err)
		}

		for _, item := range output.StateMachines {
			sm := StepFunctionsStateMachine{
				Name: awssdk.ToString(item.Name),
				ARN:  awssdk.ToString(item.StateMachineArn),
			}

			// Enrich with logging configuration
			c.enrichLoggingConfig(ctx, &sm)

			stateMachines = append(stateMachines, sm)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return stateMachines, nil
}

// enrichLoggingConfig checks if CloudWatch logging is enabled for a state machine.
func (c *StepFunctionsCollector) enrichLoggingConfig(ctx context.Context, sm *StepFunctionsStateMachine) {
	output, err := c.client.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
		StateMachineArn: awssdk.String(sm.ARN),
	})
	if err != nil {
		return // Fail-safe
	}

	if output.LoggingConfiguration != nil {
		sm.LoggingEnabled = output.LoggingConfiguration.Level != sfntypes.LogLevelOff
	}

	if output.TracingConfiguration != nil {
		sm.TracingEnabled = output.TracingConfiguration.Enabled
	}
}

// CollectEvidence collects Step Functions state machines as evidence.
func (c *StepFunctionsCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	stateMachines, err := c.CollectStateMachines(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(stateMachines))
	for i := range stateMachines {
		evidenceList = append(evidenceList, stateMachines[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
