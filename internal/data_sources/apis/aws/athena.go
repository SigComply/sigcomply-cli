package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// AthenaClient defines the interface for Athena operations.
type AthenaClient interface {
	ListWorkGroups(ctx context.Context, params *athena.ListWorkGroupsInput, optFns ...func(*athena.Options)) (*athena.ListWorkGroupsOutput, error)
	GetWorkGroup(ctx context.Context, params *athena.GetWorkGroupInput, optFns ...func(*athena.Options)) (*athena.GetWorkGroupOutput, error)
}

// AthenaWorkgroup represents an Athena workgroup.
type AthenaWorkgroup struct {
	Name                     string `json:"name"`
	ARN                      string `json:"arn"`
	PublishCloudWatchMetrics bool   `json:"publish_cloudwatch_metrics"`
}

// ToEvidence converts an AthenaWorkgroup to Evidence.
func (w *AthenaWorkgroup) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(w) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:athena:workgroup", w.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// AthenaCollector collects Athena workgroup data.
type AthenaCollector struct {
	client AthenaClient
}

// NewAthenaCollector creates a new Athena collector.
func NewAthenaCollector(client AthenaClient) *AthenaCollector {
	return &AthenaCollector{client: client}
}

// CollectWorkgroups retrieves all Athena workgroups.
func (c *AthenaCollector) CollectWorkgroups(ctx context.Context) ([]AthenaWorkgroup, error) {
	var workgroups []AthenaWorkgroup
	var nextToken *string

	for {
		output, err := c.client.ListWorkGroups(ctx, &athena.ListWorkGroupsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list Athena workgroups: %w", err)
		}

		for _, wg := range output.WorkGroups {
			name := awssdk.ToString(wg.Name)
			workgroup := AthenaWorkgroup{
				Name: name,
			}

			c.enrichWorkgroup(ctx, &workgroup)
			workgroups = append(workgroups, workgroup)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return workgroups, nil
}

// enrichWorkgroup fetches detailed workgroup configuration.
func (c *AthenaCollector) enrichWorkgroup(ctx context.Context, wg *AthenaWorkgroup) {
	output, err := c.client.GetWorkGroup(ctx, &athena.GetWorkGroupInput{
		WorkGroup: awssdk.String(wg.Name),
	})
	if err != nil {
		return // Fail-safe
	}

	if output.WorkGroup != nil {
		if output.WorkGroup.Configuration != nil {
			wg.PublishCloudWatchMetrics = awssdk.ToBool(output.WorkGroup.Configuration.PublishCloudWatchMetricsEnabled)
		}
		// Build ARN from the workgroup description (not available in the summary)
		// The ARN format: arn:aws:athena:<region>:<account>:workgroup/<name>
		// We'll use the name for resource_id since ARN isn't directly provided in GetWorkGroup
	}
}

// CollectEvidence collects Athena workgroups as evidence.
func (c *AthenaCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	workgroups, err := c.CollectWorkgroups(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(workgroups))
	for i := range workgroups {
		evidenceList = append(evidenceList, workgroups[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
