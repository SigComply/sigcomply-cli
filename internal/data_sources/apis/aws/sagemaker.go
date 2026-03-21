package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// SageMakerClient defines the interface for SageMaker operations.
type SageMakerClient interface {
	ListNotebookInstances(ctx context.Context, params *sagemaker.ListNotebookInstancesInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListNotebookInstancesOutput, error)
	DescribeNotebookInstance(ctx context.Context, params *sagemaker.DescribeNotebookInstanceInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeNotebookInstanceOutput, error)
}

// SageMakerNotebook represents a SageMaker notebook instance.
type SageMakerNotebook struct {
	Name                 string `json:"name"`
	ARN                  string `json:"arn"`
	DirectInternetAccess bool   `json:"direct_internet_access"`
	RootAccess           bool   `json:"root_access"`
	SubnetID             string `json:"subnet_id,omitempty"`
}

// ToEvidence converts a SageMakerNotebook to Evidence.
func (n *SageMakerNotebook) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(n) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:sagemaker:notebook", n.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// SageMakerCollector collects SageMaker data.
type SageMakerCollector struct {
	client SageMakerClient
}

// NewSageMakerCollector creates a new SageMaker collector.
func NewSageMakerCollector(client SageMakerClient) *SageMakerCollector {
	return &SageMakerCollector{client: client}
}

// CollectNotebooks retrieves all SageMaker notebook instances.
func (c *SageMakerCollector) CollectNotebooks(ctx context.Context) ([]SageMakerNotebook, error) {
	var notebooks []SageMakerNotebook
	var nextToken *string

	for {
		output, err := c.client.ListNotebookInstances(ctx, &sagemaker.ListNotebookInstancesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list SageMaker notebook instances: %w", err)
		}

		for _, nb := range output.NotebookInstances {
			name := awssdk.ToString(nb.NotebookInstanceName)
			notebook := SageMakerNotebook{
				Name: name,
				ARN:  awssdk.ToString(nb.NotebookInstanceArn),
			}

			// Get detailed info
			desc, err := c.client.DescribeNotebookInstance(ctx, &sagemaker.DescribeNotebookInstanceInput{
				NotebookInstanceName: awssdk.String(name),
			})
			if err == nil {
				notebook.DirectInternetAccess = string(desc.DirectInternetAccess) == "Enabled"
				notebook.RootAccess = string(desc.RootAccess) == "Enabled"
				notebook.SubnetID = awssdk.ToString(desc.SubnetId)
			}

			notebooks = append(notebooks, notebook)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return notebooks, nil
}

// CollectEvidence collects SageMaker notebooks as evidence.
func (c *SageMakerCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	notebooks, err := c.CollectNotebooks(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(notebooks))
	for i := range notebooks {
		evidenceList = append(evidenceList, notebooks[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
