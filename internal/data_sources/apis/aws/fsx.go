package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// FSxClient defines the interface for FSx operations.
type FSxClient interface {
	DescribeFileSystems(ctx context.Context, params *fsx.DescribeFileSystemsInput, optFns ...func(*fsx.Options)) (*fsx.DescribeFileSystemsOutput, error)
}

// FSxFilesystem represents an FSx file system.
type FSxFilesystem struct {
	FileSystemID   string `json:"file_system_id"`
	ARN            string `json:"arn"`
	FileSystemType string `json:"file_system_type"`
	MultiAZ        bool   `json:"multi_az"`
	Encrypted      bool   `json:"encrypted"`
	KMSKeyID       string `json:"kms_key_id,omitempty"`
}

// ToEvidence converts an FSxFilesystem to Evidence.
func (f *FSxFilesystem) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(f) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:fsx:filesystem", f.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// FSxCollector collects FSx file system data.
type FSxCollector struct {
	client FSxClient
}

// NewFSxCollector creates a new FSx collector.
func NewFSxCollector(client FSxClient) *FSxCollector {
	return &FSxCollector{client: client}
}

// CollectFileSystems retrieves all FSx file systems.
func (c *FSxCollector) CollectFileSystems(ctx context.Context) ([]FSxFilesystem, error) {
	var fileSystems []FSxFilesystem
	var nextToken *string

	for {
		output, err := c.client.DescribeFileSystems(ctx, &fsx.DescribeFileSystemsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe FSx file systems: %w", err)
		}

		for i := range output.FileSystems {
			fs := &output.FileSystems[i]
			filesystem := FSxFilesystem{
				FileSystemID:   awssdk.ToString(fs.FileSystemId),
				ARN:            awssdk.ToString(fs.ResourceARN),
				FileSystemType: string(fs.FileSystemType),
				MultiAZ:        len(fs.SubnetIds) > 1,
				KMSKeyID:       awssdk.ToString(fs.KmsKeyId),
			}
			filesystem.Encrypted = filesystem.KMSKeyID != ""
			fileSystems = append(fileSystems, filesystem)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return fileSystems, nil
}

// CollectEvidence collects FSx file systems as evidence.
func (c *FSxCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	fileSystems, err := c.CollectFileSystems(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(fileSystems))
	for i := range fileSystems {
		evidenceList = append(evidenceList, fileSystems[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
