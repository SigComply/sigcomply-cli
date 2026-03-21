package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// EFSClient defines the interface for EFS operations.
type EFSClient interface {
	DescribeFileSystems(ctx context.Context, params *efs.DescribeFileSystemsInput, optFns ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error)
	DescribeBackupPolicy(ctx context.Context, params *efs.DescribeBackupPolicyInput, optFns ...func(*efs.Options)) (*efs.DescribeBackupPolicyOutput, error)
}

// EFSFileSystem represents an EFS file system.
type EFSFileSystem struct {
	FileSystemID             string `json:"file_system_id"`
	Name                     string `json:"name,omitempty"`
	ARN                      string `json:"arn"`
	Encrypted                bool   `json:"encrypted"`
	KMSKeyID                 string `json:"kms_key_id,omitempty"`
	LifecyclePolicyConfigured bool  `json:"lifecycle_policy_configured"`
	BackupPolicyEnabled       bool  `json:"backup_policy_enabled"`
}

// ToEvidence converts an EFSFileSystem to Evidence.
func (f *EFSFileSystem) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(f) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:efs:file_system", f.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// EFSCollector collects EFS file system data.
type EFSCollector struct {
	client EFSClient
}

// NewEFSCollector creates a new EFS collector.
func NewEFSCollector(client EFSClient) *EFSCollector {
	return &EFSCollector{client: client}
}

// CollectFileSystems retrieves all EFS file systems.
func (c *EFSCollector) CollectFileSystems(ctx context.Context) ([]EFSFileSystem, error) {
	var fileSystems []EFSFileSystem
	var marker *string

	for {
		output, err := c.client.DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe EFS file systems: %w", err)
		}

		for i := range output.FileSystems {
			fs := &output.FileSystems[i]
			fileSystem := EFSFileSystem{
				FileSystemID: awssdk.ToString(fs.FileSystemId),
				ARN:          awssdk.ToString(fs.FileSystemArn),
				Encrypted:    awssdk.ToBool(fs.Encrypted),
			}

			if fs.Name != nil {
				fileSystem.Name = awssdk.ToString(fs.Name)
			}

			if fs.KmsKeyId != nil {
				fileSystem.KMSKeyID = awssdk.ToString(fs.KmsKeyId)
			}

			c.enrichBackupPolicy(ctx, &fileSystem)

			fileSystems = append(fileSystems, fileSystem)
		}

		if output.NextMarker == nil {
			break
		}
		marker = output.NextMarker
	}

	return fileSystems, nil
}

func (c *EFSCollector) enrichBackupPolicy(ctx context.Context, fs *EFSFileSystem) {
	output, err := c.client.DescribeBackupPolicy(ctx, &efs.DescribeBackupPolicyInput{
		FileSystemId: awssdk.String(fs.FileSystemID),
	})
	if err != nil {
		return // Fail-safe
	}
	if output.BackupPolicy != nil {
		fs.BackupPolicyEnabled = string(output.BackupPolicy.Status) == statusEnabled
	}
}

// CollectEvidence collects EFS file systems as evidence.
func (c *EFSCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
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
