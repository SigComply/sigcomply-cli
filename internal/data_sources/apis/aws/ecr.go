package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// ECRClient defines the interface for ECR operations.
type ECRClient interface {
	DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	GetLifecyclePolicy(ctx context.Context, params *ecr.GetLifecyclePolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error)
}

// ECRRepository represents an ECR repository.
type ECRRepository struct {
	Name               string `json:"name"`
	ARN                string `json:"arn"`
	RegistryID         string `json:"registry_id"`
	ScanOnPush         bool   `json:"scan_on_push"`
	EncryptionType     string `json:"encryption_type"`
	EncryptionKeyID    string `json:"encryption_key_id,omitempty"`
	TagImmutable       bool   `json:"tag_immutable"`
	IsPublic           bool   `json:"is_public"`
	HasLifecyclePolicy bool   `json:"has_lifecycle_policy"`
}

// ToEvidence converts an ECRRepository to Evidence.
func (r *ECRRepository) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(r) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	ev := evidence.New("aws", "aws:ecr:repository", r.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// ECRCollector collects ECR repository data.
type ECRCollector struct {
	client ECRClient
}

// NewECRCollector creates a new ECR collector.
func NewECRCollector(client ECRClient) *ECRCollector {
	return &ECRCollector{client: client}
}

// CollectRepositories retrieves all ECR repositories.
func (c *ECRCollector) CollectRepositories(ctx context.Context) ([]ECRRepository, error) {
	var repos []ECRRepository
	var nextToken *string

	for {
		output, err := c.client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe ECR repositories: %w", err)
		}

		for _, repo := range output.Repositories {
			r := ECRRepository{
				Name:       awssdk.ToString(repo.RepositoryName),
				ARN:        awssdk.ToString(repo.RepositoryArn),
				RegistryID: awssdk.ToString(repo.RegistryId),
			}

			if repo.ImageScanningConfiguration != nil {
				r.ScanOnPush = repo.ImageScanningConfiguration.ScanOnPush
			}

			if repo.EncryptionConfiguration != nil {
				r.EncryptionType = string(repo.EncryptionConfiguration.EncryptionType)
				if repo.EncryptionConfiguration.KmsKey != nil {
					r.EncryptionKeyID = awssdk.ToString(repo.EncryptionConfiguration.KmsKey)
				}
			}

			r.TagImmutable = repo.ImageTagMutability == ecrtypes.ImageTagMutabilityImmutable
			r.IsPublic = false // Private ECR API only returns private repos

			c.enrichLifecyclePolicy(ctx, &r)

			repos = append(repos, r)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return repos, nil
}

// enrichLifecyclePolicy checks if a repository has a lifecycle policy configured.
func (c *ECRCollector) enrichLifecyclePolicy(ctx context.Context, repo *ECRRepository) {
	_, err := c.client.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{
		RepositoryName: awssdk.String(repo.Name),
	})
	if err != nil {
		return // No lifecycle policy or access denied
	}
	repo.HasLifecyclePolicy = true
}

// CollectEvidence collects ECR repositories as evidence.
func (c *ECRCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	repos, err := c.CollectRepositories(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(repos))
	for i := range repos {
		evidenceList = append(evidenceList, repos[i].ToEvidence(accountID))
	}

	return evidenceList, nil
}
