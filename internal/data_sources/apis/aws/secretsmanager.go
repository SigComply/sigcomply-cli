package aws

import (
	"context"
	"encoding/json"
	"math"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// SecretsManagerClient defines the interface for Secrets Manager operations.
type SecretsManagerClient interface {
	ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

// Secret represents a Secrets Manager secret.
type Secret struct {
	Name              string `json:"name"`
	ARN               string `json:"arn"`
	RotationEnabled   bool   `json:"rotation_enabled"`
	LastRotatedDate   string `json:"last_rotated_date,omitempty"`
	DaysSinceRotation int    `json:"days_since_rotation"`
}

// ToEvidence converts a Secret to Evidence.
func (s *Secret) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck
	ev := evidence.New("aws", "aws:secretsmanager:secret", s.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// SecretsManagerCollector collects Secrets Manager data.
type SecretsManagerCollector struct {
	client SecretsManagerClient
}

// NewSecretsManagerCollector creates a new Secrets Manager collector.
func NewSecretsManagerCollector(client SecretsManagerClient) *SecretsManagerCollector {
	return &SecretsManagerCollector{client: client}
}

// CollectSecrets retrieves all secrets with rotation status.
func (c *SecretsManagerCollector) CollectSecrets(ctx context.Context) ([]Secret, error) {
	var secrets []Secret
	var nextToken *string

	for {
		output, err := c.client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}

		for _, s := range output.SecretList {
			secret := Secret{
				Name:            awssdk.ToString(s.Name),
				ARN:             awssdk.ToString(s.ARN),
				RotationEnabled: awssdk.ToBool(s.RotationEnabled),
			}

			if s.LastRotatedDate != nil {
				secret.LastRotatedDate = s.LastRotatedDate.Format(time.RFC3339)
				secret.DaysSinceRotation = int(math.Floor(time.Since(*s.LastRotatedDate).Hours() / 24))
			}

			secrets = append(secrets, secret)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return secrets, nil
}

// CollectEvidence collects secrets as evidence.
func (c *SecretsManagerCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	secrets, err := c.CollectSecrets(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(secrets))
	for i := range secrets {
		evidenceList = append(evidenceList, secrets[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
