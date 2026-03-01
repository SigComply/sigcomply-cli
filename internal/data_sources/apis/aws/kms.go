package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// KMSClient defines the interface for KMS operations.
type KMSClient interface {
	ListKeys(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyRotationStatus(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
}

// KMSKey represents a KMS customer master key.
type KMSKey struct {
	KeyID           string `json:"key_id"`
	ARN             string `json:"arn"`
	Description     string `json:"description,omitempty"`
	KeyState        string `json:"key_state"`
	KeyManager      string `json:"key_manager"`
	KeySpec         string `json:"key_spec"`
	RotationEnabled bool   `json:"rotation_enabled"`
	Enabled         bool   `json:"enabled"`
}

// ToEvidence converts a KMSKey to Evidence.
func (k *KMSKey) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(k) //nolint:errcheck
	ev := evidence.New("aws", "aws:kms:key", k.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// KMSCollector collects KMS key data.
type KMSCollector struct {
	client KMSClient
}

// NewKMSCollector creates a new KMS collector.
func NewKMSCollector(client KMSClient) *KMSCollector {
	return &KMSCollector{client: client}
}

// CollectKeys retrieves all customer-managed KMS keys.
func (c *KMSCollector) CollectKeys(ctx context.Context) ([]KMSKey, error) {
	var keys []KMSKey
	var marker *string

	for {
		output, err := c.client.ListKeys(ctx, &kms.ListKeysInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("failed to list KMS keys: %w", err)
		}

		for _, entry := range output.Keys {
			keyID := awssdk.ToString(entry.KeyId)
			keyARN := awssdk.ToString(entry.KeyArn)

			// Get key details
			desc, err := c.client.DescribeKey(ctx, &kms.DescribeKeyInput{
				KeyId: entry.KeyId,
			})
			if err != nil {
				continue // Fail-safe: skip keys we can't describe
			}

			km := desc.KeyMetadata
			// Only include customer-managed keys
			if string(km.KeyManager) != "CUSTOMER" {
				continue
			}

			key := KMSKey{
				KeyID:      keyID,
				ARN:        keyARN,
				Description: awssdk.ToString(km.Description),
				KeyState:   string(km.KeyState),
				KeyManager: string(km.KeyManager),
				KeySpec:    string(km.KeySpec),
				Enabled:    km.Enabled,
			}

			// Check rotation status
			rotStatus, err := c.client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
				KeyId: entry.KeyId,
			})
			if err != nil {
				key.RotationEnabled = false // Fail-safe
			} else {
				key.RotationEnabled = rotStatus.KeyRotationEnabled
			}

			keys = append(keys, key)
		}

		if !output.Truncated {
			break
		}
		marker = output.NextMarker
	}

	return keys, nil
}

// CollectEvidence collects KMS keys as evidence.
func (c *KMSCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	keys, err := c.CollectKeys(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(keys))
	for i := range keys {
		evidenceList = append(evidenceList, keys[i].ToEvidence(accountID))
	}

	return evidenceList, nil
}
