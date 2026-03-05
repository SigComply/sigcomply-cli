package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockSecretsManagerClient struct {
	ListSecretsFunc func(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

func (m *MockSecretsManagerClient) ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	return m.ListSecretsFunc(ctx, params, optFns...)
}

func TestSecretsManagerCollector_CollectSecrets(t *testing.T) {
	rotatedDate := time.Now().Add(-30 * 24 * time.Hour)
	mock := &MockSecretsManagerClient{
		ListSecretsFunc: func(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
			return &secretsmanager.ListSecretsOutput{
				SecretList: []smtypes.SecretListEntry{
					{
						Name:            awssdk.String("prod/db-password"),
						ARN:             awssdk.String("arn:aws:secretsmanager:us-east-1:123:secret:prod/db-password"),
						RotationEnabled: awssdk.Bool(true),
						LastRotatedDate: &rotatedDate,
					},
					{
						Name:            awssdk.String("api-key"),
						ARN:             awssdk.String("arn:aws:secretsmanager:us-east-1:123:secret:api-key"),
						RotationEnabled: awssdk.Bool(false),
					},
				},
			}, nil
		},
	}

	collector := NewSecretsManagerCollector(mock)
	secrets, err := collector.CollectSecrets(context.Background())

	require.NoError(t, err)
	require.Len(t, secrets, 2)

	assert.Equal(t, "prod/db-password", secrets[0].Name)
	assert.True(t, secrets[0].RotationEnabled)
	assert.InDelta(t, 30, secrets[0].DaysSinceRotation, 1)

	assert.Equal(t, "api-key", secrets[1].Name)
	assert.False(t, secrets[1].RotationEnabled)
}

func TestSecretsManagerCollector_CollectSecrets_Error(t *testing.T) {
	mock := &MockSecretsManagerClient{
		ListSecretsFunc: func(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewSecretsManagerCollector(mock)
	_, err := collector.CollectSecrets(context.Background())
	assert.Error(t, err)
}

func TestSecretsManagerCollector_CollectEvidence(t *testing.T) {
	mock := &MockSecretsManagerClient{
		ListSecretsFunc: func(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
			return &secretsmanager.ListSecretsOutput{
				SecretList: []smtypes.SecretListEntry{
					{Name: awssdk.String("secret1"), ARN: awssdk.String("arn:aws:secretsmanager:us-east-1:123:secret:secret1")},
				},
			}, nil
		},
	}

	collector := NewSecretsManagerCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	assert.Len(t, ev, 1)
	assert.Equal(t, "aws:secretsmanager:secret", ev[0].ResourceType)
}

func TestSecret_ToEvidence(t *testing.T) {
	secret := &Secret{Name: "test", ARN: "arn:aws:secretsmanager:us-east-1:123:secret:test", RotationEnabled: true}
	ev := secret.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:secretsmanager:secret", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
