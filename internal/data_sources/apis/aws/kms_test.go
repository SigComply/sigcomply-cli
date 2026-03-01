package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockKMSClient implements KMSClient for testing.
type MockKMSClient struct {
	ListKeysFunc             func(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKeyFunc          func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyRotationStatusFunc func(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
}

func (m *MockKMSClient) ListKeys(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	return m.ListKeysFunc(ctx, params, optFns...)
}

func (m *MockKMSClient) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return m.DescribeKeyFunc(ctx, params, optFns...)
}

func (m *MockKMSClient) GetKeyRotationStatus(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	return m.GetKeyRotationStatusFunc(ctx, params, optFns...)
}

func TestKMSCollector_CollectKeys(t *testing.T) {
	tests := []struct {
		name      string
		keys      []kmstypes.KeyListEntry
		descResp  map[string]*kms.DescribeKeyOutput
		rotResp   map[string]bool
		listErr   error
		wantCount int
		wantError bool
	}{
		{
			name: "customer-managed key with rotation",
			keys: []kmstypes.KeyListEntry{
				{KeyId: awssdk.String("key-1"), KeyArn: awssdk.String("arn:aws:kms:us-east-1:123:key/key-1")},
			},
			descResp: map[string]*kms.DescribeKeyOutput{
				"key-1": {KeyMetadata: &kmstypes.KeyMetadata{
					KeyManager:  kmstypes.KeyManagerTypeCustomer,
					KeyState:    kmstypes.KeyStateEnabled,
					KeySpec:     kmstypes.KeySpecSymmetricDefault,
					Enabled:     true,
					Description: awssdk.String("Test key"),
				}},
			},
			rotResp:   map[string]bool{"key-1": true},
			wantCount: 1,
		},
		{
			name: "AWS-managed key filtered out",
			keys: []kmstypes.KeyListEntry{
				{KeyId: awssdk.String("aws-key"), KeyArn: awssdk.String("arn:aws:kms:us-east-1:123:key/aws-key")},
			},
			descResp: map[string]*kms.DescribeKeyOutput{
				"aws-key": {KeyMetadata: &kmstypes.KeyMetadata{
					KeyManager: kmstypes.KeyManagerTypeAws,
					KeyState:   kmstypes.KeyStateEnabled,
				}},
			},
			wantCount: 0,
		},
		{
			name:      "ListKeys API error",
			listErr:   errors.New("access denied"),
			wantError: true,
		},
		{
			name: "DescribeKey fails - key skipped",
			keys: []kmstypes.KeyListEntry{
				{KeyId: awssdk.String("bad-key"), KeyArn: awssdk.String("arn:aws:kms:us-east-1:123:key/bad-key")},
			},
			descResp:  map[string]*kms.DescribeKeyOutput{},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockKMSClient{
				ListKeysFunc: func(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
					if tt.listErr != nil {
						return nil, tt.listErr
					}
					return &kms.ListKeysOutput{Keys: tt.keys, Truncated: false}, nil
				},
				DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
					keyID := awssdk.ToString(params.KeyId)
					resp, ok := tt.descResp[keyID]
					if !ok {
						return nil, errors.New("key not found")
					}
					return resp, nil
				},
				GetKeyRotationStatusFunc: func(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
					keyID := awssdk.ToString(params.KeyId)
					if rot, ok := tt.rotResp[keyID]; ok {
						return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: rot}, nil
					}
					return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: false}, nil
				},
			}

			collector := NewKMSCollector(mock)
			keys, err := collector.CollectKeys(context.Background())

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, keys, tt.wantCount)

			if tt.name == "customer-managed key with rotation" {
				assert.True(t, keys[0].RotationEnabled)
				assert.True(t, keys[0].Enabled)
				assert.Equal(t, "CUSTOMER", keys[0].KeyManager)
			}
		})
	}
}

func TestKMSCollector_CollectKeys_RotationError(t *testing.T) {
	mock := &MockKMSClient{
		ListKeysFunc: func(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
			return &kms.ListKeysOutput{
				Keys:      []kmstypes.KeyListEntry{{KeyId: awssdk.String("key-1"), KeyArn: awssdk.String("arn:aws:kms:us-east-1:123:key/key-1")}},
				Truncated: false,
			}, nil
		},
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
				KeyManager: kmstypes.KeyManagerTypeCustomer,
				KeyState:   kmstypes.KeyStateEnabled,
				Enabled:    true,
			}}, nil
		},
		GetKeyRotationStatusFunc: func(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewKMSCollector(mock)
	keys, err := collector.CollectKeys(context.Background())

	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.False(t, keys[0].RotationEnabled, "should default to false when rotation status fails")
}

func TestKMSCollector_CollectKeys_Pagination(t *testing.T) {
	callCount := 0
	mock := &MockKMSClient{
		ListKeysFunc: func(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
			callCount++
			if callCount == 1 {
				return &kms.ListKeysOutput{
					Keys:       []kmstypes.KeyListEntry{{KeyId: awssdk.String("key-1"), KeyArn: awssdk.String("arn:1")}},
					Truncated:  true,
					NextMarker: awssdk.String("marker1"),
				}, nil
			}
			return &kms.ListKeysOutput{
				Keys:      []kmstypes.KeyListEntry{{KeyId: awssdk.String("key-2"), KeyArn: awssdk.String("arn:2")}},
				Truncated: false,
			}, nil
		},
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
				KeyManager: kmstypes.KeyManagerTypeCustomer,
				Enabled:    true,
			}}, nil
		},
		GetKeyRotationStatusFunc: func(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
			return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: true}, nil
		},
	}

	collector := NewKMSCollector(mock)
	keys, err := collector.CollectKeys(context.Background())

	require.NoError(t, err)
	assert.Len(t, keys, 2)
	assert.Equal(t, 2, callCount)
}

func TestKMSKey_ToEvidence(t *testing.T) {
	key := &KMSKey{
		KeyID:           "key-1",
		ARN:             "arn:aws:kms:us-east-1:123:key/key-1",
		RotationEnabled: true,
	}

	ev := key.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:kms:key", ev.ResourceType)
	assert.Equal(t, "arn:aws:kms:us-east-1:123:key/key-1", ev.ResourceID)
	assert.NotEmpty(t, ev.Hash)
}

// --- Negative Tests ---

func TestKMSCollector_CollectKeys_PaginationErrorMidStream(t *testing.T) {
	callCount := 0
	mock := &MockKMSClient{
		ListKeysFunc: func(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
			callCount++
			if callCount == 1 {
				return &kms.ListKeysOutput{
					Keys:       []kmstypes.KeyListEntry{{KeyId: awssdk.String("key-1"), KeyArn: awssdk.String("arn:1")}},
					Truncated:  true,
					NextMarker: awssdk.String("marker1"),
				}, nil
			}
			return nil, errors.New("internal service error on page 2")
		},
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
				KeyManager: kmstypes.KeyManagerTypeCustomer,
				Enabled:    true,
			}}, nil
		},
		GetKeyRotationStatusFunc: func(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
			return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: true}, nil
		},
	}

	collector := NewKMSCollector(mock)
	_, err := collector.CollectKeys(context.Background())

	assert.Error(t, err, "pagination error on page 2 should propagate")
	assert.Contains(t, err.Error(), "failed to list KMS keys")
}

func TestKMSCollector_CollectKeys_AllKeysAWSManaged(t *testing.T) {
	mock := &MockKMSClient{
		ListKeysFunc: func(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
			return &kms.ListKeysOutput{
				Keys: []kmstypes.KeyListEntry{
					{KeyId: awssdk.String("aws-key-1"), KeyArn: awssdk.String("arn:1")},
					{KeyId: awssdk.String("aws-key-2"), KeyArn: awssdk.String("arn:2")},
				},
				Truncated: false,
			}, nil
		},
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
				KeyManager: kmstypes.KeyManagerTypeAws,
				Enabled:    true,
			}}, nil
		},
		GetKeyRotationStatusFunc: func(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
			return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: true}, nil
		},
	}

	collector := NewKMSCollector(mock)
	keys, err := collector.CollectKeys(context.Background())

	require.NoError(t, err)
	assert.Empty(t, keys, "AWS-managed keys should all be filtered out")
}

func TestKMSCollector_CollectKeys_MixedDescribeKeyFailures(t *testing.T) {
	// 3 keys: first DescribeKey fails (skip), second succeeds, third DescribeKey fails (skip)
	callCount := 0
	mock := &MockKMSClient{
		ListKeysFunc: func(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
			return &kms.ListKeysOutput{
				Keys: []kmstypes.KeyListEntry{
					{KeyId: awssdk.String("key-fail-1"), KeyArn: awssdk.String("arn:fail1")},
					{KeyId: awssdk.String("key-ok"), KeyArn: awssdk.String("arn:ok")},
					{KeyId: awssdk.String("key-fail-2"), KeyArn: awssdk.String("arn:fail2")},
				},
				Truncated: false,
			}, nil
		},
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			callCount++
			keyID := awssdk.ToString(params.KeyId)
			if keyID == "key-ok" {
				return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{
					KeyManager: kmstypes.KeyManagerTypeCustomer,
					Enabled:    true,
				}}, nil
			}
			return nil, errors.New("key not accessible")
		},
		GetKeyRotationStatusFunc: func(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
			return &kms.GetKeyRotationStatusOutput{KeyRotationEnabled: false}, nil
		},
	}

	collector := NewKMSCollector(mock)
	keys, err := collector.CollectKeys(context.Background())

	require.NoError(t, err, "DescribeKey failures are fail-safe (skip key)")
	assert.Len(t, keys, 1, "only the successful key should be returned")
	assert.Equal(t, "key-ok", keys[0].KeyID)
}

func TestKMSCollector_CollectKeys_EmptyKeyList(t *testing.T) {
	mock := &MockKMSClient{
		ListKeysFunc: func(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
			return &kms.ListKeysOutput{Keys: []kmstypes.KeyListEntry{}, Truncated: false}, nil
		},
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			t.Fatal("DescribeKey should not be called when no keys exist")
			return nil, nil
		},
		GetKeyRotationStatusFunc: func(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
			t.Fatal("GetKeyRotationStatus should not be called when no keys exist")
			return nil, nil
		},
	}

	collector := NewKMSCollector(mock)
	keys, err := collector.CollectKeys(context.Background())

	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestKMSCollector_CollectEvidence_Error(t *testing.T) {
	mock := &MockKMSClient{
		ListKeysFunc: func(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
			return nil, errors.New("throttling")
		},
		DescribeKeyFunc: func(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
			return nil, nil
		},
		GetKeyRotationStatusFunc: func(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
			return nil, nil
		},
	}

	collector := NewKMSCollector(mock)
	_, err := collector.CollectEvidence(context.Background(), "123456789012")

	assert.Error(t, err, "CollectEvidence should propagate CollectKeys error")
}
