package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	bktypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockBackupClient struct {
	ListBackupPlansFunc                 func(ctx context.Context, params *backup.ListBackupPlansInput, optFns ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error)
	GetBackupPlanFunc                   func(ctx context.Context, params *backup.GetBackupPlanInput, optFns ...func(*backup.Options)) (*backup.GetBackupPlanOutput, error)
	ListBackupVaultsFunc                func(ctx context.Context, params *backup.ListBackupVaultsInput, optFns ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error)
	DescribeBackupVaultFunc             func(ctx context.Context, params *backup.DescribeBackupVaultInput, optFns ...func(*backup.Options)) (*backup.DescribeBackupVaultOutput, error)
	ListRecoveryPointsByBackupVaultFunc func(ctx context.Context, params *backup.ListRecoveryPointsByBackupVaultInput, optFns ...func(*backup.Options)) (*backup.ListRecoveryPointsByBackupVaultOutput, error)
}

func (m *MockBackupClient) ListBackupPlans(ctx context.Context, params *backup.ListBackupPlansInput, optFns ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error) {
	return m.ListBackupPlansFunc(ctx, params, optFns...)
}

func (m *MockBackupClient) GetBackupPlan(ctx context.Context, params *backup.GetBackupPlanInput, optFns ...func(*backup.Options)) (*backup.GetBackupPlanOutput, error) {
	if m.GetBackupPlanFunc != nil {
		return m.GetBackupPlanFunc(ctx, params, optFns...)
	}
	return &backup.GetBackupPlanOutput{}, nil
}

func (m *MockBackupClient) ListBackupVaults(ctx context.Context, params *backup.ListBackupVaultsInput, optFns ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error) {
	if m.ListBackupVaultsFunc != nil {
		return m.ListBackupVaultsFunc(ctx, params, optFns...)
	}
	return &backup.ListBackupVaultsOutput{BackupVaultList: []bktypes.BackupVaultListMember{}}, nil
}

func (m *MockBackupClient) DescribeBackupVault(ctx context.Context, params *backup.DescribeBackupVaultInput, optFns ...func(*backup.Options)) (*backup.DescribeBackupVaultOutput, error) {
	if m.DescribeBackupVaultFunc != nil {
		return m.DescribeBackupVaultFunc(ctx, params, optFns...)
	}
	return &backup.DescribeBackupVaultOutput{}, nil
}

func (m *MockBackupClient) ListRecoveryPointsByBackupVault(ctx context.Context, params *backup.ListRecoveryPointsByBackupVaultInput, optFns ...func(*backup.Options)) (*backup.ListRecoveryPointsByBackupVaultOutput, error) {
	if m.ListRecoveryPointsByBackupVaultFunc != nil {
		return m.ListRecoveryPointsByBackupVaultFunc(ctx, params, optFns...)
	}
	return &backup.ListRecoveryPointsByBackupVaultOutput{}, nil
}

func TestBackupCollector_HasPlans(t *testing.T) {
	mock := &MockBackupClient{
		ListBackupPlansFunc: func(ctx context.Context, params *backup.ListBackupPlansInput, optFns ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error) {
			return &backup.ListBackupPlansOutput{
				BackupPlansList: []bktypes.BackupPlansListMember{
					{BackupPlanName: strPtr("daily-backup")},
					{BackupPlanName: strPtr("weekly-backup")},
				},
			}, nil
		},
	}

	collector := NewBackupCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.True(t, status.HasBackupPlans)
	assert.Equal(t, 2, status.PlanCount)
}

func TestBackupCollector_NoPlans(t *testing.T) {
	mock := &MockBackupClient{
		ListBackupPlansFunc: func(ctx context.Context, params *backup.ListBackupPlansInput, optFns ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error) {
			return &backup.ListBackupPlansOutput{
				BackupPlansList: []bktypes.BackupPlansListMember{},
			}, nil
		},
	}

	collector := NewBackupCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.False(t, status.HasBackupPlans)
	assert.Equal(t, 0, status.PlanCount)
}

func TestBackupCollector_Error_FailSafe(t *testing.T) {
	mock := &MockBackupClient{
		ListBackupPlansFunc: func(ctx context.Context, params *backup.ListBackupPlansInput, optFns ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewBackupCollector(mock, "us-east-1")
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.False(t, status.HasBackupPlans)
}

func TestBackupStatus_ToEvidence(t *testing.T) {
	status := &BackupStatus{HasBackupPlans: true, PlanCount: 2, Region: "us-east-1"}
	ev := status.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:backup:status", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}

func TestBackupCollector_CollectPlans_WithCrossRegionCopy(t *testing.T) {
	mock := &MockBackupClient{
		ListBackupPlansFunc: func(ctx context.Context, params *backup.ListBackupPlansInput, optFns ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error) {
			return &backup.ListBackupPlansOutput{
				BackupPlansList: []bktypes.BackupPlansListMember{
					{BackupPlanId: awssdk.String("plan-1"), BackupPlanName: awssdk.String("daily-backup")},
					{BackupPlanId: awssdk.String("plan-2"), BackupPlanName: awssdk.String("local-only")},
				},
			}, nil
		},
		GetBackupPlanFunc: func(ctx context.Context, params *backup.GetBackupPlanInput, optFns ...func(*backup.Options)) (*backup.GetBackupPlanOutput, error) {
			planID := awssdk.ToString(params.BackupPlanId)
			if planID == "plan-1" {
				return &backup.GetBackupPlanOutput{
					BackupPlan: &bktypes.BackupPlan{
						BackupPlanName: awssdk.String("daily-backup"),
						Rules: []bktypes.BackupRule{
							{
								RuleName: awssdk.String("daily"),
								CopyActions: []bktypes.CopyAction{
									{DestinationBackupVaultArn: awssdk.String("arn:aws:backup:us-west-2:123:backup-vault:remote")},
								},
							},
						},
					},
				}, nil
			}
			return &backup.GetBackupPlanOutput{
				BackupPlan: &bktypes.BackupPlan{
					BackupPlanName: awssdk.String("local-only"),
					Rules: []bktypes.BackupRule{
						{RuleName: awssdk.String("daily")},
					},
				},
			}, nil
		},
	}

	collector := NewBackupCollector(mock, "us-east-1")
	plans, err := collector.CollectPlans(context.Background())

	require.NoError(t, err)
	require.Len(t, plans, 2)
	assert.Equal(t, "plan-1", plans[0].PlanID)
	assert.True(t, plans[0].HasCrossRegionCopy)
	assert.Equal(t, "plan-2", plans[1].PlanID)
	assert.False(t, plans[1].HasCrossRegionCopy)
}

func TestBackupCollector_CollectPlans_Error(t *testing.T) {
	mock := &MockBackupClient{
		ListBackupPlansFunc: func(ctx context.Context, params *backup.ListBackupPlansInput, optFns ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewBackupCollector(mock, "us-east-1")
	_, err := collector.CollectPlans(context.Background())
	assert.Error(t, err)
}

func TestBackupCollector_CollectPlans_GetPlanError_FailSafe(t *testing.T) {
	mock := &MockBackupClient{
		ListBackupPlansFunc: func(ctx context.Context, params *backup.ListBackupPlansInput, optFns ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error) {
			return &backup.ListBackupPlansOutput{
				BackupPlansList: []bktypes.BackupPlansListMember{
					{BackupPlanId: awssdk.String("plan-1"), BackupPlanName: awssdk.String("test")},
				},
			}, nil
		},
		GetBackupPlanFunc: func(ctx context.Context, params *backup.GetBackupPlanInput, optFns ...func(*backup.Options)) (*backup.GetBackupPlanOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewBackupCollector(mock, "us-east-1")
	plans, err := collector.CollectPlans(context.Background())

	require.NoError(t, err)
	require.Len(t, plans, 1)
	assert.False(t, plans[0].HasCrossRegionCopy, "should default to false when GetBackupPlan fails")
}

func TestBackupPlan_ToEvidence(t *testing.T) {
	plan := &BackupPlan{PlanID: "plan-1", PlanName: "daily", HasCrossRegionCopy: true}
	ev := plan.ToEvidence("123456789012", "us-east-1")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:backup:plan", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "plan-1")
	assert.NotEmpty(t, ev.Hash)
}

func TestBackupCollector_CollectVaults(t *testing.T) {
	tests := []struct {
		name              string
		vaults            []bktypes.BackupVaultListMember
		vaultDetails      map[string]*backup.DescribeBackupVaultOutput
		listErr           error
		wantCount         int
		wantError         bool
		wantEncrypted     []bool
		wantKMSConfigured []bool
	}{
		{
			name: "vault with KMS encryption",
			vaults: []bktypes.BackupVaultListMember{
				{BackupVaultName: awssdk.String("my-vault"), BackupVaultArn: awssdk.String("arn:aws:backup:us-east-1:123:backup-vault:my-vault")},
			},
			vaultDetails: map[string]*backup.DescribeBackupVaultOutput{
				"my-vault": {EncryptionKeyArn: awssdk.String("arn:aws:kms:us-east-1:123:key/abc-123")},
			},
			wantCount:         1,
			wantEncrypted:     []bool{true},
			wantKMSConfigured: []bool{true},
		},
		{
			name: "vault with default aws/backup key",
			vaults: []bktypes.BackupVaultListMember{
				{BackupVaultName: awssdk.String("default-vault"), BackupVaultArn: awssdk.String("arn:aws:backup:us-east-1:123:backup-vault:default-vault")},
			},
			vaultDetails: map[string]*backup.DescribeBackupVaultOutput{
				"default-vault": {EncryptionKeyArn: awssdk.String("arn:aws:kms:us-east-1:123:alias/aws/backup")},
			},
			wantCount:         1,
			wantEncrypted:     []bool{true},
			wantKMSConfigured: []bool{false},
		},
		{
			name: "vault without encryption",
			vaults: []bktypes.BackupVaultListMember{
				{BackupVaultName: awssdk.String("no-enc"), BackupVaultArn: awssdk.String("arn:aws:backup:us-east-1:123:backup-vault:no-enc")},
			},
			vaultDetails: map[string]*backup.DescribeBackupVaultOutput{
				"no-enc": {EncryptionKeyArn: awssdk.String("")},
			},
			wantCount:         1,
			wantEncrypted:     []bool{false},
			wantKMSConfigured: []bool{false},
		},
		{
			name:      "list error",
			listErr:   errors.New("access denied"),
			wantError: true,
		},
		{
			name:      "empty vaults",
			vaults:    []bktypes.BackupVaultListMember{},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockBackupClient{
				ListBackupPlansFunc: func(ctx context.Context, params *backup.ListBackupPlansInput, optFns ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error) {
					return &backup.ListBackupPlansOutput{}, nil
				},
				ListBackupVaultsFunc: func(ctx context.Context, params *backup.ListBackupVaultsInput, optFns ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error) {
					if tt.listErr != nil {
						return nil, tt.listErr
					}
					return &backup.ListBackupVaultsOutput{BackupVaultList: tt.vaults}, nil
				},
				DescribeBackupVaultFunc: func(ctx context.Context, params *backup.DescribeBackupVaultInput, optFns ...func(*backup.Options)) (*backup.DescribeBackupVaultOutput, error) {
					if detail, ok := tt.vaultDetails[awssdk.ToString(params.BackupVaultName)]; ok {
						return detail, nil
					}
					return &backup.DescribeBackupVaultOutput{}, nil
				},
			}

			collector := NewBackupCollector(mock, "us-east-1")
			vaults, err := collector.CollectVaults(context.Background())

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, vaults, tt.wantCount)

			for i, v := range vaults {
				if i < len(tt.wantEncrypted) {
					assert.Equal(t, tt.wantEncrypted[i], v.EncryptionEnabled, "vault %d encryption", i)
				}
				if i < len(tt.wantKMSConfigured) {
					assert.Equal(t, tt.wantKMSConfigured[i], v.KMSKeyConfigured, "vault %d KMS configured", i)
				}
			}
		})
	}
}

func TestBackupVault_ToEvidence(t *testing.T) {
	vault := &BackupVault{VaultName: "my-vault", VaultARN: "arn:aws:backup:us-east-1:123:backup-vault:my-vault", EncryptionEnabled: true}
	ev := vault.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:backup:vault", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "my-vault")
	assert.NotEmpty(t, ev.Hash)
}

func TestBackupCollector_CollectRecoveryPoints(t *testing.T) {
	tests := []struct {
		name      string
		vaults    []bktypes.BackupVaultListMember
		rps       map[string][]bktypes.RecoveryPointByBackupVault
		listErr   error
		wantCount int
		wantError bool
	}{
		{
			name: "recovery points across vaults",
			vaults: []bktypes.BackupVaultListMember{
				{BackupVaultName: awssdk.String("vault-1")},
				{BackupVaultName: awssdk.String("vault-2")},
			},
			rps: map[string][]bktypes.RecoveryPointByBackupVault{
				"vault-1": {
					{RecoveryPointArn: awssdk.String("arn:rp-1"), IsEncrypted: true},
				},
				"vault-2": {
					{RecoveryPointArn: awssdk.String("arn:rp-2"), IsEncrypted: false},
				},
			},
			wantCount: 2,
		},
		{
			name:      "list vaults error",
			listErr:   errors.New("access denied"),
			wantError: true,
		},
		{
			name:      "no vaults",
			vaults:    []bktypes.BackupVaultListMember{},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockBackupClient{
				ListBackupPlansFunc: func(ctx context.Context, params *backup.ListBackupPlansInput, optFns ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error) {
					return &backup.ListBackupPlansOutput{}, nil
				},
				ListBackupVaultsFunc: func(ctx context.Context, params *backup.ListBackupVaultsInput, optFns ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error) {
					if tt.listErr != nil {
						return nil, tt.listErr
					}
					return &backup.ListBackupVaultsOutput{BackupVaultList: tt.vaults}, nil
				},
				ListRecoveryPointsByBackupVaultFunc: func(ctx context.Context, params *backup.ListRecoveryPointsByBackupVaultInput, optFns ...func(*backup.Options)) (*backup.ListRecoveryPointsByBackupVaultOutput, error) {
					vaultName := awssdk.ToString(params.BackupVaultName)
					if rps, ok := tt.rps[vaultName]; ok {
						return &backup.ListRecoveryPointsByBackupVaultOutput{RecoveryPoints: rps}, nil
					}
					return &backup.ListRecoveryPointsByBackupVaultOutput{}, nil
				},
			}

			collector := NewBackupCollector(mock, "us-east-1")
			points, err := collector.CollectRecoveryPoints(context.Background())

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, points, tt.wantCount)

			if tt.name == "recovery points across vaults" {
				assert.True(t, points[0].Encrypted)
				assert.Equal(t, "vault-1", points[0].VaultName)
				assert.False(t, points[1].Encrypted)
				assert.Equal(t, "vault-2", points[1].VaultName)
			}
		})
	}
}

func TestBackupRecoveryPoint_ToEvidence(t *testing.T) {
	rp := &BackupRecoveryPoint{RecoveryPointARN: "arn:aws:backup:us-east-1:123:recovery-point:rp-1", VaultName: "vault-1", Encrypted: true}
	ev := rp.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:backup:recovery-point", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "rp-1")
	assert.NotEmpty(t, ev.Hash)
}
