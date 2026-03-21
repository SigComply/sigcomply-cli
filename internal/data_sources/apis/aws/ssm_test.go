package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockSSMClient struct {
	DescribeInstanceInformationFunc func(ctx context.Context, params *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error)
	GetServiceSettingFunc           func(ctx context.Context, params *ssm.GetServiceSettingInput, optFns ...func(*ssm.Options)) (*ssm.GetServiceSettingOutput, error)
	ListDocumentsFunc               func(ctx context.Context, params *ssm.ListDocumentsInput, optFns ...func(*ssm.Options)) (*ssm.ListDocumentsOutput, error)
	DescribeDocumentPermissionFunc  func(ctx context.Context, params *ssm.DescribeDocumentPermissionInput, optFns ...func(*ssm.Options)) (*ssm.DescribeDocumentPermissionOutput, error)
	ListComplianceItemsFunc         func(ctx context.Context, params *ssm.ListComplianceItemsInput, optFns ...func(*ssm.Options)) (*ssm.ListComplianceItemsOutput, error)
}

func (m *MockSSMClient) DescribeInstanceInformation(ctx context.Context, params *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
	return m.DescribeInstanceInformationFunc(ctx, params, optFns...)
}

func (m *MockSSMClient) GetServiceSetting(ctx context.Context, params *ssm.GetServiceSettingInput, optFns ...func(*ssm.Options)) (*ssm.GetServiceSettingOutput, error) {
	if m.GetServiceSettingFunc != nil {
		return m.GetServiceSettingFunc(ctx, params, optFns...)
	}
	return &ssm.GetServiceSettingOutput{ServiceSetting: &ssmtypes.ServiceSetting{SettingValue: awssdk.String("Standard")}}, nil
}

func (m *MockSSMClient) ListDocuments(ctx context.Context, params *ssm.ListDocumentsInput, optFns ...func(*ssm.Options)) (*ssm.ListDocumentsOutput, error) {
	if m.ListDocumentsFunc != nil {
		return m.ListDocumentsFunc(ctx, params, optFns...)
	}
	return &ssm.ListDocumentsOutput{}, nil
}

func (m *MockSSMClient) DescribeDocumentPermission(ctx context.Context, params *ssm.DescribeDocumentPermissionInput, optFns ...func(*ssm.Options)) (*ssm.DescribeDocumentPermissionOutput, error) {
	if m.DescribeDocumentPermissionFunc != nil {
		return m.DescribeDocumentPermissionFunc(ctx, params, optFns...)
	}
	return &ssm.DescribeDocumentPermissionOutput{}, nil
}

func (m *MockSSMClient) ListComplianceItems(ctx context.Context, params *ssm.ListComplianceItemsInput, optFns ...func(*ssm.Options)) (*ssm.ListComplianceItemsOutput, error) {
	if m.ListComplianceItemsFunc != nil {
		return m.ListComplianceItemsFunc(ctx, params, optFns...)
	}
	return &ssm.ListComplianceItemsOutput{}, nil
}

func TestSSMCollector_CollectStatus(t *testing.T) {
	tests := []struct {
		name              string
		instances         []ssmtypes.InstanceInformation
		instanceErr       error
		wantSessionMgr    bool
		wantInstanceCount int
	}{
		{
			name: "managed instances present",
			instances: []ssmtypes.InstanceInformation{
				{InstanceId: awssdk.String("i-123")},
				{InstanceId: awssdk.String("i-456")},
			},
			wantSessionMgr:    true,
			wantInstanceCount: 2,
		},
		{
			name:              "no managed instances",
			instances:         []ssmtypes.InstanceInformation{},
			wantSessionMgr:    false,
			wantInstanceCount: 0,
		},
		{
			name:              "API error (fail-safe)",
			instanceErr:       errors.New("access denied"),
			wantSessionMgr:    false,
			wantInstanceCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockSSMClient{
				DescribeInstanceInformationFunc: func(ctx context.Context, params *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
					if tt.instanceErr != nil {
						return nil, tt.instanceErr
					}
					return &ssm.DescribeInstanceInformationOutput{InstanceInformationList: tt.instances}, nil
				},
			}

			collector := NewSSMCollector(mock, "us-east-1")
			status, err := collector.CollectStatus(context.Background())

			require.NoError(t, err)
			assert.Equal(t, tt.wantSessionMgr, status.SessionManagerEnabled)
			assert.Equal(t, tt.wantInstanceCount, status.ManagedInstanceCount)
		})
	}
}

func TestSSMStatus_ToEvidence(t *testing.T) {
	status := &SSMStatus{ManagedInstanceCount: 5, SessionManagerEnabled: true, Region: "us-east-1"}
	ev := status.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:ssm:status", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}

// --- Managed Instance Patch Compliance Tests ---

func TestSSMCollector_CollectManagedInstances(t *testing.T) {
	tests := []struct {
		name            string
		instances       []ssmtypes.InstanceInformation
		instanceErr     error
		complianceItems map[string][]ssmtypes.ComplianceItem
		complianceErr   error
		wantCount       int
		wantError       bool
		wantCompliant   []bool
	}{
		{
			name: "compliant instance",
			instances: []ssmtypes.InstanceInformation{
				{InstanceId: awssdk.String("i-123")},
			},
			complianceItems: map[string][]ssmtypes.ComplianceItem{
				"i-123": {
					{Status: ssmtypes.ComplianceStatusCompliant},
				},
			},
			wantCount:     1,
			wantCompliant: []bool{true},
		},
		{
			name: "non-compliant instance",
			instances: []ssmtypes.InstanceInformation{
				{InstanceId: awssdk.String("i-456")},
			},
			complianceItems: map[string][]ssmtypes.ComplianceItem{
				"i-456": {
					{Status: ssmtypes.ComplianceStatusCompliant},
					{Status: ssmtypes.ComplianceStatusNonCompliant},
				},
			},
			wantCount:     1,
			wantCompliant: []bool{false},
		},
		{
			name: "mixed instances",
			instances: []ssmtypes.InstanceInformation{
				{InstanceId: awssdk.String("i-good")},
				{InstanceId: awssdk.String("i-bad")},
			},
			complianceItems: map[string][]ssmtypes.ComplianceItem{
				"i-good": {{Status: ssmtypes.ComplianceStatusCompliant}},
				"i-bad":  {{Status: ssmtypes.ComplianceStatusNonCompliant}},
			},
			wantCount:     2,
			wantCompliant: []bool{true, false},
		},
		{
			name: "no compliance items (defaults to compliant)",
			instances: []ssmtypes.InstanceInformation{
				{InstanceId: awssdk.String("i-new")},
			},
			complianceItems: map[string][]ssmtypes.ComplianceItem{},
			wantCount:       1,
			wantCompliant:   []bool{true},
		},
		{
			name:        "describe instances error",
			instanceErr: errors.New("access denied"),
			wantError:   true,
		},
		{
			name:      "no instances",
			instances: []ssmtypes.InstanceInformation{},
			wantCount: 0,
		},
		{
			name: "compliance API error (fail-safe per instance)",
			instances: []ssmtypes.InstanceInformation{
				{InstanceId: awssdk.String("i-err")},
			},
			complianceErr: errors.New("access denied"),
			wantCount:     0, // Instance skipped on compliance error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockSSMClient{
				DescribeInstanceInformationFunc: func(ctx context.Context, params *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
					if tt.instanceErr != nil {
						return nil, tt.instanceErr
					}
					return &ssm.DescribeInstanceInformationOutput{InstanceInformationList: tt.instances}, nil
				},
				ListComplianceItemsFunc: func(ctx context.Context, params *ssm.ListComplianceItemsInput, optFns ...func(*ssm.Options)) (*ssm.ListComplianceItemsOutput, error) {
					if tt.complianceErr != nil {
						return nil, tt.complianceErr
					}
					instanceID := params.ResourceIds[0]
					items := tt.complianceItems[instanceID]
					return &ssm.ListComplianceItemsOutput{ComplianceItems: items}, nil
				},
			}

			collector := NewSSMCollector(mock, "us-east-1")
			instances, err := collector.CollectManagedInstances(context.Background())

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, instances, tt.wantCount)

			for i, inst := range instances {
				if i < len(tt.wantCompliant) {
					assert.Equal(t, tt.wantCompliant[i], inst.PatchCompliant, "instance %d compliance", i)
				}
			}
		})
	}
}

func TestSSMManagedInstance_ToEvidence(t *testing.T) {
	inst := &SSMManagedInstance{InstanceID: "i-123", PatchCompliant: true}
	ev := inst.ToEvidence("123456789012", "us-east-1")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:ssm:managed-instance", ev.ResourceType)
	assert.Contains(t, ev.ResourceID, "i-123")
	assert.NotEmpty(t, ev.Hash)
}
