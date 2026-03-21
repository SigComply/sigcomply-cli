package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockOrganizationsClient struct {
	DescribeOrganizationFunc func(ctx context.Context, params *organizations.DescribeOrganizationInput, optFns ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListPoliciesFunc         func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error)
}

func (m *MockOrganizationsClient) DescribeOrganization(ctx context.Context, params *organizations.DescribeOrganizationInput, optFns ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	return m.DescribeOrganizationFunc(ctx, params, optFns...)
}

func (m *MockOrganizationsClient) ListPolicies(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
	if m.ListPoliciesFunc != nil {
		return m.ListPoliciesFunc(ctx, params, optFns...)
	}
	return &organizations.ListPoliciesOutput{}, nil
}

func TestOrganizationsCollector_SCPsEnabled(t *testing.T) {
	mock := &MockOrganizationsClient{
		DescribeOrganizationFunc: func(ctx context.Context, params *organizations.DescribeOrganizationInput, optFns ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
			return &organizations.DescribeOrganizationOutput{
				Organization: &orgtypes.Organization{Id: awssdk.String("o-123")},
			}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{
					{Name: awssdk.String("FullAWSAccess")},
					{Name: awssdk.String("DenyS3Delete")},
					{Name: awssdk.String("RequireMFA")},
				},
			}, nil
		},
	}

	collector := NewOrganizationsCollector(mock)
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.True(t, status.IsOrganizationMember)
	assert.True(t, status.SCPEnabled)
	assert.Equal(t, 2, status.SCPCount, "should not count FullAWSAccess")
}

func TestOrganizationsCollector_NotInOrg(t *testing.T) {
	mock := &MockOrganizationsClient{
		DescribeOrganizationFunc: func(ctx context.Context, params *organizations.DescribeOrganizationInput, optFns ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
			return nil, errors.New("AWSOrganizationsNotInUseException")
		},
	}

	collector := NewOrganizationsCollector(mock)
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.False(t, status.IsOrganizationMember)
	assert.False(t, status.SCPEnabled)
}

func TestOrganizationsCollector_NoCustomSCPs(t *testing.T) {
	mock := &MockOrganizationsClient{
		DescribeOrganizationFunc: func(ctx context.Context, params *organizations.DescribeOrganizationInput, optFns ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
			return &organizations.DescribeOrganizationOutput{
				Organization: &orgtypes.Organization{Id: awssdk.String("o-123")},
			}, nil
		},
		ListPoliciesFunc: func(ctx context.Context, params *organizations.ListPoliciesInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesOutput, error) {
			return &organizations.ListPoliciesOutput{
				Policies: []orgtypes.PolicySummary{
					{Name: awssdk.String("FullAWSAccess")},
				},
			}, nil
		},
	}

	collector := NewOrganizationsCollector(mock)
	status, err := collector.CollectStatus(context.Background())

	require.NoError(t, err)
	assert.True(t, status.IsOrganizationMember)
	assert.False(t, status.SCPEnabled)
	assert.Equal(t, 0, status.SCPCount)
}

func TestOrganizationStatus_ToEvidence(t *testing.T) {
	status := &OrganizationStatus{IsOrganizationMember: true, SCPEnabled: true, SCPCount: 2}
	ev := status.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:organizations:status", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
