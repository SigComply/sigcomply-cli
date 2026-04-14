package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockCloudFrontClient struct {
	ListDistributionsFunc func(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
	GetDistributionFunc   func(ctx context.Context, params *cloudfront.GetDistributionInput, optFns ...func(*cloudfront.Options)) (*cloudfront.GetDistributionOutput, error)
}

func (m *MockCloudFrontClient) ListDistributions(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	return m.ListDistributionsFunc(ctx, params, optFns...)
}

func (m *MockCloudFrontClient) GetDistribution(ctx context.Context, params *cloudfront.GetDistributionInput, optFns ...func(*cloudfront.Options)) (*cloudfront.GetDistributionOutput, error) {
	if m.GetDistributionFunc != nil {
		return m.GetDistributionFunc(ctx, params, optFns...)
	}
	return nil, errors.New("not implemented")
}

func TestCloudFrontCollector_CollectDistributions(t *testing.T) {
	mock := &MockCloudFrontClient{
		ListDistributionsFunc: func(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
			return &cloudfront.ListDistributionsOutput{
				DistributionList: &cftypes.DistributionList{
					Items: []cftypes.DistributionSummary{
						{
							ARN:        awssdk.String("arn:aws:cloudfront::123:distribution/ABC"),
							DomainName: awssdk.String("d123.cloudfront.net"),
							DefaultCacheBehavior: &cftypes.DefaultCacheBehavior{
								ViewerProtocolPolicy: cftypes.ViewerProtocolPolicyHttpsOnly,
							},
						},
						{
							ARN:        awssdk.String("arn:aws:cloudfront::123:distribution/DEF"),
							DomainName: awssdk.String("d456.cloudfront.net"),
							DefaultCacheBehavior: &cftypes.DefaultCacheBehavior{
								ViewerProtocolPolicy: cftypes.ViewerProtocolPolicyAllowAll,
							},
						},
					},
				},
			}, nil
		},
	}

	collector := NewCloudFrontCollector(mock)
	dists, err := collector.CollectDistributions(context.Background())

	require.NoError(t, err)
	require.Len(t, dists, 2)
	assert.True(t, dists[0].HTTPSOnly)
	assert.False(t, dists[1].HTTPSOnly)
}

func TestCloudFrontCollector_CollectDistributions_Error(t *testing.T) {
	mock := &MockCloudFrontClient{
		ListDistributionsFunc: func(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewCloudFrontCollector(mock)
	_, err := collector.CollectDistributions(context.Background())
	assert.Error(t, err)
}

func TestCloudFrontDistribution_ToEvidence(t *testing.T) {
	dist := &CloudFrontDistribution{ARN: "arn:aws:cloudfront::123:distribution/ABC", DomainName: "d123.cloudfront.net"}
	ev := dist.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:cloudfront:distribution", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
