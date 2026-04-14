package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	ostypes "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockOpenSearchClient struct {
	ListDomainNamesFunc func(ctx context.Context, params *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error)
	DescribeDomainsFunc func(ctx context.Context, params *opensearch.DescribeDomainsInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainsOutput, error)
}

func (m *MockOpenSearchClient) ListDomainNames(ctx context.Context, params *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
	return m.ListDomainNamesFunc(ctx, params, optFns...)
}

func (m *MockOpenSearchClient) DescribeDomains(ctx context.Context, params *opensearch.DescribeDomainsInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainsOutput, error) {
	return m.DescribeDomainsFunc(ctx, params, optFns...)
}

func TestOpenSearchCollector_CollectDomains(t *testing.T) {
	mock := &MockOpenSearchClient{
		ListDomainNamesFunc: func(ctx context.Context, params *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
			return &opensearch.ListDomainNamesOutput{
				DomainNames: []ostypes.DomainInfo{
					{DomainName: awssdk.String("prod-search")},
					{DomainName: awssdk.String("dev-search")},
				},
			}, nil
		},
		DescribeDomainsFunc: func(ctx context.Context, params *opensearch.DescribeDomainsInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainsOutput, error) {
			return &opensearch.DescribeDomainsOutput{
				DomainStatusList: []ostypes.DomainStatus{
					{
						DomainName:                  awssdk.String("prod-search"),
						DomainId:                    awssdk.String("123/prod-search"),
						ARN:                         awssdk.String("arn:aws:es:us-east-1:123:domain/prod-search"),
						EncryptionAtRestOptions:     &ostypes.EncryptionAtRestOptions{Enabled: awssdk.Bool(true)},
						NodeToNodeEncryptionOptions: &ostypes.NodeToNodeEncryptionOptions{Enabled: awssdk.Bool(true)},
						VPCOptions:                  &ostypes.VPCDerivedInfo{VPCId: awssdk.String("vpc-123")},
						DomainEndpointOptions:       &ostypes.DomainEndpointOptions{EnforceHTTPS: awssdk.Bool(true)},
					},
					{
						DomainName:                  awssdk.String("dev-search"),
						DomainId:                    awssdk.String("123/dev-search"),
						ARN:                         awssdk.String("arn:aws:es:us-east-1:123:domain/dev-search"),
						EncryptionAtRestOptions:     &ostypes.EncryptionAtRestOptions{Enabled: awssdk.Bool(false)},
						NodeToNodeEncryptionOptions: &ostypes.NodeToNodeEncryptionOptions{Enabled: awssdk.Bool(false)},
					},
				},
			}, nil
		},
	}

	collector := NewOpenSearchCollector(mock)
	domains, err := collector.CollectDomains(context.Background())

	require.NoError(t, err)
	require.Len(t, domains, 2)

	assert.Equal(t, "prod-search", domains[0].DomainName)
	assert.True(t, domains[0].EncryptedAtRest)
	assert.True(t, domains[0].NodeToNodeEncryption)
	assert.True(t, domains[0].VPCConfigured)
	assert.True(t, domains[0].EnforceHTTPS)

	assert.Equal(t, "dev-search", domains[1].DomainName)
	assert.False(t, domains[1].EncryptedAtRest)
	assert.False(t, domains[1].NodeToNodeEncryption)
	assert.False(t, domains[1].VPCConfigured)
}

func TestOpenSearchCollector_CollectDomains_Empty(t *testing.T) {
	mock := &MockOpenSearchClient{
		ListDomainNamesFunc: func(ctx context.Context, params *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
			return &opensearch.ListDomainNamesOutput{DomainNames: []ostypes.DomainInfo{}}, nil
		},
	}

	collector := NewOpenSearchCollector(mock)
	domains, err := collector.CollectDomains(context.Background())

	require.NoError(t, err)
	assert.Empty(t, domains)
}

func TestOpenSearchCollector_CollectDomains_Error(t *testing.T) {
	mock := &MockOpenSearchClient{
		ListDomainNamesFunc: func(ctx context.Context, params *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewOpenSearchCollector(mock)
	_, err := collector.CollectDomains(context.Background())
	assert.Error(t, err)
}

func TestOpenSearchCollector_CollectDomains_DescribeError(t *testing.T) {
	mock := &MockOpenSearchClient{
		ListDomainNamesFunc: func(ctx context.Context, params *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
			return &opensearch.ListDomainNamesOutput{
				DomainNames: []ostypes.DomainInfo{
					{DomainName: awssdk.String("test-domain")},
				},
			}, nil
		},
		DescribeDomainsFunc: func(ctx context.Context, params *opensearch.DescribeDomainsInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainsOutput, error) {
			return nil, errors.New("describe failed")
		},
	}

	collector := NewOpenSearchCollector(mock)
	_, err := collector.CollectDomains(context.Background())
	assert.Error(t, err, "should propagate DescribeDomains error")
}

func TestOpenSearchCollector_CollectDomains_NilOptionalFields(t *testing.T) {
	mock := &MockOpenSearchClient{
		ListDomainNamesFunc: func(ctx context.Context, params *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
			return &opensearch.ListDomainNamesOutput{
				DomainNames: []ostypes.DomainInfo{
					{DomainName: awssdk.String("minimal-domain")},
				},
			}, nil
		},
		DescribeDomainsFunc: func(ctx context.Context, params *opensearch.DescribeDomainsInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainsOutput, error) {
			return &opensearch.DescribeDomainsOutput{
				DomainStatusList: []ostypes.DomainStatus{
					{
						DomainName: awssdk.String("minimal-domain"),
						DomainId:   awssdk.String("123/minimal-domain"),
						ARN:        awssdk.String("arn:aws:es:us-east-1:123:domain/minimal-domain"),
						// All optional security fields nil
					},
				},
			}, nil
		},
	}

	collector := NewOpenSearchCollector(mock)
	domains, err := collector.CollectDomains(context.Background())

	require.NoError(t, err)
	require.Len(t, domains, 1)
	assert.False(t, domains[0].EncryptedAtRest, "nil encryption should default to false")
	assert.False(t, domains[0].NodeToNodeEncryption, "nil node encryption should default to false")
	assert.False(t, domains[0].VPCConfigured, "nil VPC should default to false")
	assert.False(t, domains[0].EnforceHTTPS, "nil endpoint options should default to false")
}

func TestOpenSearchCollector_CollectEvidence(t *testing.T) {
	mock := &MockOpenSearchClient{
		ListDomainNamesFunc: func(ctx context.Context, params *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
			return &opensearch.ListDomainNamesOutput{
				DomainNames: []ostypes.DomainInfo{
					{DomainName: awssdk.String("ev-domain")},
				},
			}, nil
		},
		DescribeDomainsFunc: func(ctx context.Context, params *opensearch.DescribeDomainsInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainsOutput, error) {
			return &opensearch.DescribeDomainsOutput{
				DomainStatusList: []ostypes.DomainStatus{
					{
						DomainName:              awssdk.String("ev-domain"),
						DomainId:                awssdk.String("123/ev-domain"),
						ARN:                     awssdk.String("arn:aws:es:us-east-1:123:domain/ev-domain"),
						EncryptionAtRestOptions: &ostypes.EncryptionAtRestOptions{Enabled: awssdk.Bool(true)},
					},
				},
			}, nil
		},
	}

	collector := NewOpenSearchCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:opensearch:domain", ev[0].ResourceType)
	assert.Equal(t, "123456789012", ev[0].Metadata.AccountID)
}

func TestOpenSearchCollector_CollectEvidence_Error(t *testing.T) {
	mock := &MockOpenSearchClient{
		ListDomainNamesFunc: func(ctx context.Context, params *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error) {
			return nil, errors.New("service unavailable")
		},
		DescribeDomainsFunc: func(ctx context.Context, params *opensearch.DescribeDomainsInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainsOutput, error) {
			return nil, errors.New("should not be called")
		},
	}

	collector := NewOpenSearchCollector(mock)
	_, err := collector.CollectEvidence(context.Background(), "123456789012")
	assert.Error(t, err)
}

func TestOpenSearchDomain_ToEvidence(t *testing.T) {
	domain := &OpenSearchDomain{
		DomainName:      "prod-search",
		ARN:             "arn:aws:es:us-east-1:123:domain/prod-search",
		EncryptedAtRest: true,
	}
	ev := domain.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:opensearch:domain", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
