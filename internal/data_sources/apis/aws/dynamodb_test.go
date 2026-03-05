package aws

import (
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockDynamoDBClient struct {
	ListTablesFunc             func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error)
	DescribeTableFunc          func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	DescribeContinuousBackupsFunc func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error)
}

func (m *MockDynamoDBClient) ListTables(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	return m.ListTablesFunc(ctx, params, optFns...)
}

func (m *MockDynamoDBClient) DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if m.DescribeTableFunc != nil {
		return m.DescribeTableFunc(ctx, params, optFns...)
	}
	return &dynamodb.DescribeTableOutput{Table: &ddbtypes.TableDescription{TableArn: awssdk.String("arn:aws:dynamodb:us-east-1:123:table/" + *params.TableName)}}, nil
}

func (m *MockDynamoDBClient) DescribeContinuousBackups(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
	if m.DescribeContinuousBackupsFunc != nil {
		return m.DescribeContinuousBackupsFunc(ctx, params, optFns...)
	}
	return &dynamodb.DescribeContinuousBackupsOutput{}, nil
}

func TestDynamoDBCollector_CollectTables(t *testing.T) {
	mock := &MockDynamoDBClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{TableNames: []string{"users", "orders"}}, nil
		},
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{
					TableArn: awssdk.String("arn:aws:dynamodb:us-east-1:123:table/" + *params.TableName),
					SSEDescription: &ddbtypes.SSEDescription{
						Status:  "ENABLED",
						SSEType: ddbtypes.SSETypeKms,
					},
				},
			}, nil
		},
		DescribeContinuousBackupsFunc: func(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error) {
			return &dynamodb.DescribeContinuousBackupsOutput{
				ContinuousBackupsDescription: &ddbtypes.ContinuousBackupsDescription{
					PointInTimeRecoveryDescription: &ddbtypes.PointInTimeRecoveryDescription{
						PointInTimeRecoveryStatus: "ENABLED",
					},
				},
			}, nil
		},
	}

	collector := NewDynamoDBCollector(mock)
	tables, err := collector.CollectTables(context.Background())

	require.NoError(t, err)
	require.Len(t, tables, 2)
	assert.True(t, tables[0].SSEEnabled)
	assert.True(t, tables[0].PITREnabled)
	assert.Equal(t, "KMS", tables[0].EncryptionType)
}

func TestDynamoDBCollector_CollectTables_DefaultEncryption(t *testing.T) {
	mock := &MockDynamoDBClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return &dynamodb.ListTablesOutput{TableNames: []string{"my-table"}}, nil
		},
		DescribeTableFunc: func(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
			return &dynamodb.DescribeTableOutput{
				Table: &ddbtypes.TableDescription{
					TableArn:       awssdk.String("arn:aws:dynamodb:us-east-1:123:table/my-table"),
					SSEDescription: nil, // Default encryption
				},
			}, nil
		},
	}

	collector := NewDynamoDBCollector(mock)
	tables, err := collector.CollectTables(context.Background())

	require.NoError(t, err)
	require.Len(t, tables, 1)
	assert.True(t, tables[0].SSEEnabled, "default encryption should be treated as enabled")
	assert.Equal(t, "DEFAULT", tables[0].EncryptionType)
}

func TestDynamoDBCollector_CollectTables_Error(t *testing.T) {
	mock := &MockDynamoDBClient{
		ListTablesFunc: func(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
			return nil, errors.New("access denied")
		},
	}

	collector := NewDynamoDBCollector(mock)
	_, err := collector.CollectTables(context.Background())
	assert.Error(t, err)
}

func TestDynamoDBTable_ToEvidence(t *testing.T) {
	table := &DynamoDBTable{Name: "test", ARN: "arn:aws:dynamodb:us-east-1:123:table/test"}
	ev := table.ToEvidence("123456789012")
	assert.Equal(t, "aws", ev.Collector)
	assert.Equal(t, "aws:dynamodb:table", ev.ResourceType)
	assert.NotEmpty(t, ev.Hash)
}
