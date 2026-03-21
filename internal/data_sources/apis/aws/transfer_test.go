package aws

import (
	"context"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	transfertypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockTransferClient struct {
	ListServersFunc    func(ctx context.Context, params *transfer.ListServersInput, optFns ...func(*transfer.Options)) (*transfer.ListServersOutput, error)
	DescribeServerFunc func(ctx context.Context, params *transfer.DescribeServerInput, optFns ...func(*transfer.Options)) (*transfer.DescribeServerOutput, error)
}

func (m *MockTransferClient) ListServers(ctx context.Context, params *transfer.ListServersInput, optFns ...func(*transfer.Options)) (*transfer.ListServersOutput, error) {
	return m.ListServersFunc(ctx, params, optFns...)
}

func (m *MockTransferClient) DescribeServer(ctx context.Context, params *transfer.DescribeServerInput, optFns ...func(*transfer.Options)) (*transfer.DescribeServerOutput, error) {
	if m.DescribeServerFunc != nil {
		return m.DescribeServerFunc(ctx, params, optFns...)
	}
	return &transfer.DescribeServerOutput{}, nil
}

func TestTransferCollector_CollectServers(t *testing.T) {
	mock := &MockTransferClient{
		ListServersFunc: func(ctx context.Context, params *transfer.ListServersInput, optFns ...func(*transfer.Options)) (*transfer.ListServersOutput, error) {
			return &transfer.ListServersOutput{
				Servers: []transfertypes.ListedServer{
					{
						ServerId: awssdk.String("s-sftp123"),
						Arn:      awssdk.String("arn:aws:transfer:us-east-1:123:server/s-sftp123"),
					},
					{
						ServerId: awssdk.String("s-ftp456"),
						Arn:      awssdk.String("arn:aws:transfer:us-east-1:123:server/s-ftp456"),
					},
				},
			}, nil
		},
		DescribeServerFunc: func(ctx context.Context, params *transfer.DescribeServerInput, optFns ...func(*transfer.Options)) (*transfer.DescribeServerOutput, error) {
			if awssdk.ToString(params.ServerId) == "s-sftp123" {
				return &transfer.DescribeServerOutput{
					Server: &transfertypes.DescribedServer{
						Protocols: []transfertypes.Protocol{transfertypes.ProtocolSftp},
						Arn:       awssdk.String("arn:aws:transfer:us-east-1:123:server/s-sftp123"),
					},
				}, nil
			}
			return &transfer.DescribeServerOutput{
				Server: &transfertypes.DescribedServer{
					Protocols: []transfertypes.Protocol{transfertypes.ProtocolFtp},
					Arn:       awssdk.String("arn:aws:transfer:us-east-1:123:server/s-ftp456"),
				},
			}, nil
		},
	}

	collector := NewTransferCollector(mock)
	servers, err := collector.CollectServers(context.Background())

	require.NoError(t, err)
	require.Len(t, servers, 2)

	assert.Equal(t, "s-sftp123", servers[0].ServerID)
	assert.Equal(t, "SFTP", servers[0].Protocol)

	assert.Equal(t, "s-ftp456", servers[1].ServerID)
	assert.Equal(t, "FTP", servers[1].Protocol)
}

func TestTransferCollector_CollectEvidence(t *testing.T) {
	mock := &MockTransferClient{
		ListServersFunc: func(ctx context.Context, params *transfer.ListServersInput, optFns ...func(*transfer.Options)) (*transfer.ListServersOutput, error) {
			return &transfer.ListServersOutput{
				Servers: []transfertypes.ListedServer{
					{ServerId: awssdk.String("s-abc"), Arn: awssdk.String("arn:aws:transfer:us-east-1:123:server/s-abc")},
				},
			}, nil
		},
	}

	collector := NewTransferCollector(mock)
	ev, err := collector.CollectEvidence(context.Background(), "123456789012")

	require.NoError(t, err)
	require.Len(t, ev, 1)
	assert.Equal(t, "aws:transfer:server", ev[0].ResourceType)
}
