package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// TransferClient defines the interface for Transfer Family operations.
type TransferClient interface {
	ListServers(ctx context.Context, params *transfer.ListServersInput, optFns ...func(*transfer.Options)) (*transfer.ListServersOutput, error)
	DescribeServer(ctx context.Context, params *transfer.DescribeServerInput, optFns ...func(*transfer.Options)) (*transfer.DescribeServerOutput, error)
}

// TransferServer represents an AWS Transfer Family server.
type TransferServer struct {
	ServerID string `json:"server_id"`
	ARN      string `json:"arn"`
	Protocol string `json:"protocol"`
}

// ToEvidence converts a TransferServer to Evidence.
func (s *TransferServer) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck
	ev := evidence.New("aws", "aws:transfer:server", s.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// TransferCollector collects Transfer Family server data.
type TransferCollector struct {
	client TransferClient
}

// NewTransferCollector creates a new Transfer Family collector.
func NewTransferCollector(client TransferClient) *TransferCollector {
	return &TransferCollector{client: client}
}

// CollectServers retrieves all Transfer Family servers with protocol information.
func (c *TransferCollector) CollectServers(ctx context.Context) ([]TransferServer, error) {
	var servers []TransferServer
	var nextToken *string

	for {
		output, err := c.client.ListServers(ctx, &transfer.ListServersInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list Transfer Family servers: %w", err)
		}

		for _, item := range output.Servers {
			server := TransferServer{
				ServerID: awssdk.ToString(item.ServerId),
				ARN:      awssdk.ToString(item.Arn),
			}

			c.enrichServer(ctx, &server)
			servers = append(servers, server)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return servers, nil
}

// enrichServer retrieves detailed server information and sets protocol.
func (c *TransferCollector) enrichServer(ctx context.Context, server *TransferServer) {
	output, err := c.client.DescribeServer(ctx, &transfer.DescribeServerInput{
		ServerId: awssdk.String(server.ServerID),
	})
	if err != nil {
		return // Fail-safe
	}

	if output.Server != nil && len(output.Server.Protocols) > 0 {
		// Use the first protocol; Transfer servers typically have one primary protocol
		server.Protocol = string(output.Server.Protocols[0])
		if server.ARN == "" {
			server.ARN = awssdk.ToString(output.Server.Arn)
		}
	}
}

// CollectEvidence collects Transfer Family servers as evidence.
func (c *TransferCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	servers, err := c.CollectServers(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(servers))
	for i := range servers {
		evidenceList = append(evidenceList, servers[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
