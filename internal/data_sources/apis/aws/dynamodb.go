package aws

import (
	"context"
	"encoding/json"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// DynamoDBClient defines the interface for DynamoDB operations.
type DynamoDBClient interface {
	ListTables(ctx context.Context, params *dynamodb.ListTablesInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error)
	DescribeTable(ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
	DescribeContinuousBackups(ctx context.Context, params *dynamodb.DescribeContinuousBackupsInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeContinuousBackupsOutput, error)
}

// DynamoDBTable represents a DynamoDB table with security configuration.
type DynamoDBTable struct {
	Name           string `json:"name"`
	ARN            string `json:"arn"`
	EncryptionType string `json:"encryption_type,omitempty"`
	SSEEnabled     bool   `json:"sse_enabled"`
	PITREnabled    bool   `json:"pitr_enabled"`
	BillingMode        string `json:"billing_mode,omitempty"`
	DeletionProtection bool   `json:"deletion_protection"`
}

// ToEvidence converts a DynamoDBTable to Evidence.
func (d *DynamoDBTable) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(d) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:dynamodb:table", d.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// DynamoDBCollector collects DynamoDB table data.
type DynamoDBCollector struct {
	client DynamoDBClient
}

// NewDynamoDBCollector creates a new DynamoDB collector.
func NewDynamoDBCollector(client DynamoDBClient) *DynamoDBCollector {
	return &DynamoDBCollector{client: client}
}

// CollectTables retrieves all DynamoDB tables with encryption and PITR status.
func (c *DynamoDBCollector) CollectTables(ctx context.Context) ([]DynamoDBTable, error) {
	var tables []DynamoDBTable
	var lastTable *string

	for {
		output, err := c.client.ListTables(ctx, &dynamodb.ListTablesInput{
			ExclusiveStartTableName: lastTable,
		})
		if err != nil {
			return nil, err
		}

		for _, name := range output.TableNames {
			table := DynamoDBTable{Name: name}
			c.enrichTableDetails(ctx, &table)
			c.enrichPITR(ctx, &table)
			tables = append(tables, table)
		}

		if output.LastEvaluatedTableName == nil {
			break
		}
		lastTable = output.LastEvaluatedTableName
	}

	return tables, nil
}

func (c *DynamoDBCollector) enrichTableDetails(ctx context.Context, table *DynamoDBTable) {
	output, err := c.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: awssdk.String(table.Name),
	})
	if err != nil {
		return
	}

	if output.Table != nil {
		table.ARN = awssdk.ToString(output.Table.TableArn)
		if output.Table.SSEDescription != nil {
			table.SSEEnabled = output.Table.SSEDescription.Status == statusEnabled
			table.EncryptionType = string(output.Table.SSEDescription.SSEType)
		} else {
			// Default encryption (AWS owned key) is always enabled
			table.SSEEnabled = true
			table.EncryptionType = "DEFAULT"
		}
		if output.Table.BillingModeSummary != nil {
			table.BillingMode = string(output.Table.BillingModeSummary.BillingMode)
		}
		if output.Table.DeletionProtectionEnabled != nil {
			table.DeletionProtection = *output.Table.DeletionProtectionEnabled
		}
	}
}

func (c *DynamoDBCollector) enrichPITR(ctx context.Context, table *DynamoDBTable) {
	output, err := c.client.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{
		TableName: awssdk.String(table.Name),
	})
	if err != nil {
		return
	}

	if output.ContinuousBackupsDescription != nil &&
		output.ContinuousBackupsDescription.PointInTimeRecoveryDescription != nil {
		table.PITREnabled = output.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == statusEnabled
	}
}

// CollectEvidence collects DynamoDB tables as evidence.
func (c *DynamoDBCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	tables, err := c.CollectTables(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(tables))
	for i := range tables {
		evidenceList = append(evidenceList, tables[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
