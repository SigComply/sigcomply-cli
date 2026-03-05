package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// RDSClient defines the interface for RDS operations.
type RDSClient interface {
	DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	DescribeDBParameterGroups(ctx context.Context, params *rds.DescribeDBParameterGroupsInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParameterGroupsOutput, error)
	DescribeDBParameters(ctx context.Context, params *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error)
}

// RDSInstance represents an RDS database instance.
type RDSInstance struct {
	DBInstanceID        string `json:"db_instance_id"`
	ARN                 string `json:"arn"`
	Engine              string `json:"engine"`
	EngineVersion       string `json:"engine_version,omitempty"`
	DBInstanceClass     string `json:"db_instance_class"`
	StorageEncrypted    bool   `json:"storage_encrypted"`
	KMSKeyID            string `json:"kms_key_id,omitempty"`
	PubliclyAccessible  bool   `json:"publicly_accessible"`
	MultiAZ             bool   `json:"multi_az"`
	BackupRetentionPeriod int  `json:"backup_retention_period"`
	BackupEnabled       bool   `json:"backup_enabled"`
	PITREnabled         bool   `json:"pitr_enabled"`
	ForceSSL            bool   `json:"force_ssl"`
	DeletionProtection  bool   `json:"deletion_protection"`
	ParameterGroupName  string `json:"parameter_group_name,omitempty"`
}

// ToEvidence converts an RDSInstance to Evidence.
func (r *RDSInstance) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(r) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	ev := evidence.New("aws", "aws:rds:instance", r.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// RDSCollector collects RDS instance data.
type RDSCollector struct {
	client RDSClient
}

// NewRDSCollector creates a new RDS collector.
func NewRDSCollector(client RDSClient) *RDSCollector {
	return &RDSCollector{client: client}
}

// CollectInstances retrieves all RDS instances.
func (c *RDSCollector) CollectInstances(ctx context.Context) ([]RDSInstance, error) {
	var instances []RDSInstance
	var marker *string

	for {
		output, err := c.client.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe RDS instances: %w", err)
		}

		for idx := range output.DBInstances {
			db := &output.DBInstances[idx]
			instance := RDSInstance{
				DBInstanceID:        awssdk.ToString(db.DBInstanceIdentifier),
				ARN:                 awssdk.ToString(db.DBInstanceArn),
				Engine:              awssdk.ToString(db.Engine),
				EngineVersion:       awssdk.ToString(db.EngineVersion),
				DBInstanceClass:     awssdk.ToString(db.DBInstanceClass),
				StorageEncrypted:    awssdk.ToBool(db.StorageEncrypted),
				PubliclyAccessible:  awssdk.ToBool(db.PubliclyAccessible),
				MultiAZ:            awssdk.ToBool(db.MultiAZ),
				BackupRetentionPeriod: int(awssdk.ToInt32(db.BackupRetentionPeriod)),
			}

			instance.DeletionProtection = awssdk.ToBool(db.DeletionProtection)

			if db.KmsKeyId != nil {
				instance.KMSKeyID = awssdk.ToString(db.KmsKeyId)
			}

			// Backup is enabled if retention period > 0
			instance.BackupEnabled = awssdk.ToInt32(db.BackupRetentionPeriod) > 0
			// PITR is available when automated backups are enabled
			instance.PITREnabled = awssdk.ToInt32(db.BackupRetentionPeriod) > 0

			// Get parameter group name
			if len(db.DBParameterGroups) > 0 {
				instance.ParameterGroupName = awssdk.ToString(db.DBParameterGroups[0].DBParameterGroupName)
			}

			// Check SSL enforcement via parameter group
			c.enrichSSLStatus(ctx, &instance)

			instances = append(instances, instance)
		}

		if output.Marker == nil {
			break
		}
		marker = output.Marker
	}

	return instances, nil
}

// enrichSSLStatus checks if SSL is enforced for the RDS instance.
func (c *RDSCollector) enrichSSLStatus(ctx context.Context, instance *RDSInstance) {
	if instance.ParameterGroupName == "" {
		return
	}

	// Look for SSL-related parameters
	sslParamNames := map[string]bool{
		"rds.force_ssl":   true,
		"require_secure_transport": true,
	}

	output, err := c.client.DescribeDBParameters(ctx, &rds.DescribeDBParametersInput{
		DBParameterGroupName: awssdk.String(instance.ParameterGroupName),
	})
	if err != nil {
		return // Fail-safe
	}

	for _, param := range output.Parameters {
		name := awssdk.ToString(param.ParameterName)
		if sslParamNames[name] {
			val := awssdk.ToString(param.ParameterValue)
			if val == "1" || val == "true" || val == "ON" {
				instance.ForceSSL = true
				return
			}
		}
	}
}

// CollectEvidence collects RDS instances as evidence.
func (c *RDSCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	instances, err := c.CollectInstances(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(instances))
	for i := range instances {
		evidenceList = append(evidenceList, instances[i].ToEvidence(accountID))
	}

	return evidenceList, nil
}
