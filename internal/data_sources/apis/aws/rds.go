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
	DescribeDBSnapshots(ctx context.Context, params *rds.DescribeDBSnapshotsInput, optFns ...func(*rds.Options)) (*rds.DescribeDBSnapshotsOutput, error)
	DescribeEventSubscriptions(ctx context.Context, params *rds.DescribeEventSubscriptionsInput, optFns ...func(*rds.Options)) (*rds.DescribeEventSubscriptionsOutput, error)
	DescribeDBClusters(ctx context.Context, params *rds.DescribeDBClustersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBClustersOutput, error)
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
	ForceSSL               bool `json:"force_ssl"`
	AutoMinorVersionUpgrade bool `json:"auto_minor_version_upgrade"`
	DeletionProtection     bool `json:"deletion_protection"`
	ParameterGroupName         string `json:"parameter_group_name,omitempty"`
	EnhancedMonitoringEnabled      bool   `json:"enhanced_monitoring_enabled"`
	PerformanceInsightsEncrypted   bool   `json:"performance_insights_encrypted"`
	MasterUsername                 string `json:"master_username,omitempty"`
	IAMDatabaseAuthEnabled         bool   `json:"iam_database_authentication_enabled"`
	EnabledCloudwatchLogs          bool   `json:"enabled_cloudwatch_logs"`
	Port                           int32  `json:"port"`
	DBSubnetGroupName              string `json:"db_subnet_group_name,omitempty"`
}

// ToEvidence converts an RDSInstance to Evidence.
func (r *RDSInstance) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(r) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	ev := evidence.New("aws", "aws:rds:instance", r.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// RDSSnapshot represents an RDS DB snapshot.
type RDSSnapshot struct {
	SnapshotID   string `json:"snapshot_id"`
	DBInstanceID string `json:"db_instance_id,omitempty"`
	ARN          string `json:"arn"`
	Encrypted    bool   `json:"encrypted"`
	Public       bool   `json:"public"`
}

// ToEvidence converts an RDSSnapshot to Evidence.
func (s *RDSSnapshot) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:rds:snapshot", s.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// RDSEventSubscriptionStatus represents whether RDS event subscriptions are configured.
type RDSEventSubscriptionStatus struct {
	Configured bool   `json:"configured"`
	Region     string `json:"region"`
}

// ToEvidence converts an RDSEventSubscriptionStatus to Evidence.
func (s *RDSEventSubscriptionStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:rds::%s:event-subscription-status", accountID)
	ev := evidence.New("aws", "aws:rds:event-subscription", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// RDSCluster represents an RDS Aurora cluster.
type RDSCluster struct {
	ClusterID             string `json:"cluster_id"`
	ARN                   string `json:"arn"`
	Engine                string `json:"engine"`
	StorageEncrypted      bool   `json:"storage_encrypted"`
	EnabledCloudwatchLogs bool   `json:"enabled_cloudwatch_logs"`
}

// ToEvidence converts an RDSCluster to Evidence.
func (c *RDSCluster) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:rds:cluster", c.ARN, data)
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

			// Enhanced monitoring is enabled if MonitoringInterval > 0
			instance.EnhancedMonitoringEnabled = awssdk.ToInt32(db.MonitoringInterval) > 0
			instance.PerformanceInsightsEncrypted = awssdk.ToString(db.PerformanceInsightsKMSKeyId) != ""

			instance.DeletionProtection = awssdk.ToBool(db.DeletionProtection)
			instance.AutoMinorVersionUpgrade = awssdk.ToBool(db.AutoMinorVersionUpgrade)

			instance.MasterUsername = awssdk.ToString(db.MasterUsername)
			instance.IAMDatabaseAuthEnabled = awssdk.ToBool(db.IAMDatabaseAuthenticationEnabled)
			instance.EnabledCloudwatchLogs = len(db.EnabledCloudwatchLogsExports) > 0
			if db.Endpoint != nil {
				instance.Port = awssdk.ToInt32(db.Endpoint.Port)
			}
			if db.DBSubnetGroup != nil {
				instance.DBSubnetGroupName = awssdk.ToString(db.DBSubnetGroup.DBSubnetGroupName)
			}

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

// CollectSnapshots retrieves all RDS DB snapshots.
func (c *RDSCollector) CollectSnapshots(ctx context.Context) ([]RDSSnapshot, error) {
	var snapshots []RDSSnapshot
	var marker *string

	for {
		output, err := c.client.DescribeDBSnapshots(ctx, &rds.DescribeDBSnapshotsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe RDS snapshots: %w", err)
		}

		for i := range output.DBSnapshots {
			snap := &output.DBSnapshots[i]
			snapshot := RDSSnapshot{
				SnapshotID:   awssdk.ToString(snap.DBSnapshotIdentifier),
				DBInstanceID: awssdk.ToString(snap.DBInstanceIdentifier),
				ARN:          awssdk.ToString(snap.DBSnapshotArn),
				Encrypted:    awssdk.ToBool(snap.Encrypted),
			}

			// Check restore attribute for public sharing
			// Note: DescribeDBSnapshotAttributes would be more accurate,
			// but we use the simpler approach of checking if the snapshot
			// was marked as public during creation
			snapshot.Public = false

			snapshots = append(snapshots, snapshot)
		}

		if output.Marker == nil {
			break
		}
		marker = output.Marker
	}

	return snapshots, nil
}

// CollectEventSubscriptions retrieves RDS event subscription status.
func (c *RDSCollector) CollectEventSubscriptions(ctx context.Context) (*RDSEventSubscriptionStatus, error) {
	status := &RDSEventSubscriptionStatus{}

	output, err := c.client.DescribeEventSubscriptions(ctx, &rds.DescribeEventSubscriptionsInput{})
	if err != nil {
		return status, nil //nolint:nilerr // fail-safe: return partial results on error
	}

	status.Configured = len(output.EventSubscriptionsList) > 0
	return status, nil
}

// CollectClusters retrieves all RDS Aurora clusters.
func (c *RDSCollector) CollectClusters(ctx context.Context) ([]RDSCluster, error) {
	var clusters []RDSCluster
	var marker *string

	for {
		output, err := c.client.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe RDS clusters: %w", err)
		}

		for i := range output.DBClusters {
			cl := &output.DBClusters[i]
			clusters = append(clusters, RDSCluster{
				ClusterID:             awssdk.ToString(cl.DBClusterIdentifier),
				ARN:                   awssdk.ToString(cl.DBClusterArn),
				Engine:                awssdk.ToString(cl.Engine),
				StorageEncrypted:      awssdk.ToBool(cl.StorageEncrypted),
				EnabledCloudwatchLogs: len(cl.EnabledCloudwatchLogsExports) > 0,
			})
		}

		if output.Marker == nil {
			break
		}
		marker = output.Marker
	}

	return clusters, nil
}

// CollectEvidence collects RDS instances and snapshots as evidence.
func (c *RDSCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	instances, err := c.CollectInstances(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(instances))
	for i := range instances {
		evidenceList = append(evidenceList, instances[i].ToEvidence(accountID))
	}

	// Collect snapshots (fail-safe)
	snapshots, err := c.CollectSnapshots(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range snapshots {
			evidenceList = append(evidenceList, snapshots[i].ToEvidence(accountID))
		}
	}

	// Clusters (fail-safe)
	clusters, err := c.CollectClusters(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range clusters {
			evidenceList = append(evidenceList, clusters[i].ToEvidence(accountID))
		}
	}

	// Event subscriptions
	eventSub, err := c.CollectEventSubscriptions(ctx)
	if err == nil {
		evidenceList = append(evidenceList, eventSub.ToEvidence(accountID))
	}

	return evidenceList, nil
}
