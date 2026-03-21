package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// DMSClient defines the interface for DMS operations.
type DMSClient interface {
	DescribeReplicationInstances(ctx context.Context, params *databasemigrationservice.DescribeReplicationInstancesInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationInstancesOutput, error)
	DescribeEndpoints(ctx context.Context, params *databasemigrationservice.DescribeEndpointsInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeEndpointsOutput, error)
	DescribeReplicationTasks(ctx context.Context, params *databasemigrationservice.DescribeReplicationTasksInput, optFns ...func(*databasemigrationservice.Options)) (*databasemigrationservice.DescribeReplicationTasksOutput, error)
}

// DMSReplicationInstance represents a DMS replication instance.
type DMSReplicationInstance struct {
	ID                      string `json:"id"`
	ARN                     string `json:"arn"`
	PubliclyAccessible      bool   `json:"publicly_accessible"`
	AutoMinorVersionUpgrade bool   `json:"auto_minor_version_upgrade"`
	MultiAZ                 bool   `json:"multi_az"`
}

// ToEvidence converts a DMSReplicationInstance to Evidence.
func (d *DMSReplicationInstance) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(d) //nolint:errcheck
	ev := evidence.New("aws", "aws:dms:replication-instance", d.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// DMSEndpoint represents a DMS endpoint.
type DMSEndpoint struct {
	ID      string `json:"id"`
	ARN     string `json:"arn"`
	SSLMode string `json:"ssl_mode"`
}

// ToEvidence converts a DMSEndpoint to Evidence.
func (d *DMSEndpoint) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(d) //nolint:errcheck
	ev := evidence.New("aws", "aws:dms:endpoint", d.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// DMSReplicationTask represents a DMS replication task.
type DMSReplicationTask struct {
	TaskID               string `json:"task_id"`
	ARN                  string `json:"arn"`
	SourceLoggingEnabled bool   `json:"source_logging_enabled"`
	TargetLoggingEnabled bool   `json:"target_logging_enabled"`
}

// ToEvidence converts a DMSReplicationTask to Evidence.
func (t *DMSReplicationTask) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(t) //nolint:errcheck
	ev := evidence.New("aws", "aws:dms:replication-task", t.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// DMSCollector collects DMS data.
type DMSCollector struct {
	client DMSClient
}

// NewDMSCollector creates a new DMS collector.
func NewDMSCollector(client DMSClient) *DMSCollector {
	return &DMSCollector{client: client}
}

// CollectReplicationInstances retrieves all DMS replication instances.
func (c *DMSCollector) CollectReplicationInstances(ctx context.Context) ([]DMSReplicationInstance, error) {
	var instances []DMSReplicationInstance
	var marker *string

	for {
		output, err := c.client.DescribeReplicationInstances(ctx, &databasemigrationservice.DescribeReplicationInstancesInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe DMS replication instances: %w", err)
		}

		for i := range output.ReplicationInstances {
			ri := &output.ReplicationInstances[i]
			instance := DMSReplicationInstance{
				ID:                      awssdk.ToString(ri.ReplicationInstanceIdentifier),
				ARN:                     awssdk.ToString(ri.ReplicationInstanceArn),
				PubliclyAccessible:      ri.PubliclyAccessible,
				AutoMinorVersionUpgrade: ri.AutoMinorVersionUpgrade,
				MultiAZ:                 ri.MultiAZ,
			}
			instances = append(instances, instance)
		}

		if output.Marker == nil {
			break
		}
		marker = output.Marker
	}

	return instances, nil
}

// CollectEndpoints retrieves all DMS endpoints.
func (c *DMSCollector) CollectEndpoints(ctx context.Context) ([]DMSEndpoint, error) {
	var endpoints []DMSEndpoint
	var marker *string

	for {
		output, err := c.client.DescribeEndpoints(ctx, &databasemigrationservice.DescribeEndpointsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe DMS endpoints: %w", err)
		}

		for i := range output.Endpoints {
			ep := &output.Endpoints[i]
			endpoint := DMSEndpoint{
				ID:      awssdk.ToString(ep.EndpointIdentifier),
				ARN:     awssdk.ToString(ep.EndpointArn),
				SSLMode: string(ep.SslMode),
			}
			endpoints = append(endpoints, endpoint)
		}

		if output.Marker == nil {
			break
		}
		marker = output.Marker
	}

	return endpoints, nil
}

// CollectReplicationTasks retrieves all DMS replication tasks.
func (c *DMSCollector) CollectReplicationTasks(ctx context.Context) ([]DMSReplicationTask, error) {
	var tasks []DMSReplicationTask
	var marker *string

	for {
		output, err := c.client.DescribeReplicationTasks(ctx, &databasemigrationservice.DescribeReplicationTasksInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe DMS replication tasks: %w", err)
		}

		for i := range output.ReplicationTasks {
			rt := &output.ReplicationTasks[i]
			task := DMSReplicationTask{
				TaskID: awssdk.ToString(rt.ReplicationTaskIdentifier),
				ARN:    awssdk.ToString(rt.ReplicationTaskArn),
			}

			// Check task settings JSON for logging configuration
			if rt.ReplicationTaskSettings != nil {
				settings := awssdk.ToString(rt.ReplicationTaskSettings)
				task.SourceLoggingEnabled = strings.Contains(settings, `"SOURCE_CAPTURE"`) || strings.Contains(settings, `"SOURCE_UNLOAD"`)
				task.TargetLoggingEnabled = strings.Contains(settings, `"TARGET_LOAD"`) || strings.Contains(settings, `"TARGET_APPLY"`)
			}

			tasks = append(tasks, task)
		}

		if output.Marker == nil {
			break
		}
		marker = output.Marker
	}

	return tasks, nil
}

// CollectEvidence collects DMS replication instances and endpoints as evidence.
func (c *DMSCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	var evidenceList []evidence.Evidence

	instances, err := c.CollectReplicationInstances(ctx)
	if err != nil {
		return nil, err
	}
	for i := range instances {
		evidenceList = append(evidenceList, instances[i].ToEvidence(accountID))
	}

	// Endpoints (fail-safe)
	endpoints, err := c.CollectEndpoints(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range endpoints {
			evidenceList = append(evidenceList, endpoints[i].ToEvidence(accountID))
		}
	}

	// Replication tasks (fail-safe)
	tasks, err := c.CollectReplicationTasks(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range tasks {
			evidenceList = append(evidenceList, tasks[i].ToEvidence(accountID))
		}
	}

	return evidenceList, nil
}
