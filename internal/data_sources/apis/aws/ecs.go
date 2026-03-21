package aws

import (
	"context"
	"encoding/json"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// ECSClient defines the interface for ECS operations.
type ECSClient interface {
	ListClusters(ctx context.Context, params *ecs.ListClustersInput, optFns ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	DescribeClusters(ctx context.Context, params *ecs.DescribeClustersInput, optFns ...func(*ecs.Options)) (*ecs.DescribeClustersOutput, error)
	ListTaskDefinitionFamilies(ctx context.Context, params *ecs.ListTaskDefinitionFamiliesInput, optFns ...func(*ecs.Options)) (*ecs.ListTaskDefinitionFamiliesOutput, error)
	DescribeTaskDefinition(ctx context.Context, params *ecs.DescribeTaskDefinitionInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
}

// ECSCluster represents an ECS cluster with security configuration.
type ECSCluster struct {
	Name                     string `json:"name"`
	ARN                      string `json:"arn"`
	ContainerInsightsEnabled bool   `json:"container_insights_enabled"`
	ExecuteCommandEnabled    bool   `json:"execute_command_enabled"`
}

// ToEvidence converts an ECSCluster to Evidence.
func (c *ECSCluster) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck
	ev := evidence.New("aws", "aws:ecs:cluster", c.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// ECSTaskDefinition represents an ECS task definition with security configuration.
type ECSTaskDefinition struct {
	TaskDefinitionARN          string `json:"task_definition_arn"`
	Family                     string `json:"family"`
	NetworkMode                string `json:"network_mode"`
	HasPrivilegedContainer     bool   `json:"has_privileged_container"`
	RunsAsRoot                 bool   `json:"runs_as_root"`
	LoggingConfigured          bool   `json:"logging_configured"`
	HasEFSVolumes              bool   `json:"has_efs_volumes"`
	EFSTransitEncryptionEnabled bool  `json:"efs_transit_encryption_enabled"`
	HasHostPIDMode              bool  `json:"has_host_pid_mode"`
	HasReadOnlyRootFilesystem   bool  `json:"has_readonly_root_filesystem"`
	HasSecretsInEnvVars         bool  `json:"has_secrets_in_env_vars"`
}

// ToEvidence converts an ECSTaskDefinition to Evidence.
func (t *ECSTaskDefinition) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(t) //nolint:errcheck
	ev := evidence.New("aws", "aws:ecs:task-definition", t.TaskDefinitionARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// ECSCollector collects ECS cluster data.
type ECSCollector struct {
	client ECSClient
}

// NewECSCollector creates a new ECS collector.
func NewECSCollector(client ECSClient) *ECSCollector {
	return &ECSCollector{client: client}
}

// CollectClusters retrieves all ECS clusters with their configuration.
func (c *ECSCollector) CollectClusters(ctx context.Context) ([]ECSCluster, error) {
	var clusters []ECSCluster
	var nextToken *string

	for {
		listOutput, err := c.client.ListClusters(ctx, &ecs.ListClustersInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}

		if len(listOutput.ClusterArns) == 0 {
			break
		}

		descOutput, err := c.client.DescribeClusters(ctx, &ecs.DescribeClustersInput{
			Clusters: listOutput.ClusterArns,
			Include:  []ecstypes.ClusterField{ecstypes.ClusterFieldSettings},
		})
		if err != nil {
			return nil, err
		}

		for i := range descOutput.Clusters {
			cl := &descOutput.Clusters[i]
			cluster := ECSCluster{
				Name: awssdk.ToString(cl.ClusterName),
				ARN:  awssdk.ToString(cl.ClusterArn),
			}

			for _, setting := range cl.Settings {
				if string(setting.Name) == "containerInsights" {
					cluster.ContainerInsightsEnabled = awssdk.ToString(setting.Value) == statusEnabledLower
				}
			}

			// Check for executeCommandConfiguration in cluster configuration
			if cl.Configuration != nil && cl.Configuration.ExecuteCommandConfiguration != nil {
				cluster.ExecuteCommandEnabled = true
			}

			clusters = append(clusters, cluster)
		}

		if listOutput.NextToken == nil {
			break
		}
		nextToken = listOutput.NextToken
	}

	return clusters, nil
}

// CollectTaskDefinitions retrieves active ECS task definitions with security details.
//nolint:gocyclo // AWS API response mapping requires sequential field extraction
func (c *ECSCollector) CollectTaskDefinitions(ctx context.Context) ([]ECSTaskDefinition, error) {
	var taskDefs []ECSTaskDefinition
	var nextToken *string

	for {
		listOutput, err := c.client.ListTaskDefinitionFamilies(ctx, &ecs.ListTaskDefinitionFamiliesInput{
			Status:    ecstypes.TaskDefinitionFamilyStatusActive,
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}

		for _, family := range listOutput.Families {
			descOutput, err := c.client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{
				TaskDefinition: awssdk.String(family),
			})
			if err != nil {
				continue // Fail-safe per task definition
			}

			td := descOutput.TaskDefinition
			if td == nil {
				continue
			}

			taskDef := ECSTaskDefinition{
				TaskDefinitionARN: awssdk.ToString(td.TaskDefinitionArn),
				Family:            awssdk.ToString(td.Family),
				NetworkMode:       string(td.NetworkMode),
				LoggingConfigured: true, // Assume true, check below
				HasHostPIDMode:    td.PidMode == ecstypes.PidModeHost,
			}

			allHaveLogging := true
			allReadOnly := true
			for k := range td.ContainerDefinitions {
				container := &td.ContainerDefinitions[k]
				if container.Privileged != nil && *container.Privileged {
					taskDef.HasPrivilegedContainer = true
				}
				if container.User == nil || awssdk.ToString(container.User) == "" || awssdk.ToString(container.User) == "root" || awssdk.ToString(container.User) == "0" {
					taskDef.RunsAsRoot = true
				}
				if container.LogConfiguration == nil {
					allHaveLogging = false
				}
				if container.ReadonlyRootFilesystem == nil || !*container.ReadonlyRootFilesystem {
					allReadOnly = false
				}
				for _, env := range container.Environment {
					name := strings.ToUpper(awssdk.ToString(env.Name))
					if strings.Contains(name, "SECRET") || strings.Contains(name, "PASSWORD") || strings.Contains(name, "KEY") || strings.Contains(name, "TOKEN") {
						taskDef.HasSecretsInEnvVars = true
					}
				}
			}
			taskDef.LoggingConfigured = allHaveLogging && len(td.ContainerDefinitions) > 0
			taskDef.HasReadOnlyRootFilesystem = allReadOnly && len(td.ContainerDefinitions) > 0

			// Check EFS volumes
			for _, vol := range td.Volumes {
				if vol.EfsVolumeConfiguration != nil {
					taskDef.HasEFSVolumes = true
					if vol.EfsVolumeConfiguration.TransitEncryption == ecstypes.EFSTransitEncryptionEnabled {
						taskDef.EFSTransitEncryptionEnabled = true
					}
				}
			}

			taskDefs = append(taskDefs, taskDef)
		}

		if listOutput.NextToken == nil {
			break
		}
		nextToken = listOutput.NextToken
	}

	return taskDefs, nil
}

// CollectEvidence collects ECS clusters and task definitions as evidence.
func (c *ECSCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	var evidenceList []evidence.Evidence

	clusters, err := c.CollectClusters(ctx)
	if err != nil {
		return nil, err
	}
	for i := range clusters {
		evidenceList = append(evidenceList, clusters[i].ToEvidence(accountID))
	}

	// Task definitions (fail-safe)
	taskDefs, err := c.CollectTaskDefinitions(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range taskDefs {
			evidenceList = append(evidenceList, taskDefs[i].ToEvidence(accountID))
		}
	}

	return evidenceList, nil
}
