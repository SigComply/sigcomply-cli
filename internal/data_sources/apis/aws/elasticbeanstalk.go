package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// ElasticBeanstalkClient defines the interface for Elastic Beanstalk operations.
type ElasticBeanstalkClient interface {
	DescribeEnvironments(ctx context.Context, params *elasticbeanstalk.DescribeEnvironmentsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeEnvironmentsOutput, error)
	DescribeConfigurationSettings(ctx context.Context, params *elasticbeanstalk.DescribeConfigurationSettingsInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.DescribeConfigurationSettingsOutput, error)
}

// BeanstalkEnvironment represents an Elastic Beanstalk environment.
type BeanstalkEnvironment struct {
	EnvironmentName         string `json:"environment_name"`
	ARN                     string `json:"arn"`
	EnhancedHealthReporting bool   `json:"enhanced_health_reporting"`
	ManagedUpdatesEnabled   bool   `json:"managed_updates_enabled"`
	CloudWatchLogsEnabled   bool   `json:"cloudwatch_logs_enabled"`
}

// ToEvidence converts a BeanstalkEnvironment to Evidence.
func (e *BeanstalkEnvironment) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(e) //nolint:errcheck
	ev := evidence.New("aws", "aws:elasticbeanstalk:environment", e.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// BeanstalkCollector collects Elastic Beanstalk environment data.
type BeanstalkCollector struct {
	client ElasticBeanstalkClient
}

// NewBeanstalkCollector creates a new Elastic Beanstalk collector.
func NewBeanstalkCollector(client ElasticBeanstalkClient) *BeanstalkCollector {
	return &BeanstalkCollector{client: client}
}

// CollectEnvironments retrieves all Elastic Beanstalk environments with enriched config data.
func (c *BeanstalkCollector) CollectEnvironments(ctx context.Context) ([]BeanstalkEnvironment, error) {
	var environments []BeanstalkEnvironment
	var nextToken *string

	for {
		output, err := c.client.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe Elastic Beanstalk environments: %w", err)
		}

		for _, env := range output.Environments {
			benv := BeanstalkEnvironment{
				EnvironmentName: awssdk.ToString(env.EnvironmentName),
				ARN:             awssdk.ToString(env.EnvironmentArn),
			}

			// Enrich with configuration settings
			c.enrichConfigSettings(ctx, &benv, awssdk.ToString(env.ApplicationName), awssdk.ToString(env.EnvironmentName))

			environments = append(environments, benv)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return environments, nil
}

// enrichConfigSettings fetches configuration options and sets health/update/logging flags.
func (c *BeanstalkCollector) enrichConfigSettings(ctx context.Context, env *BeanstalkEnvironment, appName, envName string) {
	if appName == "" || envName == "" {
		return
	}

	output, err := c.client.DescribeConfigurationSettings(ctx, &elasticbeanstalk.DescribeConfigurationSettingsInput{
		ApplicationName: awssdk.String(appName),
		EnvironmentName: awssdk.String(envName),
	})
	if err != nil {
		return // Fail-safe: leave defaults (false)
	}

	for _, cfgSet := range output.ConfigurationSettings {
		for _, opt := range cfgSet.OptionSettings {
			ns := awssdk.ToString(opt.Namespace)
			optName := awssdk.ToString(opt.OptionName)
			value := strings.TrimSpace(awssdk.ToString(opt.Value))

			switch {
			case ns == "aws:elasticbeanstalk:healthreporting:system" && optName == "SystemType":
				env.EnhancedHealthReporting = strings.EqualFold(value, "enhanced")
			case ns == "aws:elasticbeanstalk:managedactions" && optName == "ManagedActionsEnabled":
				env.ManagedUpdatesEnabled = strings.EqualFold(value, "true")
			case ns == "aws:elasticbeanstalk:cloudwatch:logs" && optName == "StreamLogs":
				env.CloudWatchLogsEnabled = strings.EqualFold(value, "true")
			}
		}
	}
}

// CollectEvidence collects Elastic Beanstalk environments as evidence.
func (c *BeanstalkCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	envs, err := c.CollectEnvironments(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(envs))
	for i := range envs {
		evidenceList = append(evidenceList, envs[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
