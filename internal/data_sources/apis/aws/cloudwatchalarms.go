package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// CloudWatchAlarmsClient defines the interface for CloudWatch Alarms operations.
type CloudWatchAlarmsClient interface {
	DescribeAlarms(ctx context.Context, params *cloudwatch.DescribeAlarmsInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.DescribeAlarmsOutput, error)
}

// CloudWatchAlarmConfig represents the security alarm configuration.
type CloudWatchAlarmConfig struct {
	AlarmCount                  int  `json:"alarm_count"`
	HasUnauthorizedAPICalls     bool `json:"has_unauthorized_api_calls"`
	HasRootUsage                bool `json:"has_root_usage"`
	HasConsoleSignInFailures    bool `json:"has_console_sign_in_failures"`
	AllCriticalAlarmsConfigured bool `json:"all_critical_alarms_configured"`
	Region                      string `json:"region"`
}

// ToEvidence converts a CloudWatchAlarmConfig to Evidence.
func (c *CloudWatchAlarmConfig) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:cloudwatch:%s:%s:alarm-config", c.Region, accountID)
	ev := evidence.New("aws", "aws:cloudwatch:alarm-config", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// CloudWatchAlarmsCollector collects CloudWatch alarm configuration.
type CloudWatchAlarmsCollector struct {
	client CloudWatchAlarmsClient
	region string
}

// NewCloudWatchAlarmsCollector creates a new CloudWatch alarms collector.
func NewCloudWatchAlarmsCollector(client CloudWatchAlarmsClient, region string) *CloudWatchAlarmsCollector {
	return &CloudWatchAlarmsCollector{client: client, region: region}
}

// CollectAlarmConfig retrieves and analyzes CloudWatch alarm configuration.
func (c *CloudWatchAlarmsCollector) CollectAlarmConfig(ctx context.Context) (*CloudWatchAlarmConfig, error) {
	config := &CloudWatchAlarmConfig{Region: c.region}

	var nextToken *string
	for {
		output, err := c.client.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return config, nil // Fail-safe
		}

		for _, alarm := range output.MetricAlarms {
			config.AlarmCount++
			name := strings.ToLower(awssdk.ToString(alarm.AlarmName))
			desc := strings.ToLower(awssdk.ToString(alarm.AlarmDescription))
			combined := name + " " + desc

			if strings.Contains(combined, "unauthorizedapicalls") || strings.Contains(combined, "unauthorized") {
				config.HasUnauthorizedAPICalls = true
			}
			if strings.Contains(combined, "rootaccountusage") || strings.Contains(combined, "root") {
				config.HasRootUsage = true
			}
			if strings.Contains(combined, "consolesigninfailures") || strings.Contains(combined, "signin") || strings.Contains(combined, "sign-in") {
				config.HasConsoleSignInFailures = true
			}
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	config.AllCriticalAlarmsConfigured = config.HasUnauthorizedAPICalls && config.HasRootUsage && config.HasConsoleSignInFailures

	return config, nil
}

// CollectEvidence collects CloudWatch alarm config as evidence.
func (c *CloudWatchAlarmsCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	config, err := c.CollectAlarmConfig(ctx)
	if err != nil {
		return nil, err
	}
	return []evidence.Evidence{config.ToEvidence(accountID)}, nil
}
