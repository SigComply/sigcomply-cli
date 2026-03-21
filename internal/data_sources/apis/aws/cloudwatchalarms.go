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
	HasConsoleSignInNoMFA       bool `json:"has_console_signin_no_mfa"`
	HasIAMPolicyChanges         bool `json:"has_iam_policy_changes"`
	HasCloudTrailConfigChanges  bool `json:"has_cloudtrail_config_changes"`
	HasCMKDisableDeletion       bool `json:"has_cmk_disable_deletion"`
	HasS3BucketPolicyChanges    bool `json:"has_s3_bucket_policy_changes"`
	HasConfigChanges            bool `json:"has_config_changes"`
	HasSecurityGroupChanges     bool `json:"has_security_group_changes"`
	HasNACLChanges              bool `json:"has_nacl_changes"`
	HasNetworkGatewayChanges    bool `json:"has_network_gateway_changes"`
	HasRouteTableChanges        bool `json:"has_route_table_changes"`
	HasVPCChanges               bool   `json:"has_vpc_changes"`
	HasOrganizationsChanges     bool   `json:"has_organizations_changes"`
	AllCriticalAlarmsConfigured bool   `json:"all_critical_alarms_configured"`
	Region                      string `json:"region"`
}

// CISMetricFilter represents the status of a CIS CloudWatch metric filter check.
type CISMetricFilter struct {
	FilterName string `json:"filter_name"`
	Configured bool   `json:"configured"`
	Region     string `json:"region"`
}

// ToEvidence converts a CISMetricFilter to Evidence.
func (f *CISMetricFilter) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(f) //nolint:errcheck // marshaling a known struct type will not fail
	resourceID := fmt.Sprintf("arn:aws:cloudwatch:%s:%s:cis-metric-filter/%s", f.Region, accountID, f.FilterName)
	ev := evidence.New("aws", "aws:cloudwatch:cis-metric-filter", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// ToEvidence converts a CloudWatchAlarmConfig to Evidence.
func (c *CloudWatchAlarmConfig) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck // marshaling a known struct type will not fail
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
//nolint:gocyclo // AWS API response mapping requires sequential field extraction
func (c *CloudWatchAlarmsCollector) CollectAlarmConfig(ctx context.Context) (*CloudWatchAlarmConfig, error) {
	config := &CloudWatchAlarmConfig{Region: c.region}

	var nextToken *string
	for {
		output, err := c.client.DescribeAlarms(ctx, &cloudwatch.DescribeAlarmsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return config, nil //nolint:nilerr // fail-safe: return partial results on error
		}

		for i := range output.MetricAlarms {
			alarm := &output.MetricAlarms[i]
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
			if strings.Contains(combined, "consolenosignin") || strings.Contains(combined, "no-mfa") || strings.Contains(combined, "nomfa") {
				config.HasConsoleSignInNoMFA = true
			}
			if strings.Contains(combined, "iampolicy") || strings.Contains(combined, "iam-policy") || strings.Contains(combined, "policychange") {
				config.HasIAMPolicyChanges = true
			}
			if strings.Contains(combined, "cloudtrailchange") || strings.Contains(combined, "cloudtrailconfig") || strings.Contains(combined, "cloudtrail-config") {
				config.HasCloudTrailConfigChanges = true
			}
			if strings.Contains(combined, "cmkdisable") || strings.Contains(combined, "kmsdelete") || strings.Contains(combined, "cmk") {
				config.HasCMKDisableDeletion = true
			}
			if strings.Contains(combined, "s3bucketpolicy") || strings.Contains(combined, "s3-policy") {
				config.HasS3BucketPolicyChanges = true
			}
			if strings.Contains(combined, "configchange") || strings.Contains(combined, "awsconfig") || strings.Contains(combined, "config-change") {
				config.HasConfigChanges = true
			}
			if strings.Contains(combined, "securitygroup") || strings.Contains(combined, "security-group") {
				config.HasSecurityGroupChanges = true
			}
			if strings.Contains(combined, "naclchange") || strings.Contains(combined, "networkacl") || strings.Contains(combined, "nacl") {
				config.HasNACLChanges = true
			}
			if strings.Contains(combined, "networkgateway") || strings.Contains(combined, "igwchange") || strings.Contains(combined, "gateway") {
				config.HasNetworkGatewayChanges = true
			}
			if strings.Contains(combined, "routetable") || strings.Contains(combined, "route-table") {
				config.HasRouteTableChanges = true
			}
			if strings.Contains(combined, "vpcchange") || (strings.Contains(combined, "vpc") && strings.Contains(combined, "change")) {
				config.HasVPCChanges = true
			}
			if strings.Contains(combined, "organizations") || strings.Contains(combined, "orgchange") {
				config.HasOrganizationsChanges = true
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

// CollectCISMetricFilters checks alarm data to infer CIS 4.x metric filter status.
func (c *CloudWatchAlarmsCollector) CollectCISMetricFilters(ctx context.Context) ([]CISMetricFilter, error) {
	config, err := c.CollectAlarmConfig(ctx)
	if err != nil {
		config = &CloudWatchAlarmConfig{Region: c.region}
	}

	filters := []CISMetricFilter{
		{FilterName: "unauthorized_api_calls", Configured: config.HasUnauthorizedAPICalls, Region: c.region},
		{FilterName: "console_signin_no_mfa", Configured: config.HasConsoleSignInNoMFA, Region: c.region},
		{FilterName: "root_account_usage", Configured: config.HasRootUsage, Region: c.region},
		{FilterName: "iam_policy_changes", Configured: config.HasIAMPolicyChanges, Region: c.region},
		{FilterName: "cloudtrail_config_changes", Configured: config.HasCloudTrailConfigChanges, Region: c.region},
		{FilterName: "console_auth_failures", Configured: config.HasConsoleSignInFailures, Region: c.region},
		{FilterName: "cmk_disable_deletion", Configured: config.HasCMKDisableDeletion, Region: c.region},
		{FilterName: "s3_bucket_policy_changes", Configured: config.HasS3BucketPolicyChanges, Region: c.region},
		{FilterName: "config_changes", Configured: config.HasConfigChanges, Region: c.region},
		{FilterName: "security_group_changes", Configured: config.HasSecurityGroupChanges, Region: c.region},
		{FilterName: "nacl_changes", Configured: config.HasNACLChanges, Region: c.region},
		{FilterName: "network_gateway_changes", Configured: config.HasNetworkGatewayChanges, Region: c.region},
		{FilterName: "route_table_changes", Configured: config.HasRouteTableChanges, Region: c.region},
		{FilterName: "vpc_changes", Configured: config.HasVPCChanges, Region: c.region},
		{FilterName: "organizations_changes", Configured: config.HasOrganizationsChanges, Region: c.region},
	}

	return filters, nil
}

// CollectEvidence collects CloudWatch alarm config as evidence.
func (c *CloudWatchAlarmsCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	var evidenceList []evidence.Evidence

	config, err := c.CollectAlarmConfig(ctx)
	if err != nil {
		return nil, err
	}
	evidenceList = append(evidenceList, config.ToEvidence(accountID))

	// CIS metric filter evidence
	filters, err := c.CollectCISMetricFilters(ctx)
	if err == nil {
		for i := range filters {
			evidenceList = append(evidenceList, filters[i].ToEvidence(accountID))
		}
	}

	return evidenceList, nil
}
