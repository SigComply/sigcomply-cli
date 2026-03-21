package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// ConfigServiceClient defines the interface for AWS Config operations.
type ConfigServiceClient interface {
	DescribeConfigurationRecorders(ctx context.Context, params *configservice.DescribeConfigurationRecordersInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecordersOutput, error)
	DescribeConfigurationRecorderStatus(ctx context.Context, params *configservice.DescribeConfigurationRecorderStatusInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationRecorderStatusOutput, error)
	DescribeConfigurationAggregators(ctx context.Context, params *configservice.DescribeConfigurationAggregatorsInput, optFns ...func(*configservice.Options)) (*configservice.DescribeConfigurationAggregatorsOutput, error)
}

// ConfigRecorder represents an AWS Config recorder.
type ConfigRecorder struct {
	Name       string `json:"name"`
	Recording  bool   `json:"recording"`
	AllSupported bool `json:"all_supported"`
	Region     string `json:"region"`
}

// ConfigStatus represents the overall AWS Config status.
type ConfigStatus struct {
	Enabled   bool             `json:"enabled"`
	Recorders []ConfigRecorder `json:"recorders"`
	Region    string           `json:"region"`
}

// ToEvidence converts a ConfigStatus to Evidence.
func (c *ConfigStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(c) //nolint:errcheck // json.Marshal on a known-serializable struct will not error
	resourceID := fmt.Sprintf("arn:aws:config:%s:%s:recorder", c.Region, accountID)
	ev := evidence.New("aws", "aws:config:recorder", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// ConfigAggregatorStatus represents the Config aggregator status.
type ConfigAggregatorStatus struct {
	Configured bool   `json:"configured"`
	Region     string `json:"region"`
}

// ToEvidence converts a ConfigAggregatorStatus to Evidence.
func (a *ConfigAggregatorStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(a) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:config:%s:%s:aggregator", a.Region, accountID)
	ev := evidence.New("aws", "aws:config:aggregator", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// ConfigCollector collects AWS Config status.
type ConfigCollector struct {
	client ConfigServiceClient
	region string
}

// NewConfigCollector creates a new AWS Config collector.
func NewConfigCollector(client ConfigServiceClient, region string) *ConfigCollector {
	return &ConfigCollector{client: client, region: region}
}

// CollectStatus retrieves AWS Config recorder status.
func (c *ConfigCollector) CollectStatus(ctx context.Context) (*ConfigStatus, error) {
	status := &ConfigStatus{Region: c.region}

	// Get recorders
	recOutput, err := c.client.DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	if err != nil {
		return status, nil //nolint:nilerr // no access or not configured is a valid state
	}

	if len(recOutput.ConfigurationRecorders) == 0 {
		return status, nil
	}

	// Get recorder status
	statusOutput, err := c.client.DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{})
	if err != nil {
		return status, nil //nolint:nilerr // fail-safe: treat status query failure as unconfigured
	}

	recordingStatus := make(map[string]bool)
	for _, s := range statusOutput.ConfigurationRecordersStatus {
		recordingStatus[awssdk.ToString(s.Name)] = s.Recording
	}

	for _, rec := range recOutput.ConfigurationRecorders {
		name := awssdk.ToString(rec.Name)
		recorder := ConfigRecorder{
			Name:      name,
			Recording: recordingStatus[name],
			Region:    c.region,
		}

		if rec.RecordingGroup != nil {
			recorder.AllSupported = rec.RecordingGroup.AllSupported
		}

		status.Recorders = append(status.Recorders, recorder)

		if recorder.Recording {
			status.Enabled = true
		}
	}

	return status, nil
}

// CollectAggregatorStatus retrieves AWS Config aggregator status.
func (c *ConfigCollector) CollectAggregatorStatus(ctx context.Context) (*ConfigAggregatorStatus, error) {
	status := &ConfigAggregatorStatus{Region: c.region}

	output, err := c.client.DescribeConfigurationAggregators(ctx, &configservice.DescribeConfigurationAggregatorsInput{})
	if err != nil {
		return status, nil //nolint:nilerr // fail-safe: return partial results on error
	}

	status.Configured = len(output.ConfigurationAggregators) > 0
	return status, nil
}

// CollectEvidence collects AWS Config status as evidence.
func (c *ConfigCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	var evidenceList []evidence.Evidence

	status, err := c.CollectStatus(ctx)
	if err != nil {
		return nil, err
	}
	evidenceList = append(evidenceList, status.ToEvidence(accountID))

	// Config aggregator
	aggStatus, err := c.CollectAggregatorStatus(ctx)
	if err == nil {
		evidenceList = append(evidenceList, aggStatus.ToEvidence(accountID))
	}

	return evidenceList, nil
}
