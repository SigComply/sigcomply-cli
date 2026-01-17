package aws

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/tracevault/tracevault-cli/internal/core/evidence"
)

// CloudTrailClient defines the interface for CloudTrail operations we use.
type CloudTrailClient interface {
	DescribeTrails(ctx context.Context, params *cloudtrail.DescribeTrailsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.DescribeTrailsOutput, error)
	GetTrailStatus(ctx context.Context, params *cloudtrail.GetTrailStatusInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.GetTrailStatusOutput, error)
}

// CloudTrailTrail represents a CloudTrail trail with its configuration.
type CloudTrailTrail struct {
	Name                string `json:"name"`
	ARN                 string `json:"arn"`
	HomeRegion          string `json:"home_region,omitempty"`
	IsMultiRegion       bool   `json:"is_multi_region"`
	IsOrganizationTrail bool   `json:"is_organization_trail"`
	IsLogging           bool   `json:"is_logging"`
	LogFileValidation   bool   `json:"log_file_validation"`
	IncludeGlobalEvents bool   `json:"include_global_events"`
	S3BucketName        string `json:"s3_bucket_name"`
	KMSKeyID            string `json:"kms_key_id,omitempty"`
}

// ToEvidence converts a CloudTrailTrail to an Evidence struct.
func (t *CloudTrailTrail) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(t) //nolint:errcheck // Marshal of known struct won't fail
	ev := evidence.New("aws", "aws:cloudtrail:trail", t.ARN, data)
	ev.Metadata = evidence.Metadata{
		AccountID: accountID,
	}
	return ev
}

// CloudTrailCollector collects CloudTrail trail data.
type CloudTrailCollector struct {
	client CloudTrailClient
}

// NewCloudTrailCollector creates a new CloudTrail collector.
func NewCloudTrailCollector(client CloudTrailClient) *CloudTrailCollector {
	return &CloudTrailCollector{client: client}
}

// CollectTrails retrieves all CloudTrail trails with their configuration.
func (c *CloudTrailCollector) CollectTrails(ctx context.Context) ([]CloudTrailTrail, error) {
	output, err := c.client.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe CloudTrail trails: %w", err)
	}

	trails := make([]CloudTrailTrail, 0, len(output.TrailList))
	for i := range output.TrailList {
		t := &output.TrailList[i]
		trail := CloudTrailTrail{
			Name:                aws.ToString(t.Name),
			ARN:                 aws.ToString(t.TrailARN),
			HomeRegion:          aws.ToString(t.HomeRegion),
			IsMultiRegion:       aws.ToBool(t.IsMultiRegionTrail),
			IsOrganizationTrail: aws.ToBool(t.IsOrganizationTrail),
			LogFileValidation:   aws.ToBool(t.LogFileValidationEnabled),
			IncludeGlobalEvents: aws.ToBool(t.IncludeGlobalServiceEvents),
			S3BucketName:        aws.ToString(t.S3BucketName),
			KMSKeyID:            aws.ToString(t.KmsKeyId),
		}

		// Get logging status
		c.enrichLoggingStatus(ctx, &trail)

		trails = append(trails, trail)
	}

	return trails, nil
}

// enrichLoggingStatus adds logging status to a trail.
func (c *CloudTrailCollector) enrichLoggingStatus(ctx context.Context, trail *CloudTrailTrail) {
	output, err := c.client.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
		Name: aws.String(trail.Name),
	})
	if err != nil {
		// Access denied or other error - fail-safe approach
		trail.IsLogging = false
		return
	}

	trail.IsLogging = aws.ToBool(output.IsLogging)
}

// CollectEvidence collects CloudTrail trails as evidence.
func (c *CloudTrailCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	trails, err := c.CollectTrails(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(trails))
	for i := range trails {
		evidenceList = append(evidenceList, trails[i].ToEvidence(accountID))
	}

	return evidenceList, nil
}
