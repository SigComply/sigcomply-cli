package aws

import (
	"context"
	"encoding/json"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// CloudFrontClient defines the interface for CloudFront operations.
type CloudFrontClient interface {
	ListDistributions(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
}

// CloudFrontDistribution represents a CloudFront distribution.
type CloudFrontDistribution struct {
	ARN                  string `json:"arn"`
	DomainName           string `json:"domain_name"`
	ViewerProtocolPolicy string `json:"viewer_protocol_policy"`
	HTTPSOnly            bool   `json:"https_only"`
}

// ToEvidence converts a CloudFrontDistribution to Evidence.
func (d *CloudFrontDistribution) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(d) //nolint:errcheck
	ev := evidence.New("aws", "aws:cloudfront:distribution", d.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// CloudFrontCollector collects CloudFront distribution data.
type CloudFrontCollector struct {
	client CloudFrontClient
}

// NewCloudFrontCollector creates a new CloudFront collector.
func NewCloudFrontCollector(client CloudFrontClient) *CloudFrontCollector {
	return &CloudFrontCollector{client: client}
}

// CollectDistributions retrieves all CloudFront distributions.
func (c *CloudFrontCollector) CollectDistributions(ctx context.Context) ([]CloudFrontDistribution, error) {
	var distributions []CloudFrontDistribution
	var marker *string

	for {
		output, err := c.client.ListDistributions(ctx, &cloudfront.ListDistributionsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, err
		}

		if output.DistributionList == nil {
			break
		}

		for _, item := range output.DistributionList.Items {
			dist := CloudFrontDistribution{
				ARN:        awssdk.ToString(item.ARN),
				DomainName: awssdk.ToString(item.DomainName),
			}

			if item.DefaultCacheBehavior != nil {
				dist.ViewerProtocolPolicy = string(item.DefaultCacheBehavior.ViewerProtocolPolicy)
				dist.HTTPSOnly = dist.ViewerProtocolPolicy == "https-only" || dist.ViewerProtocolPolicy == "redirect-to-https"
			}

			distributions = append(distributions, dist)
		}

		if output.DistributionList.NextMarker == nil || !awssdk.ToBool(output.DistributionList.IsTruncated) {
			break
		}
		marker = output.DistributionList.NextMarker
	}

	return distributions, nil
}

// CollectEvidence collects CloudFront distributions as evidence.
func (c *CloudFrontCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	distributions, err := c.CollectDistributions(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(distributions))
	for i := range distributions {
		evidenceList = append(evidenceList, distributions[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
