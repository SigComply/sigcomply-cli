package aws

import (
	"context"
	"encoding/json"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// CloudFrontClient defines the interface for CloudFront operations.
type CloudFrontClient interface {
	ListDistributions(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
	GetDistribution(ctx context.Context, params *cloudfront.GetDistributionInput, optFns ...func(*cloudfront.Options)) (*cloudfront.GetDistributionOutput, error)
}

// CloudFrontDistribution represents a CloudFront distribution.
type CloudFrontDistribution struct {
	ARN                     string `json:"arn"`
	DomainName              string `json:"domain_name"`
	ViewerProtocolPolicy    string `json:"viewer_protocol_policy"`
	HTTPSOnly               bool   `json:"https_only"`
	MinimumProtocolVersion  string `json:"minimum_protocol_version,omitempty"`
	LoggingEnabled          bool   `json:"logging_enabled"`
	WAFEnabled              bool   `json:"waf_enabled"`
	OriginProtocolPolicy    string `json:"origin_protocol_policy,omitempty"`
	DefaultRootObject      string `json:"default_root_object,omitempty"`
	GeoRestrictionEnabled  bool   `json:"geo_restriction_enabled"`
	HasOriginFailover      bool   `json:"has_origin_failover"`
	UsesSNI                bool   `json:"uses_sni"`
}

// ToEvidence converts a CloudFrontDistribution to Evidence.
func (d *CloudFrontDistribution) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(d) //nolint:errcheck // marshaling a known struct type will not fail
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
//nolint:gocyclo // AWS API response mapping requires sequential field extraction
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

		for i := range output.DistributionList.Items {
			item := &output.DistributionList.Items[i]
			dist := CloudFrontDistribution{
				ARN:        awssdk.ToString(item.ARN),
				DomainName: awssdk.ToString(item.DomainName),
			}

			if item.DefaultCacheBehavior != nil {
				dist.ViewerProtocolPolicy = string(item.DefaultCacheBehavior.ViewerProtocolPolicy)
				dist.HTTPSOnly = dist.ViewerProtocolPolicy == "https-only" || dist.ViewerProtocolPolicy == "redirect-to-https"
			}

			if item.ViewerCertificate != nil {
				dist.MinimumProtocolVersion = string(item.ViewerCertificate.MinimumProtocolVersion)
				dist.UsesSNI = string(item.ViewerCertificate.SSLSupportMethod) == "sni-only"
			}

			// WAF association
			dist.WAFEnabled = awssdk.ToString(item.WebACLId) != ""

			// Origin failover (origin groups)
			if item.OriginGroups != nil && item.OriginGroups.Quantity != nil && *item.OriginGroups.Quantity > 0 {
				dist.HasOriginFailover = true
			}

			// Origin protocol policy (from first custom origin)
			if item.Origins != nil {
				for _, origin := range item.Origins.Items {
					if origin.CustomOriginConfig != nil {
						dist.OriginProtocolPolicy = string(origin.CustomOriginConfig.OriginProtocolPolicy)
						break
					}
				}
			}

			// Enrich with full distribution details for logging
			c.enrichDistribution(ctx, &dist)

			distributions = append(distributions, dist)
		}

		if output.DistributionList.NextMarker == nil || !awssdk.ToBool(output.DistributionList.IsTruncated) {
			break
		}
		marker = output.DistributionList.NextMarker
	}

	return distributions, nil
}

// enrichDistribution fetches full distribution details to populate fields not available in list output.
func (c *CloudFrontCollector) enrichDistribution(ctx context.Context, dist *CloudFrontDistribution) {
	// Extract distribution ID from ARN (last segment after /)
	parts := strings.Split(dist.ARN, "/")
	if len(parts) < 2 {
		return
	}
	distID := parts[len(parts)-1]

	output, err := c.client.GetDistribution(ctx, &cloudfront.GetDistributionInput{
		Id: awssdk.String(distID),
	})
	if err != nil {
		return // Fail-safe
	}

	if output.Distribution != nil && output.Distribution.DistributionConfig != nil {
		cfg := output.Distribution.DistributionConfig
		if cfg.Logging != nil {
			dist.LoggingEnabled = awssdk.ToBool(cfg.Logging.Enabled)
		}
		if cfg.DefaultRootObject != nil {
			dist.DefaultRootObject = awssdk.ToString(cfg.DefaultRootObject)
		}
		if cfg.Restrictions != nil && cfg.Restrictions.GeoRestriction != nil {
			dist.GeoRestrictionEnabled = string(cfg.Restrictions.GeoRestriction.RestrictionType) != "none"
		}
	}
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
