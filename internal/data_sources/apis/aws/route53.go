package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// Route53Client defines the interface for Route53 operations.
type Route53Client interface {
	ListHostedZones(ctx context.Context, params *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListQueryLoggingConfigs(ctx context.Context, params *route53.ListQueryLoggingConfigsInput, optFns ...func(*route53.Options)) (*route53.ListQueryLoggingConfigsOutput, error)
	GetDNSSEC(ctx context.Context, params *route53.GetDNSSECInput, optFns ...func(*route53.Options)) (*route53.GetDNSSECOutput, error)
}

// Route53HostedZone represents a Route53 hosted zone.
type Route53HostedZone struct {
	ZoneName      string `json:"zone_name"`
	ZoneID        string `json:"zone_id"`
	ARN           string `json:"arn"`
	IsPrivate     bool   `json:"is_private"`
	QueryLogging  bool   `json:"query_logging"`
	DNSSECSigning bool   `json:"dnssec_signing"`
}

// ToEvidence converts a Route53HostedZone to Evidence.
func (z *Route53HostedZone) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(z) //nolint:errcheck
	ev := evidence.New("aws", "aws:route53:hosted-zone", z.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// Route53Collector collects Route53 hosted zone data.
type Route53Collector struct {
	client Route53Client
}

// NewRoute53Collector creates a new Route53 collector.
func NewRoute53Collector(client Route53Client) *Route53Collector {
	return &Route53Collector{client: client}
}

// stripHostedZonePrefix removes the "/hostedzone/" prefix from Route53 zone IDs.
func stripHostedZonePrefix(id string) string {
	return strings.TrimPrefix(id, "/hostedzone/")
}

// CollectHostedZones retrieves all Route53 hosted zones with query logging status.
func (c *Route53Collector) CollectHostedZones(ctx context.Context) ([]Route53HostedZone, error) {
	var zones []Route53HostedZone
	var marker *string

	for {
		output, err := c.client.ListHostedZones(ctx, &route53.ListHostedZonesInput{
			Marker: marker,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list Route53 hosted zones: %w", err)
		}

		for _, hz := range output.HostedZones {
			rawID := awssdk.ToString(hz.Id)
			zoneID := stripHostedZonePrefix(rawID)
			zoneName := awssdk.ToString(hz.Name)

			isPrivate := false
			if hz.Config != nil {
				isPrivate = hz.Config.PrivateZone
			}

			arn := fmt.Sprintf("arn:aws:route53:::hostedzone/%s", zoneID)

			zone := Route53HostedZone{
				ZoneName:  zoneName,
				ZoneID:    zoneID,
				ARN:       arn,
				IsPrivate: isPrivate,
			}

			// Check query logging for this zone
			zone.QueryLogging = c.hasQueryLogging(ctx, zoneID)

			// Check DNSSEC signing for public zones
			if !isPrivate {
				zone.DNSSECSigning = c.hasDNSSEC(ctx, zoneID)
			}

			zones = append(zones, zone)
		}

		if !output.IsTruncated {
			break
		}
		marker = output.NextMarker
	}

	return zones, nil
}

// hasQueryLogging checks whether query logging is enabled for a hosted zone.
func (c *Route53Collector) hasQueryLogging(ctx context.Context, zoneID string) bool {
	var nextToken *string

	for {
		output, err := c.client.ListQueryLoggingConfigs(ctx, &route53.ListQueryLoggingConfigsInput{
			HostedZoneId: awssdk.String(zoneID),
			NextToken:    nextToken,
		})
		if err != nil {
			return false // Fail-safe
		}

		if len(output.QueryLoggingConfigs) > 0 {
			return true
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return false
}

// hasDNSSEC checks if DNSSEC signing is enabled for a hosted zone.
func (c *Route53Collector) hasDNSSEC(ctx context.Context, zoneID string) bool {
	output, err := c.client.GetDNSSEC(ctx, &route53.GetDNSSECInput{
		HostedZoneId: awssdk.String(zoneID),
	})
	if err != nil {
		return false // Fail-safe
	}

	if output.Status != nil {
		status := awssdk.ToString(output.Status.ServeSignature)
		return status == "SIGNING"
	}
	return false
}

// CollectEvidence collects Route53 hosted zones as evidence.
func (c *Route53Collector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	zones, err := c.CollectHostedZones(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(zones))
	for i := range zones {
		evidenceList = append(evidenceList, zones[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
