package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// AutoScalingClient defines the interface for Auto Scaling operations.
type AutoScalingClient interface {
	DescribeAutoScalingGroups(ctx context.Context, params *autoscaling.DescribeAutoScalingGroupsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeAutoScalingGroupsOutput, error)
	DescribeLaunchConfigurations(ctx context.Context, params *autoscaling.DescribeLaunchConfigurationsInput, optFns ...func(*autoscaling.Options)) (*autoscaling.DescribeLaunchConfigurationsOutput, error)
}

// AutoScalingGroup represents an EC2 Auto Scaling group.
type AutoScalingGroup struct {
	GroupName          string `json:"group_name"`
	ARN                string `json:"arn"`
	ELBHealthCheck     bool   `json:"elb_health_check"`
	MultiAZ            bool   `json:"multi_az"`
	IMDSv2Required     bool   `json:"imdsv2_required"`
	AssociatePublicIP  bool   `json:"associate_public_ip"`
	UsesLaunchTemplate bool   `json:"uses_launch_template"`
}

// ToEvidence converts an AutoScalingGroup to Evidence.
func (g *AutoScalingGroup) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(g) //nolint:errcheck // marshalling a known struct type will not fail
	ev := evidence.New("aws", "aws:autoscaling:group", g.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// AutoScalingCollector collects Auto Scaling group data.
type AutoScalingCollector struct {
	client AutoScalingClient
}

// NewAutoScalingCollector creates a new Auto Scaling collector.
func NewAutoScalingCollector(client AutoScalingClient) *AutoScalingCollector {
	return &AutoScalingCollector{client: client}
}

// CollectGroups retrieves all Auto Scaling groups.
func (c *AutoScalingCollector) CollectGroups(ctx context.Context) ([]AutoScalingGroup, error) {
	// Build a map of launch configuration name -> AssociatePublicIpAddress for enrichment.
	lcPublicIPMap, err := c.collectLaunchConfigPublicIP(ctx)
	if err != nil {
		// Fail-safe: proceed without launch configuration data.
		lcPublicIPMap = map[string]bool{}
	}

	var groups []AutoScalingGroup
	var nextToken *string

	for {
		output, err := c.client.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe Auto Scaling groups: %w", err)
		}

		for i := range output.AutoScalingGroups {
			asg := &output.AutoScalingGroups[i]
			usesLaunchTemplate := asg.LaunchTemplate != nil || asg.MixedInstancesPolicy != nil

			associatePublicIP := false
			if lcName := awssdk.ToString(asg.LaunchConfigurationName); lcName != "" {
				if pub, ok := lcPublicIPMap[lcName]; ok {
					associatePublicIP = pub
				}
			}

			group := AutoScalingGroup{
				GroupName:          awssdk.ToString(asg.AutoScalingGroupName),
				ARN:                awssdk.ToString(asg.AutoScalingGroupARN),
				ELBHealthCheck:     awssdk.ToString(asg.HealthCheckType) == "ELB",
				MultiAZ:            len(asg.AvailabilityZones) > 1,
				IMDSv2Required:     false, // Would require EC2 DescribeLaunchTemplateVersions; defaulting to false.
				AssociatePublicIP:  associatePublicIP,
				UsesLaunchTemplate: usesLaunchTemplate,
			}

			groups = append(groups, group)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return groups, nil
}

// collectLaunchConfigPublicIP builds a map of launch configuration name to AssociatePublicIpAddress.
func (c *AutoScalingCollector) collectLaunchConfigPublicIP(ctx context.Context) (map[string]bool, error) {
	result := map[string]bool{}
	var nextToken *string

	for {
		output, err := c.client.DescribeLaunchConfigurations(ctx, &autoscaling.DescribeLaunchConfigurationsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to describe launch configurations: %w", err)
		}

		for i := range output.LaunchConfigurations {
			lc := &output.LaunchConfigurations[i]
			name := awssdk.ToString(lc.LaunchConfigurationName)
			if name == "" {
				continue
			}
			result[name] = awssdk.ToBool(lc.AssociatePublicIpAddress)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return result, nil
}

// CollectEvidence collects Auto Scaling groups as evidence.
func (c *AutoScalingCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	groups, err := c.CollectGroups(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(groups))
	for i := range groups {
		evidenceList = append(evidenceList, groups[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
