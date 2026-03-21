package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// WAFClient defines the interface for WAF operations.
type WAFClient interface {
	ListWebACLs(ctx context.Context, params *wafv2.ListWebACLsInput, optFns ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error)
	ListResourcesForWebACL(ctx context.Context, params *wafv2.ListResourcesForWebACLInput, optFns ...func(*wafv2.Options)) (*wafv2.ListResourcesForWebACLOutput, error)
	GetWebACL(ctx context.Context, params *wafv2.GetWebACLInput, optFns ...func(*wafv2.Options)) (*wafv2.GetWebACLOutput, error)
	GetLoggingConfiguration(ctx context.Context, params *wafv2.GetLoggingConfigurationInput, optFns ...func(*wafv2.Options)) (*wafv2.GetLoggingConfigurationOutput, error)
}

// WAFStatus represents the WAF configuration status.
type WAFStatus struct {
	WebACLCount        int    `json:"web_acl_count"`
	ResourcesProtected int    `json:"resources_protected"`
	HasALBProtection   bool   `json:"has_alb_protection"`
	LoggingEnabled     bool   `json:"logging_enabled"`
	HasRules           bool   `json:"has_rules"`
	Region             string `json:"region"`
}

// ToEvidence converts a WAFStatus to Evidence.
func (w *WAFStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(w) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:wafv2:%s:%s:waf-status", w.Region, accountID)
	ev := evidence.New("aws", "aws:wafv2:status", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// WAFCollector collects WAF data.
type WAFCollector struct {
	client WAFClient
	region string
}

// NewWAFCollector creates a new WAF collector.
func NewWAFCollector(client WAFClient, region string) *WAFCollector {
	return &WAFCollector{client: client, region: region}
}

// CollectStatus retrieves WAF status.
func (c *WAFCollector) CollectStatus(ctx context.Context) (*WAFStatus, error) {
	status := &WAFStatus{Region: c.region}

	output, err := c.client.ListWebACLs(ctx, &wafv2.ListWebACLsInput{
		Scope: waftypes.ScopeRegional,
	})
	if err != nil {
		return status, nil // Fail-safe
	}

	status.WebACLCount = len(output.WebACLs)

	for _, acl := range output.WebACLs {
		// Check logging configuration
		logOutput, logErr := c.client.GetLoggingConfiguration(ctx, &wafv2.GetLoggingConfigurationInput{
			ResourceArn: acl.ARN,
		})
		if logErr == nil && logOutput.LoggingConfiguration != nil {
			status.LoggingEnabled = true
		}

		// Check rules by getting full web ACL
		aclOutput, aclErr := c.client.GetWebACL(ctx, &wafv2.GetWebACLInput{
			Name:  acl.Name,
			Id:    acl.Id,
			Scope: waftypes.ScopeRegional,
		})
		if aclErr == nil && aclOutput.WebACL != nil && len(aclOutput.WebACL.Rules) > 0 {
			status.HasRules = true
		}

		resOutput, err := c.client.ListResourcesForWebACL(ctx, &wafv2.ListResourcesForWebACLInput{
			WebACLArn: acl.ARN,
		})
		if err != nil {
			continue
		}

		resCount := len(resOutput.ResourceArns)
		status.ResourcesProtected += resCount

		// Check for ALB protection
		for _, arn := range resOutput.ResourceArns {
			if contains(arn, "elasticloadbalancing") {
				status.HasALBProtection = true
			}
		}
	}

	return status, nil
}

func contains(s, substr string) bool {
	return awssdk.ToString(&s) != "" && len(s) > 0 && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// CollectEvidence collects WAF status as evidence.
func (c *WAFCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	status, err := c.CollectStatus(ctx)
	if err != nil {
		return nil, err
	}
	return []evidence.Evidence{status.ToEvidence(accountID)}, nil
}
