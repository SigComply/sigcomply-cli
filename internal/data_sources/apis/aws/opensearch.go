package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// OpenSearchClient defines the interface for OpenSearch operations.
type OpenSearchClient interface {
	ListDomainNames(ctx context.Context, params *opensearch.ListDomainNamesInput, optFns ...func(*opensearch.Options)) (*opensearch.ListDomainNamesOutput, error)
	DescribeDomains(ctx context.Context, params *opensearch.DescribeDomainsInput, optFns ...func(*opensearch.Options)) (*opensearch.DescribeDomainsOutput, error)
}

// OpenSearchDomain represents an OpenSearch domain.
type OpenSearchDomain struct {
	DomainName               string `json:"domain_name"`
	DomainID                 string `json:"domain_id,omitempty"`
	ARN                      string `json:"arn"`
	EncryptedAtRest          bool   `json:"encrypted_at_rest"`
	NodeToNodeEncryption     bool   `json:"node_to_node_encryption"`
	VPCConfigured            bool   `json:"vpc_configured"`
	EnforceHTTPS             bool   `json:"enforce_https"`
	AuditLoggingEnabled      bool   `json:"audit_logging_enabled"`
	FineGrainedAccessEnabled bool   `json:"fine_grained_access_enabled"`
	SlowLogsEnabled          bool   `json:"slow_logs_enabled"`
	ZoneAwarenessEnabled     bool   `json:"zone_awareness_enabled"`
}

// ToEvidence converts an OpenSearchDomain to Evidence.
func (d *OpenSearchDomain) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(d) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:opensearch:domain", d.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// OpenSearchCollector collects OpenSearch domain data.
type OpenSearchCollector struct {
	client OpenSearchClient
}

// NewOpenSearchCollector creates a new OpenSearch collector.
func NewOpenSearchCollector(client OpenSearchClient) *OpenSearchCollector {
	return &OpenSearchCollector{client: client}
}

// CollectDomains retrieves all OpenSearch domains.
//
//nolint:gocyclo // AWS API response mapping requires sequential field extraction
func (c *OpenSearchCollector) CollectDomains(ctx context.Context) ([]OpenSearchDomain, error) {
	// List domain names first
	listOutput, err := c.client.ListDomainNames(ctx, &opensearch.ListDomainNamesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list OpenSearch domains: %w", err)
	}

	if len(listOutput.DomainNames) == 0 {
		return nil, nil
	}

	// Collect domain names for describe call
	var domainNames []string
	for _, d := range listOutput.DomainNames {
		domainNames = append(domainNames, awssdk.ToString(d.DomainName))
	}

	// Describe domains in batch
	descOutput, err := c.client.DescribeDomains(ctx, &opensearch.DescribeDomainsInput{
		DomainNames: domainNames,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe OpenSearch domains: %w", err)
	}

	var domains []OpenSearchDomain
	for i := range descOutput.DomainStatusList {
		status := &descOutput.DomainStatusList[i]
		domain := OpenSearchDomain{
			DomainName: awssdk.ToString(status.DomainName),
			DomainID:   awssdk.ToString(status.DomainId),
			ARN:        awssdk.ToString(status.ARN),
		}

		if status.EncryptionAtRestOptions != nil {
			domain.EncryptedAtRest = awssdk.ToBool(status.EncryptionAtRestOptions.Enabled)
		}

		if status.NodeToNodeEncryptionOptions != nil {
			domain.NodeToNodeEncryption = awssdk.ToBool(status.NodeToNodeEncryptionOptions.Enabled)
		}

		if status.VPCOptions != nil && status.VPCOptions.VPCId != nil {
			domain.VPCConfigured = true
		}

		if status.DomainEndpointOptions != nil {
			domain.EnforceHTTPS = awssdk.ToBool(status.DomainEndpointOptions.EnforceHTTPS)
		}

		// Audit logging
		if status.LogPublishingOptions != nil {
			if auditLog, ok := status.LogPublishingOptions["AUDIT_LOGS"]; ok {
				domain.AuditLoggingEnabled = awssdk.ToBool(auditLog.Enabled)
			}
			if slowLog, ok := status.LogPublishingOptions["SEARCH_SLOW_LOGS"]; ok {
				domain.SlowLogsEnabled = awssdk.ToBool(slowLog.Enabled)
			} else if indexLog, ok := status.LogPublishingOptions["INDEX_SLOW_LOGS"]; ok {
				domain.SlowLogsEnabled = awssdk.ToBool(indexLog.Enabled)
			}
		}

		// Fine-grained access control
		if status.AdvancedSecurityOptions != nil {
			domain.FineGrainedAccessEnabled = awssdk.ToBool(status.AdvancedSecurityOptions.Enabled)
		}

		// Zone awareness
		if status.ClusterConfig != nil {
			domain.ZoneAwarenessEnabled = awssdk.ToBool(status.ClusterConfig.ZoneAwarenessEnabled)
		}

		domains = append(domains, domain)
	}

	return domains, nil
}

// CollectEvidence collects OpenSearch domains as evidence.
func (c *OpenSearchCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	domains, err := c.CollectDomains(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(domains))
	for i := range domains {
		evidenceList = append(evidenceList, domains[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
