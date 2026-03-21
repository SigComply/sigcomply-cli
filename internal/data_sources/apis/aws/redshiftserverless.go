package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// RedshiftServerlessClient defines the interface for Redshift Serverless operations.
type RedshiftServerlessClient interface {
	ListWorkgroups(ctx context.Context, params *redshiftserverless.ListWorkgroupsInput, optFns ...func(*redshiftserverless.Options)) (*redshiftserverless.ListWorkgroupsOutput, error)
	ListNamespaces(ctx context.Context, params *redshiftserverless.ListNamespacesInput, optFns ...func(*redshiftserverless.Options)) (*redshiftserverless.ListNamespacesOutput, error)
}

// RedshiftServerlessWorkgroup represents a Redshift Serverless workgroup.
type RedshiftServerlessWorkgroup struct {
	Name               string `json:"name"`
	ARN                string `json:"arn"`
	PubliclyAccessible bool   `json:"publicly_accessible"`
	Encrypted          bool   `json:"encrypted"`
	KMSKeyID           string `json:"kms_key_id,omitempty"`
}

// ToEvidence converts a RedshiftServerlessWorkgroup to Evidence.
func (w *RedshiftServerlessWorkgroup) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(w) //nolint:errcheck // marshaling a known struct type will not fail
	ev := evidence.New("aws", "aws:redshift-serverless:workgroup", w.ARN, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// RedshiftServerlessCollector collects Redshift Serverless data.
type RedshiftServerlessCollector struct {
	client RedshiftServerlessClient
}

// NewRedshiftServerlessCollector creates a new Redshift Serverless collector.
func NewRedshiftServerlessCollector(client RedshiftServerlessClient) *RedshiftServerlessCollector {
	return &RedshiftServerlessCollector{client: client}
}

// CollectWorkgroups retrieves all Redshift Serverless workgroups.
func (c *RedshiftServerlessCollector) CollectWorkgroups(ctx context.Context) ([]RedshiftServerlessWorkgroup, error) {
	var workgroups []RedshiftServerlessWorkgroup
	var nextToken *string

	// Build a map of namespace name -> encryption info
	namespaceEncryption := make(map[string]struct {
		encrypted bool
		kmsKeyID  string
	})
	c.collectNamespaceEncryption(ctx, namespaceEncryption)

	for {
		output, err := c.client.ListWorkgroups(ctx, &redshiftserverless.ListWorkgroupsInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list Redshift Serverless workgroups: %w", err)
		}

		for i := range output.Workgroups {
			wg := &output.Workgroups[i]
			workgroup := RedshiftServerlessWorkgroup{
				Name:               awssdk.ToString(wg.WorkgroupName),
				ARN:                awssdk.ToString(wg.WorkgroupArn),
				PubliclyAccessible: awssdk.ToBool(wg.PubliclyAccessible),
			}

			// Look up encryption from the associated namespace
			nsName := awssdk.ToString(wg.NamespaceName)
			if nsInfo, ok := namespaceEncryption[nsName]; ok {
				workgroup.Encrypted = nsInfo.encrypted
				workgroup.KMSKeyID = nsInfo.kmsKeyID
			}

			workgroups = append(workgroups, workgroup)
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return workgroups, nil
}

// collectNamespaceEncryption builds a map of namespace encryption status.
func (c *RedshiftServerlessCollector) collectNamespaceEncryption(ctx context.Context, nsMap map[string]struct {
	encrypted bool
	kmsKeyID  string
}) {
	var nextToken *string

	for {
		output, err := c.client.ListNamespaces(ctx, &redshiftserverless.ListNamespacesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return // Fail-safe
		}

		for i := range output.Namespaces {
			ns := &output.Namespaces[i]
			name := awssdk.ToString(ns.NamespaceName)
			kmsKeyID := awssdk.ToString(ns.KmsKeyId)
			nsMap[name] = struct {
				encrypted bool
				kmsKeyID  string
			}{
				encrypted: kmsKeyID != "",
				kmsKeyID:  kmsKeyID,
			}
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}
}

// CollectEvidence collects Redshift Serverless workgroups as evidence.
func (c *RedshiftServerlessCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	workgroups, err := c.CollectWorkgroups(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(workgroups))
	for i := range workgroups {
		evidenceList = append(evidenceList, workgroups[i].ToEvidence(accountID))
	}
	return evidenceList, nil
}
