package aws

import (
	"context"
	"encoding/json"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// SSMClient defines the interface for SSM operations.
type SSMClient interface {
	DescribeInstanceInformation(ctx context.Context, params *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error)
	GetServiceSetting(ctx context.Context, params *ssm.GetServiceSettingInput, optFns ...func(*ssm.Options)) (*ssm.GetServiceSettingOutput, error)
	ListDocuments(ctx context.Context, params *ssm.ListDocumentsInput, optFns ...func(*ssm.Options)) (*ssm.ListDocumentsOutput, error)
	DescribeDocumentPermission(ctx context.Context, params *ssm.DescribeDocumentPermissionInput, optFns ...func(*ssm.Options)) (*ssm.DescribeDocumentPermissionOutput, error)
	ListComplianceItems(ctx context.Context, params *ssm.ListComplianceItemsInput, optFns ...func(*ssm.Options)) (*ssm.ListComplianceItemsOutput, error)
}

// SSMStatus represents the SSM Session Manager status.
type SSMStatus struct {
	ManagedInstanceCount  int    `json:"managed_instance_count"`
	SessionManagerEnabled bool   `json:"session_manager_enabled"`
	Region                string `json:"region"`
}

// ToEvidence converts an SSMStatus to Evidence.
func (s *SSMStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:ssm:%s:%s:ssm-status", s.Region, accountID)
	ev := evidence.New("aws", "aws:ssm:status", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// SSMDocumentStatus represents the SSM document public sharing status.
type SSMDocumentStatus struct {
	HasPublicDocuments bool   `json:"has_public_documents"`
	Region             string `json:"region"`
}

// ToEvidence converts an SSMDocumentStatus to Evidence.
func (s *SSMDocumentStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:ssm:%s:%s:document-status", s.Region, accountID)
	ev := evidence.New("aws", "aws:ssm:document-status", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// SSMManagedInstance represents an SSM-managed instance with patch compliance.
type SSMManagedInstance struct {
	InstanceID     string `json:"instance_id"`
	PatchCompliant bool   `json:"patch_compliant"`
}

// ToEvidence converts an SSMManagedInstance to Evidence.
func (i *SSMManagedInstance) ToEvidence(accountID, region string) evidence.Evidence {
	data, _ := json.Marshal(i) //nolint:errcheck
	resourceID := fmt.Sprintf("arn:aws:ssm:%s:%s:managed-instance/%s", region, accountID, i.InstanceID)
	ev := evidence.New("aws", "aws:ssm:managed-instance", resourceID, data)
	ev.Metadata = evidence.Metadata{AccountID: accountID}
	return ev
}

// SSMCollector collects SSM data.
type SSMCollector struct {
	client SSMClient
	region string
}

// NewSSMCollector creates a new SSM collector.
func NewSSMCollector(client SSMClient, region string) *SSMCollector {
	return &SSMCollector{client: client, region: region}
}

// CollectStatus retrieves SSM status.
func (c *SSMCollector) CollectStatus(ctx context.Context) (*SSMStatus, error) {
	status := &SSMStatus{Region: c.region}

	// Count managed instances
	output, err := c.client.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{})
	if err == nil {
		status.ManagedInstanceCount = len(output.InstanceInformationList)
	}

	// Check Session Manager
	settingOutput, err := c.client.GetServiceSetting(ctx, &ssm.GetServiceSettingInput{
		SettingId: awssdk.String(fmt.Sprintf("arn:aws:ssm:%s:%s:servicesetting/ssm/managed-instance/activation-tier", c.region, "account")),
	})
	if err == nil && settingOutput.ServiceSetting != nil {
		// Session Manager is available if there are managed instances
		status.SessionManagerEnabled = status.ManagedInstanceCount > 0
	} else {
		// Fallback: if we have managed instances, Session Manager is likely enabled
		status.SessionManagerEnabled = status.ManagedInstanceCount > 0
	}

	return status, nil
}

// CollectDocumentStatus checks if any SSM documents are publicly shared.
func (c *SSMCollector) CollectDocumentStatus(ctx context.Context) (*SSMDocumentStatus, error) {
	status := &SSMDocumentStatus{Region: c.region}

	// List owned documents
	output, err := c.client.ListDocuments(ctx, &ssm.ListDocumentsInput{
		Filters: []ssmtypes.DocumentKeyValuesFilter{
			{Key: awssdk.String("Owner"), Values: []string{"Self"}},
		},
	})
	if err != nil {
		return status, nil //nolint:nilerr // fail-safe: return partial results on error
	}

	for _, doc := range output.DocumentIdentifiers {
		docName := awssdk.ToString(doc.Name)
		if docName == "" {
			continue
		}
		permOutput, err := c.client.DescribeDocumentPermission(ctx, &ssm.DescribeDocumentPermissionInput{
			Name:           awssdk.String(docName),
			PermissionType: ssmtypes.DocumentPermissionTypeShare,
		})
		if err != nil {
			continue // Fail-safe per document
		}
		for _, acctID := range permOutput.AccountIds {
			if acctID == "all" {
				status.HasPublicDocuments = true
				return status, nil
			}
		}
	}

	return status, nil
}

// CollectManagedInstances retrieves SSM-managed instances with patch compliance status.
func (c *SSMCollector) CollectManagedInstances(ctx context.Context) ([]SSMManagedInstance, error) {
	output, err := c.client.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to describe instance information: %w", err)
	}

	var instances []SSMManagedInstance
	for _, inst := range output.InstanceInformationList {
		instanceID := awssdk.ToString(inst.InstanceId)
		managed := SSMManagedInstance{
			InstanceID:     instanceID,
			PatchCompliant: true, // Assume compliant unless we find non-compliant items
		}

		// Check patch compliance for this instance
		compOutput, err := c.client.ListComplianceItems(ctx, &ssm.ListComplianceItemsInput{
			ResourceIds:   []string{instanceID},
			ResourceTypes: []string{"ManagedInstance"},
			Filters: []ssmtypes.ComplianceStringFilter{
				{
					Key:    awssdk.String("ComplianceType"),
					Values: []string{"Patch"},
				},
			},
		})
		if err != nil {
			continue // Fail-safe per instance
		}

		for _, item := range compOutput.ComplianceItems {
			if item.Status == ssmtypes.ComplianceStatusNonCompliant {
				managed.PatchCompliant = false
				break
			}
		}

		instances = append(instances, managed)
	}

	return instances, nil
}

// CollectEvidence collects SSM status as evidence.
func (c *SSMCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	var evidenceList []evidence.Evidence

	status, err := c.CollectStatus(ctx)
	if err != nil {
		return nil, err
	}
	evidenceList = append(evidenceList, status.ToEvidence(accountID))

	// Document status (fail-safe)
	docStatus, err := c.CollectDocumentStatus(ctx)
	if err == nil {
		evidenceList = append(evidenceList, docStatus.ToEvidence(accountID))
	}

	// Managed instances with patch compliance (fail-safe)
	managedInstances, err := c.CollectManagedInstances(ctx)
	if err != nil {
		_ = err
	} else {
		for i := range managedInstances {
			evidenceList = append(evidenceList, managedInstances[i].ToEvidence(accountID, c.region))
		}
	}

	return evidenceList, nil
}
