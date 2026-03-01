package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/iam/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// ServiceAccount represents a GCP service account with key metadata.
type ServiceAccount struct {
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name,omitempty"`
	UniqueID    string    `json:"unique_id"`
	Disabled    bool      `json:"disabled"`
	Keys        []SAKey   `json:"keys,omitempty"`
	KeyCount    int       `json:"key_count"`
	OldestKeyAge int      `json:"oldest_key_age_days"`
}

// SAKey represents a service account key.
type SAKey struct {
	Name           string    `json:"name"`
	KeyAlgorithm   string    `json:"key_algorithm"`
	KeyOrigin      string    `json:"key_origin"`
	KeyType        string    `json:"key_type"`
	ValidAfterTime time.Time `json:"valid_after_time"`
	ValidBeforeTime time.Time `json:"valid_before_time"`
	AgeDays        int       `json:"age_days"`
}

// IAMBinding represents an IAM policy binding on the project.
type IAMBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

// ProjectIAMPolicy represents the IAM policy for a project.
type ProjectIAMPolicy struct {
	ProjectID string       `json:"project_id"`
	Bindings  []IAMBinding `json:"bindings"`
}

// ToEvidence converts a ServiceAccount to Evidence.
func (sa *ServiceAccount) ToEvidence(projectID string) evidence.Evidence {
	data, _ := json.Marshal(sa) //nolint:errcheck
	ev := evidence.New("gcp", "gcp:iam:service-account", sa.Email, data)
	ev.Metadata = evidence.Metadata{
		AccountID: projectID,
	}
	return ev
}

// ToEvidence converts a ProjectIAMPolicy to Evidence.
func (p *ProjectIAMPolicy) ToEvidence() evidence.Evidence {
	data, _ := json.Marshal(p) //nolint:errcheck
	ev := evidence.New("gcp", "gcp:iam:policy", p.ProjectID, data)
	ev.Metadata = evidence.Metadata{
		AccountID: p.ProjectID,
	}
	return ev
}

// IAMCollector collects GCP IAM data.
type IAMCollector struct {
	iamService *iam.Service
	crmService *cloudresourcemanager.Service
}

// NewIAMCollector creates a new GCP IAM collector.
func NewIAMCollector(iamService *iam.Service, crmService *cloudresourcemanager.Service) *IAMCollector {
	return &IAMCollector{iamService: iamService, crmService: crmService}
}

// CollectServiceAccounts retrieves all service accounts with key metadata.
func (c *IAMCollector) CollectServiceAccounts(ctx context.Context, projectID string) ([]ServiceAccount, error) {
	resp, err := c.iamService.Projects.ServiceAccounts.List(
		fmt.Sprintf("projects/%s", projectID),
	).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list service accounts: %w", err)
	}

	var accounts []ServiceAccount
	now := time.Now()

	for _, sa := range resp.Accounts {
		account := ServiceAccount{
			Email:       sa.Email,
			Name:        sa.Name,
			DisplayName: sa.DisplayName,
			UniqueID:    sa.UniqueId,
			Disabled:    sa.Disabled,
		}

		// Get keys for this service account
		keys, err := c.getServiceAccountKeys(ctx, sa.Name)
		if err != nil {
			// Fail-safe: continue without keys
			account.Keys = []SAKey{}
		} else {
			account.Keys = keys
			account.KeyCount = len(keys)

			// Calculate oldest key age
			var oldestAge int
			for _, k := range keys {
				age := int(now.Sub(k.ValidAfterTime).Hours() / 24)
				if age > oldestAge {
					oldestAge = age
				}
			}
			account.OldestKeyAge = oldestAge
		}

		accounts = append(accounts, account)
	}

	return accounts, nil
}

// getServiceAccountKeys retrieves user-managed keys for a service account.
func (c *IAMCollector) getServiceAccountKeys(ctx context.Context, saName string) ([]SAKey, error) {
	resp, err := c.iamService.Projects.ServiceAccounts.Keys.List(saName).
		KeyTypes("USER_MANAGED").
		Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys for %s: %w", saName, err)
	}

	now := time.Now()
	var keys []SAKey

	for _, k := range resp.Keys {
		key := SAKey{
			Name:         k.Name,
			KeyAlgorithm: k.KeyAlgorithm,
			KeyOrigin:    k.KeyOrigin,
			KeyType:      k.KeyType,
		}

		if t, err := time.Parse(time.RFC3339, k.ValidAfterTime); err == nil {
			key.ValidAfterTime = t
			key.AgeDays = int(now.Sub(t).Hours() / 24)
		}
		if t, err := time.Parse(time.RFC3339, k.ValidBeforeTime); err == nil {
			key.ValidBeforeTime = t
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// CollectIAMPolicy retrieves the project-level IAM policy.
func (c *IAMCollector) CollectIAMPolicy(ctx context.Context, projectID string) (*ProjectIAMPolicy, error) {
	policy, err := c.crmService.Projects.GetIamPolicy(projectID,
		&cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy: %w", err)
	}

	result := &ProjectIAMPolicy{
		ProjectID: projectID,
	}

	for _, b := range policy.Bindings {
		result.Bindings = append(result.Bindings, IAMBinding{
			Role:    b.Role,
			Members: b.Members,
		})
	}

	return result, nil
}

// CollectEvidence collects all IAM evidence.
func (c *IAMCollector) CollectEvidence(ctx context.Context, projectID string) ([]evidence.Evidence, error) {
	var evidenceList []evidence.Evidence

	// Collect service accounts
	accounts, err := c.CollectServiceAccounts(ctx, projectID)
	if err != nil {
		return nil, err
	}
	for i := range accounts {
		evidenceList = append(evidenceList, accounts[i].ToEvidence(projectID))
	}

	// Collect IAM policy
	policy, err := c.CollectIAMPolicy(ctx, projectID)
	if err != nil {
		// Fail-safe: continue without policy
		_ = err
	} else {
		evidenceList = append(evidenceList, policy.ToEvidence())
	}

	return evidenceList, nil
}
