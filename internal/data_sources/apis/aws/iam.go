package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// IAMClient defines the interface for IAM operations we use.
type IAMClient interface {
	ListUsers(ctx context.Context, params *iam.ListUsersInput, optFns ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListMFADevices(ctx context.Context, params *iam.ListMFADevicesInput, optFns ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
	GetLoginProfile(ctx context.Context, params *iam.GetLoginProfileInput, optFns ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error)
	ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetAccessKeyLastUsed(ctx context.Context, params *iam.GetAccessKeyLastUsedInput, optFns ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
	ListAttachedUserPolicies(ctx context.Context, params *iam.ListAttachedUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
}

// AccessKey represents an IAM access key with usage details.
type AccessKey struct {
	AccessKeyID     string    `json:"access_key_id"`
	Status          string    `json:"status"`
	CreateDate      time.Time `json:"create_date"`
	AgeDays         int       `json:"age_days"`
	LastUsedDays    int       `json:"last_used_days"`
	LastUsedService string    `json:"last_used_service,omitempty"`
}

// AttachedPolicy represents a managed policy attached to a user.
type AttachedPolicy struct {
	PolicyName string `json:"policy_name"`
	PolicyARN  string `json:"policy_arn"`
}

// IAMUser represents an IAM user with MFA status.
type IAMUser struct {
	UserName            string           `json:"user_name"`
	ARN                 string           `json:"arn"`
	UserID              string           `json:"user_id"`
	CreateDate          time.Time        `json:"create_date"`
	PasswordLastUsed    *time.Time       `json:"password_last_used,omitempty"`
	MFAEnabled          bool             `json:"mfa_enabled"`
	MFADevices          []string         `json:"mfa_devices,omitempty"`
	HasLoginProfile     bool             `json:"has_login_profile"`
	AccessKeys          []AccessKey      `json:"access_keys,omitempty"`
	ActiveKeyCount      int              `json:"active_key_count"`
	OldestKeyAgeDays    int              `json:"oldest_key_age_days"`
	PasswordInactiveDays int             `json:"password_inactive_days"`
	AttachedPolicies    []AttachedPolicy `json:"attached_policies,omitempty"`
	HasAdminPolicy      bool             `json:"has_admin_policy"`
}

// ToEvidence converts an IAMUser to an Evidence struct.
func (u *IAMUser) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(u) //nolint:errcheck // Marshal of known struct won't fail
	ev := evidence.New("aws", "aws:iam:user", u.ARN, data)
	ev.Metadata = evidence.Metadata{
		AccountID: accountID,
	}
	return ev
}

// IAMCollector collects IAM user data.
type IAMCollector struct {
	client IAMClient
}

// NewIAMCollector creates a new IAM collector.
func NewIAMCollector(client IAMClient) *IAMCollector {
	return &IAMCollector{client: client}
}

// CollectUsers retrieves all IAM users with their MFA status.
func (c *IAMCollector) CollectUsers(ctx context.Context) ([]IAMUser, error) {
	var users []IAMUser
	var marker *string

	now := time.Now().UTC()

	for {
		input := &iam.ListUsersInput{
			Marker: marker,
		}

		output, err := c.client.ListUsers(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list IAM users: %w", err)
		}

		for _, u := range output.Users {
			user := IAMUser{
				UserName: aws.ToString(u.UserName),
				ARN:      aws.ToString(u.Arn),
				UserID:   aws.ToString(u.UserId),
			}

			if u.CreateDate != nil {
				user.CreateDate = *u.CreateDate
			}
			if u.PasswordLastUsed != nil {
				user.PasswordLastUsed = u.PasswordLastUsed
			}

			// Check MFA status
			mfaDevices, err := c.getMFADevices(ctx, user.UserName)
			if err != nil {
				// Log warning but continue - fail-safe approach
				// In a real implementation, we'd use a logger here
				user.MFAEnabled = false
			} else {
				user.MFAEnabled = len(mfaDevices) > 0
				user.MFADevices = mfaDevices
			}

			// Check login profile (console access)
			user.HasLoginProfile = c.hasLoginProfile(ctx, user.UserName)

			// Enrich access keys
			c.enrichAccessKeys(ctx, &user, now)

			// Compute password inactive days
			c.computePasswordInactiveDays(&user, now)

			// Enrich attached policies
			c.enrichAttachedPolicies(ctx, &user)

			users = append(users, user)
		}

		if !output.IsTruncated {
			break
		}
		marker = output.Marker
	}

	return users, nil
}

// getMFADevices retrieves MFA devices for a user.
func (c *IAMCollector) getMFADevices(ctx context.Context, userName string) ([]string, error) {
	input := &iam.ListMFADevicesInput{
		UserName: aws.String(userName),
	}

	output, err := c.client.ListMFADevices(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to list MFA devices for user %s: %w", userName, err)
	}

	devices := make([]string, 0, len(output.MFADevices))
	for i := range output.MFADevices {
		devices = append(devices, aws.ToString(output.MFADevices[i].SerialNumber))
	}

	return devices, nil
}

// hasLoginProfile checks if a user has a login profile (console access).
// Returns false for programmatic-only users (NoSuchEntityException).
// Returns true on other errors as a fail-safe (assume console access).
func (c *IAMCollector) hasLoginProfile(ctx context.Context, userName string) bool {
	input := &iam.GetLoginProfileInput{
		UserName: aws.String(userName),
	}

	_, err := c.client.GetLoginProfile(ctx, input)
	if err != nil {
		var noSuchEntity *types.NoSuchEntityException
		if errors.As(err, &noSuchEntity) {
			return false
		}
		// Fail-safe: if we can't determine, assume console access
		return true
	}

	return true
}

// enrichAccessKeys fetches access key details for a user.
// Fail-safe: errors don't abort user collection.
func (c *IAMCollector) enrichAccessKeys(ctx context.Context, user *IAMUser, now time.Time) {
	output, err := c.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: aws.String(user.UserName),
	})
	if err != nil {
		// Fail-safe: can't list keys, leave defaults (empty keys, 0 counts)
		return
	}

	activeCount := 0
	oldestAge := 0

	for _, k := range output.AccessKeyMetadata {
		key := AccessKey{
			AccessKeyID: aws.ToString(k.AccessKeyId),
			Status:      string(k.Status),
		}

		if k.CreateDate != nil {
			key.CreateDate = *k.CreateDate
			key.AgeDays = daysBetween(*k.CreateDate, now)
		}

		// Get last used info
		key.LastUsedDays = -1 // default: never used
		lastUsedOutput, err := c.client.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
			AccessKeyId: k.AccessKeyId,
		})
		if err == nil && lastUsedOutput.AccessKeyLastUsed != nil {
			if lastUsedOutput.AccessKeyLastUsed.LastUsedDate != nil {
				key.LastUsedDays = daysBetween(*lastUsedOutput.AccessKeyLastUsed.LastUsedDate, now)
				key.LastUsedService = aws.ToString(lastUsedOutput.AccessKeyLastUsed.ServiceName)
			}
		}

		user.AccessKeys = append(user.AccessKeys, key)

		if k.Status == types.StatusTypeActive {
			activeCount++
			if key.AgeDays > oldestAge {
				oldestAge = key.AgeDays
			}
		}
	}

	user.ActiveKeyCount = activeCount
	user.OldestKeyAgeDays = oldestAge
}

// computePasswordInactiveDays computes how many days since password was last used.
// Returns -1 if user has no login profile or password was never used.
func (c *IAMCollector) computePasswordInactiveDays(user *IAMUser, now time.Time) {
	if !user.HasLoginProfile {
		user.PasswordInactiveDays = -1
		return
	}

	if user.PasswordLastUsed == nil {
		// Has console access but never logged in
		user.PasswordInactiveDays = -1
		return
	}

	user.PasswordInactiveDays = daysBetween(*user.PasswordLastUsed, now)
}

// enrichAttachedPolicies fetches managed policies attached to a user.
// Fail-safe: errors don't abort user collection.
func (c *IAMCollector) enrichAttachedPolicies(ctx context.Context, user *IAMUser) {
	output, err := c.client.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{
		UserName: aws.String(user.UserName),
	})
	if err != nil {
		// Fail-safe: can't list policies, leave defaults
		return
	}

	for _, p := range output.AttachedPolicies {
		ap := AttachedPolicy{
			PolicyName: aws.ToString(p.PolicyName),
			PolicyARN:  aws.ToString(p.PolicyArn),
		}
		user.AttachedPolicies = append(user.AttachedPolicies, ap)

		if ap.PolicyName == "AdministratorAccess" {
			user.HasAdminPolicy = true
		}
	}
}

// daysBetween returns the number of whole days between two times.
func daysBetween(from, to time.Time) int {
	d := to.Sub(from).Hours() / 24
	return int(math.Floor(d))
}

// CollectEvidence collects IAM users as evidence.
func (c *IAMCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	users, err := c.CollectUsers(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(users))
	for i := range users {
		evidenceList = append(evidenceList, users[i].ToEvidence(accountID))
	}

	return evidenceList, nil
}
