package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
}

// IAMUser represents an IAM user with MFA status.
type IAMUser struct {
	UserName       string    `json:"user_name"`
	ARN            string    `json:"arn"`
	UserID         string    `json:"user_id"`
	CreateDate     time.Time `json:"create_date"`
	PasswordLastUsed *time.Time `json:"password_last_used,omitempty"`
	MFAEnabled     bool      `json:"mfa_enabled"`
	MFADevices      []string  `json:"mfa_devices,omitempty"`
	HasLoginProfile bool      `json:"has_login_profile"`
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
				UserName:   aws.ToString(u.UserName),
				ARN:        aws.ToString(u.Arn),
				UserID:     aws.ToString(u.UserId),
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
