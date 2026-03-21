package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
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
	ListUserPolicies(ctx context.Context, params *iam.ListUserPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	ListGroupsForUser(ctx context.Context, params *iam.ListGroupsForUserInput, optFns ...func(*iam.Options)) (*iam.ListGroupsForUserOutput, error)
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListPolicies(ctx context.Context, params *iam.ListPoliciesInput, optFns ...func(*iam.Options)) (*iam.ListPoliciesOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	ListServerCertificates(ctx context.Context, params *iam.ListServerCertificatesInput, optFns ...func(*iam.Options)) (*iam.ListServerCertificatesOutput, error)
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
	HasAdminPolicy       bool             `json:"has_admin_policy"`
	InlinePolicyCount    int              `json:"inline_policy_count"`
	HasPermissionBoundary bool            `json:"has_permission_boundary"`
	GroupCount            int             `json:"group_count"`
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

// IAMRole represents an IAM role with admin access status.
type IAMRole struct {
	RoleName         string           `json:"role_name"`
	ARN              string           `json:"arn"`
	RoleID           string           `json:"role_id"`
	HasAdminAccess   bool             `json:"has_admin_access"`
	AttachedPolicies []AttachedPolicy `json:"attached_policies,omitempty"`
}

// ToEvidence converts an IAMRole to an Evidence struct.
func (r *IAMRole) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(r) //nolint:errcheck // Marshal of known struct won't fail
	ev := evidence.New("aws", "aws:iam:role", r.ARN, data)
	ev.Metadata = evidence.Metadata{
		AccountID: accountID,
	}
	return ev
}

// IAMPolicy represents an IAM customer-managed policy.
type IAMPolicy struct {
	PolicyName            string `json:"policy_name"`
	PolicyARN             string `json:"policy_arn"`
	PolicyID              string `json:"policy_id"`
	IsAWSManaged          bool   `json:"is_aws_managed"`
	HasWildcardKMSDecrypt bool   `json:"has_wildcard_kms_decrypt"`
}

// ToEvidence converts an IAMPolicy to an Evidence struct.
func (p *IAMPolicy) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(p) //nolint:errcheck // Marshal of known struct won't fail
	ev := evidence.New("aws", "aws:iam:policy", p.PolicyARN, data)
	ev.Metadata = evidence.Metadata{
		AccountID: accountID,
	}
	return ev
}

// IAMSupportRoleStatus represents whether an AWS Support access role exists.
type IAMSupportRoleStatus struct {
	HasSupportRole bool   `json:"has_support_role"`
	RoleARN        string `json:"role_arn,omitempty"`
}

// ToEvidence converts an IAMSupportRoleStatus to an Evidence struct.
func (s *IAMSupportRoleStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // Marshal of known struct won't fail
	ev := evidence.New("aws", "aws:iam:support-role-status", fmt.Sprintf("arn:aws:iam::%s:support-role-status", accountID), data)
	ev.Metadata = evidence.Metadata{
		AccountID: accountID,
	}
	return ev
}

// IAMServerCertificateStatus represents whether IAM server certificates exist.
type IAMServerCertificateStatus struct {
	HasServerCertificates bool `json:"has_server_certificates"`
	CertificateCount      int  `json:"certificate_count"`
}

// ToEvidence converts an IAMServerCertificateStatus to an Evidence struct.
func (s *IAMServerCertificateStatus) ToEvidence(accountID string) evidence.Evidence {
	data, _ := json.Marshal(s) //nolint:errcheck // Marshal of known struct won't fail
	ev := evidence.New("aws", "aws:iam:server-certificate-status", fmt.Sprintf("arn:aws:iam::%s:server-certificate-status", accountID), data)
	ev.Metadata = evidence.Metadata{
		AccountID: accountID,
	}
	return ev
}

// policyDocument represents an IAM policy document structure.
type policyDocument struct {
	Statement []policyStatement `json:"Statement"`
}

// policyStatement represents a single statement in an IAM policy document.
type policyStatement struct {
	Effect   string      `json:"Effect"`
	Action   interface{} `json:"Action"`
	Resource interface{} `json:"Resource"`
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
				UserName:              aws.ToString(u.UserName),
				ARN:                   aws.ToString(u.Arn),
				UserID:                aws.ToString(u.UserId),
				HasPermissionBoundary: u.PermissionsBoundary != nil,
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

			// Enrich inline policy count
			c.enrichInlinePolicies(ctx, &user)

			// Enrich group membership
			c.enrichGroups(ctx, &user)

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

// enrichInlinePolicies counts inline policies attached to a user.
// Fail-safe: errors don't abort user collection.
func (c *IAMCollector) enrichInlinePolicies(ctx context.Context, user *IAMUser) {
	output, err := c.client.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
		UserName: aws.String(user.UserName),
	})
	if err != nil {
		// Fail-safe: can't list inline policies, leave default (0)
		return
	}

	user.InlinePolicyCount = len(output.PolicyNames)
}

// enrichGroups counts groups a user belongs to.
// Fail-safe: errors don't abort user collection.
func (c *IAMCollector) enrichGroups(ctx context.Context, user *IAMUser) {
	output, err := c.client.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{
		UserName: aws.String(user.UserName),
	})
	if err != nil {
		// Fail-safe: can't list groups, leave default (0)
		return
	}

	user.GroupCount = len(output.Groups)
}

// daysBetween returns the number of whole days between two times.
func daysBetween(from, to time.Time) int {
	d := to.Sub(from).Hours() / 24
	return int(math.Floor(d))
}

// CollectRoles retrieves all IAM roles with their attached policies and admin access status.
func (c *IAMCollector) CollectRoles(ctx context.Context) ([]IAMRole, error) {
	var roles []IAMRole
	var marker *string

	for {
		input := &iam.ListRolesInput{
			Marker: marker,
		}

		output, err := c.client.ListRoles(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list IAM roles: %w", err)
		}

		for _, r := range output.Roles {
			role := IAMRole{
				RoleName: aws.ToString(r.RoleName),
				ARN:      aws.ToString(r.Arn),
				RoleID:   aws.ToString(r.RoleId),
			}

			// Enrich with attached policies
			c.enrichRolePolicies(ctx, &role)

			roles = append(roles, role)
		}

		if !output.IsTruncated {
			break
		}
		marker = output.Marker
	}

	return roles, nil
}

// enrichRolePolicies fetches managed policies attached to a role and checks for admin access.
// Fail-safe: errors don't abort role collection.
func (c *IAMCollector) enrichRolePolicies(ctx context.Context, role *IAMRole) {
	output, err := c.client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(role.RoleName),
	})
	if err != nil {
		// Fail-safe: skip enrichment on error
		return
	}

	for _, p := range output.AttachedPolicies {
		ap := AttachedPolicy{
			PolicyName: aws.ToString(p.PolicyName),
			PolicyARN:  aws.ToString(p.PolicyArn),
		}
		role.AttachedPolicies = append(role.AttachedPolicies, ap)

		if ap.PolicyARN == "arn:aws:iam::aws:policy/AdministratorAccess" {
			role.HasAdminAccess = true
		}
	}
}

// CollectPolicies retrieves all customer-managed IAM policies and checks for wildcard KMS decrypt permissions.
func (c *IAMCollector) CollectPolicies(ctx context.Context) ([]IAMPolicy, error) {
	var policies []IAMPolicy
	var marker *string

	for {
		input := &iam.ListPoliciesInput{
			Scope:  types.PolicyScopeTypeLocal,
			Marker: marker,
		}

		output, err := c.client.ListPolicies(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list IAM policies: %w", err)
		}

		for _, p := range output.Policies {
			policy := IAMPolicy{
				PolicyName:   aws.ToString(p.PolicyName),
				PolicyARN:    aws.ToString(p.Arn),
				PolicyID:     aws.ToString(p.PolicyId),
				IsAWSManaged: false, // Scope: Local means customer-managed
			}

			// Check for wildcard KMS decrypt
			policy.HasWildcardKMSDecrypt = c.checkWildcardKMSDecrypt(ctx, policy.PolicyARN, aws.ToString(p.DefaultVersionId))

			policies = append(policies, policy)
		}

		if !output.IsTruncated {
			break
		}
		marker = output.Marker
	}

	return policies, nil
}

// checkWildcardKMSDecrypt checks if a policy version grants wildcard kms:Decrypt access.
// Fail-safe: returns false if the policy document cannot be retrieved or parsed.
func (c *IAMCollector) checkWildcardKMSDecrypt(ctx context.Context, policyARN, versionID string) bool {
	output, err := c.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(policyARN),
		VersionId: aws.String(versionID),
	})
	if err != nil {
		return false
	}

	if output.PolicyVersion == nil || output.PolicyVersion.Document == nil {
		return false
	}

	// Policy documents are URL-encoded
	decoded, err := url.QueryUnescape(aws.ToString(output.PolicyVersion.Document))
	if err != nil {
		return false
	}

	var doc policyDocument
	if err := json.Unmarshal([]byte(decoded), &doc); err != nil {
		return false
	}

	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		if !interfaceContainsAny(stmt.Action, "kms:Decrypt", "kms:*") {
			continue
		}
		if !interfaceContainsAny(stmt.Resource, "*") {
			continue
		}
		return true
	}

	return false
}

// interfaceContainsAny checks if a value (string or []interface{}) contains any of the target strings.
func interfaceContainsAny(val interface{}, targets ...string) bool {
	switch v := val.(type) {
	case string:
		for _, t := range targets {
			if strings.EqualFold(v, t) {
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				continue
			}
			for _, t := range targets {
				if strings.EqualFold(s, t) {
					return true
				}
			}
		}
	}
	return false
}

// CollectSupportRoleStatus checks if any IAM role has the AWSSupportAccess policy attached.
func (c *IAMCollector) CollectSupportRoleStatus(ctx context.Context) (*IAMSupportRoleStatus, error) {
	roles, err := c.CollectRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect roles for support role check: %w", err)
	}

	status := &IAMSupportRoleStatus{}
	for _, role := range roles {
		for _, p := range role.AttachedPolicies {
			if p.PolicyName == "AWSSupportAccess" {
				status.HasSupportRole = true
				status.RoleARN = role.ARN
				return status, nil
			}
		}
	}

	return status, nil
}

// CollectServerCertificateStatus checks if any IAM server certificates exist.
func (c *IAMCollector) CollectServerCertificateStatus(ctx context.Context) (*IAMServerCertificateStatus, error) {
	output, err := c.client.ListServerCertificates(ctx, &iam.ListServerCertificatesInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to list server certificates: %w", err)
	}

	count := len(output.ServerCertificateMetadataList)
	return &IAMServerCertificateStatus{
		HasServerCertificates: count > 0,
		CertificateCount:      count,
	}, nil
}

// CollectEvidence collects IAM users, roles, and policies as evidence.
func (c *IAMCollector) CollectEvidence(ctx context.Context, accountID string) ([]evidence.Evidence, error) {
	users, err := c.CollectUsers(ctx)
	if err != nil {
		return nil, err
	}

	evidenceList := make([]evidence.Evidence, 0, len(users))
	for i := range users {
		evidenceList = append(evidenceList, users[i].ToEvidence(accountID))
	}

	// Collect roles (fail-safe: errors ignored)
	roles, err := c.CollectRoles(ctx)
	if err == nil {
		for i := range roles {
			evidenceList = append(evidenceList, roles[i].ToEvidence(accountID))
		}
	}

	// Collect policies (fail-safe: errors ignored)
	policies, err := c.CollectPolicies(ctx)
	if err == nil {
		for i := range policies {
			evidenceList = append(evidenceList, policies[i].ToEvidence(accountID))
		}
	}

	// Support role status (fail-safe)
	supportStatus, err := c.CollectSupportRoleStatus(ctx)
	if err == nil {
		evidenceList = append(evidenceList, supportStatus.ToEvidence(accountID))
	}

	// Server certificate status (fail-safe)
	certStatus, err := c.CollectServerCertificateStatus(ctx)
	if err == nil {
		evidenceList = append(evidenceList, certStatus.ToEvidence(accountID))
	}

	return evidenceList, nil
}
