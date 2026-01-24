package github

import (
	"context"
	"encoding/json"
	"fmt"

	gh "github.com/google/go-github/v57/github"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// Member represents a GitHub organization member.
type Member struct {
	Login             string `json:"login"`
	ID                int64  `json:"id"`
	Type              string `json:"type"`
	SiteAdmin         bool   `json:"site_admin"`
	Organization      string `json:"organization"`
	Role              string `json:"role,omitempty"`
	TwoFactorEnabled  *bool  `json:"two_factor_enabled,omitempty"`
}

// ToEvidence converts a Member to an Evidence struct.
func (m *Member) ToEvidence() evidence.Evidence {
	data, _ := json.Marshal(m) //nolint:errcheck // Marshal of known struct won't fail
	resourceID := fmt.Sprintf("%s/members/%s", m.Organization, m.Login)
	ev := evidence.New("github", "github:member", resourceID, data)
	ev.Metadata = evidence.Metadata{
		Organization: m.Organization,
	}
	return ev
}

// MemberCollector collects GitHub organization member data.
type MemberCollector struct {
	client Client
}

// NewMemberCollector creates a new member collector.
func NewMemberCollector(client Client) *MemberCollector {
	return &MemberCollector{client: client}
}

// CollectMembers collects all members from an organization.
func (c *MemberCollector) CollectMembers(ctx context.Context, org string) ([]evidence.Evidence, error) {
	var allMembers []*gh.User
	opts := &gh.ListMembersOptions{
		ListOptions: gh.ListOptions{PerPage: 100},
	}

	// List all members with pagination
	for {
		members, resp, err := c.client.ListOrgMembers(ctx, org, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list organization members: %w", err)
		}

		allMembers = append(allMembers, members...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	// Convert to evidence
	evidenceList := make([]evidence.Evidence, 0, len(allMembers))
	for _, user := range allMembers {
		member := &Member{
			Login:        user.GetLogin(),
			ID:           user.GetID(),
			Type:         user.GetType(),
			SiteAdmin:    user.GetSiteAdmin(),
			Organization: org,
		}

		// Note: GitHub API doesn't directly expose 2FA status for org members
		// You need admin access and the /orgs/{org}/members?filter=2fa_disabled endpoint
		// We leave TwoFactorEnabled as nil to indicate unknown

		evidenceList = append(evidenceList, member.ToEvidence())
	}

	return evidenceList, nil
}

// CollectMembersWithFilter collects members with a specific filter.
// Filter can be "all", "2fa_disabled", or empty for default.
func (c *MemberCollector) CollectMembersWithFilter(ctx context.Context, org, filter string) ([]evidence.Evidence, error) {
	var allMembers []*gh.User
	opts := &gh.ListMembersOptions{
		Filter:      filter,
		ListOptions: gh.ListOptions{PerPage: 100},
	}

	for {
		members, resp, err := c.client.ListOrgMembers(ctx, org, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list organization members with filter %s: %w", filter, err)
		}

		allMembers = append(allMembers, members...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	// Determine 2FA status based on filter
	var twoFactorEnabled *bool
	if filter == "2fa_disabled" {
		f := false
		twoFactorEnabled = &f
	}

	evidenceList := make([]evidence.Evidence, 0, len(allMembers))
	for _, user := range allMembers {
		member := &Member{
			Login:            user.GetLogin(),
			ID:               user.GetID(),
			Type:             user.GetType(),
			SiteAdmin:        user.GetSiteAdmin(),
			Organization:     org,
			TwoFactorEnabled: twoFactorEnabled,
		}

		evidenceList = append(evidenceList, member.ToEvidence())
	}

	return evidenceList, nil
}

// CollectMembersWithTwoFactorStatus collects all members and determines their 2FA status.
// It first attempts to query members with 2FA disabled (requires org admin access).
// If successful, it cross-references to determine each member's 2FA status.
// If the filter query fails (no admin access), it falls back to unknown status.
func (c *MemberCollector) CollectMembersWithTwoFactorStatus(ctx context.Context, org string) ([]evidence.Evidence, bool, error) {
	// First, try to get members with 2FA disabled (requires admin access)
	membersWithout2FA := make(map[string]bool)
	has2FAVisibility := false

	disabledOpts := &gh.ListMembersOptions{
		Filter:      "2fa_disabled",
		ListOptions: gh.ListOptions{PerPage: 100},
	}

	for {
		members, resp, err := c.client.ListOrgMembers(ctx, org, disabledOpts)
		if err != nil {
			// If we get an error (likely 403 Forbidden), we don't have admin access
			// Fall back to collecting without 2FA status
			break
		}

		// If we get here, we have admin access
		has2FAVisibility = true
		for _, user := range members {
			membersWithout2FA[user.GetLogin()] = true
		}

		if resp.NextPage == 0 {
			break
		}
		disabledOpts.Page = resp.NextPage
	}

	// Now get all members
	var allMembers []*gh.User
	opts := &gh.ListMembersOptions{
		ListOptions: gh.ListOptions{PerPage: 100},
	}

	for {
		members, resp, err := c.client.ListOrgMembers(ctx, org, opts)
		if err != nil {
			return nil, has2FAVisibility, fmt.Errorf("failed to list organization members: %w", err)
		}

		allMembers = append(allMembers, members...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	// Convert to evidence with 2FA status
	evidenceList := make([]evidence.Evidence, 0, len(allMembers))
	for _, user := range allMembers {
		member := &Member{
			Login:        user.GetLogin(),
			ID:           user.GetID(),
			Type:         user.GetType(),
			SiteAdmin:    user.GetSiteAdmin(),
			Organization: org,
		}

		if has2FAVisibility {
			// We have admin access, so we can determine 2FA status
			twoFactorEnabled := !membersWithout2FA[user.GetLogin()]
			member.TwoFactorEnabled = &twoFactorEnabled
		}
		// If no admin access, TwoFactorEnabled remains nil (unknown)

		evidenceList = append(evidenceList, member.ToEvidence())
	}

	return evidenceList, has2FAVisibility, nil
}
