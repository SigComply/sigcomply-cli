//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/engine"
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	"github.com/sigcomply/sigcomply-cli/internal/data_sources/apis/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// skipIfNoGitHub skips the test if GitHub token is not configured.
func skipIfNoGitHub(t *testing.T) {
	t.Helper()

	if os.Getenv("GITHUB_TOKEN") == "" {
		t.Skip("GitHub token not configured - set GITHUB_TOKEN environment variable")
	}
}

// getGitHubOrg returns the GitHub organization to test against.
// Uses E2E_GITHUB_ORG env var, or falls back to extracting from E2E_GITHUB_REPO.
func getGitHubOrg() string {
	if org := os.Getenv("E2E_GITHUB_ORG"); org != "" {
		return org
	}
	// Try to extract from repo (format: owner/repo)
	if repo := os.Getenv("E2E_GITHUB_REPO"); repo != "" {
		parts := strings.Split(repo, "/")
		if len(parts) >= 1 {
			return parts[0]
		}
	}
	return ""
}

// TestGitHub_Connectivity verifies that we can connect to GitHub with the provided token.
func TestGitHub_Connectivity(t *testing.T) {
	skipIfNoGitHub(t)

	ctx := context.Background()
	collector := github.New()

	err := collector.Init(ctx)
	require.NoError(t, err, "Failed to initialize GitHub collector")

	status := collector.Status(ctx)
	assert.True(t, status.Connected, "Should be connected to GitHub")
	assert.NotEmpty(t, status.Username, "Should have authenticated username")

	t.Logf("Connected to GitHub as: %s", status.Username)
}

// TestGitHub_RepoCollection tests that we can collect repository evidence.
func TestGitHub_RepoCollection(t *testing.T) {
	skipIfNoGitHub(t)

	ctx := context.Background()
	org := getGitHubOrg()

	collector := github.New()
	if org != "" {
		collector.WithOrganization(org)
	}

	err := collector.Init(ctx)
	require.NoError(t, err)

	result, err := collector.Collect(ctx)
	require.NoError(t, err, "Evidence collection should not fail")

	// Log any errors that occurred during collection
	if result.HasErrors() {
		for _, e := range result.Errors {
			t.Logf("Collection warning: %s - %s", e.Resource, e.Error)
		}
	}

	// Should have collected at least some evidence
	require.NotEmpty(t, result.Evidence, "Should have collected some evidence")

	// Count evidence by type
	typeCounts := make(map[string]int)
	for _, ev := range result.Evidence {
		typeCounts[ev.ResourceType]++
	}

	t.Logf("Collected evidence summary:")
	for resourceType, count := range typeCounts {
		t.Logf("  - %s: %d items", resourceType, count)
	}

	// Should have collected repositories
	assert.Greater(t, typeCounts["github:repository"], 0, "Should have collected at least one repository")
}

// TestGitHub_RepoStructure validates the structure of collected repository evidence.
func TestGitHub_RepoStructure(t *testing.T) {
	skipIfNoGitHub(t)

	ctx := context.Background()
	org := getGitHubOrg()

	collector := github.New()
	if org != "" {
		collector.WithOrganization(org)
	}

	require.NoError(t, collector.Init(ctx))

	result, err := collector.Collect(ctx)
	require.NoError(t, err)

	// Filter for repositories
	var repos []evidence.Evidence
	for _, ev := range result.Evidence {
		if ev.ResourceType == "github:repository" {
			repos = append(repos, ev)
		}
	}

	require.NotEmpty(t, repos, "Should have collected repositories")

	// Validate repository structure
	for _, ev := range repos {
		var data map[string]interface{}
		err := json.Unmarshal(ev.Data, &data)
		require.NoError(t, err, "Should parse repository data")

		// Check required fields exist
		assert.NotNil(t, data["name"], "Repository should have name")
		assert.NotNil(t, data["full_name"], "Repository should have full_name")
		assert.NotNil(t, data["owner"], "Repository should have owner")

		// Log branch protection status
		if bp, ok := data["branch_protection"]; ok && bp != nil {
			bpMap := bp.(map[string]interface{})
			t.Logf("  Repo: %s, Branch Protection: enabled=%v, require_pr=%v",
				data["full_name"], bpMap["enabled"], bpMap["require_pull_request"])
		} else {
			t.Logf("  Repo: %s, Branch Protection: not configured", data["full_name"])
		}
	}
}

// TestGitHub_MemberCollection tests organization member collection.
// This test requires an organization and may require admin access for 2FA status.
func TestGitHub_MemberCollection(t *testing.T) {
	skipIfNoGitHub(t)

	org := getGitHubOrg()
	if org == "" {
		t.Skip("No GitHub organization configured - set E2E_GITHUB_ORG")
	}

	ctx := context.Background()
	collector := github.New().WithOrganization(org)

	require.NoError(t, collector.Init(ctx))

	result, err := collector.Collect(ctx)
	require.NoError(t, err)

	// Filter for members
	var members []evidence.Evidence
	for _, ev := range result.Evidence {
		if ev.ResourceType == "github:member" {
			members = append(members, ev)
		}
	}

	// Check if we have member collection errors (may be due to permissions)
	for _, e := range result.Errors {
		if e.Resource == "members" || e.Resource == "members-2fa" {
			t.Logf("Member collection note: %s - %s", e.Resource, e.Error)
		}
	}

	if len(members) == 0 {
		t.Log("No members collected - may require org member access")
		return
	}

	t.Logf("Collected %d organization members", len(members))

	// Validate member structure
	for _, ev := range members {
		var data map[string]interface{}
		err := json.Unmarshal(ev.Data, &data)
		require.NoError(t, err, "Should parse member data")

		assert.NotNil(t, data["login"], "Member should have login")
		assert.NotNil(t, data["organization"], "Member should have organization")

		// Log 2FA status
		if twoFA, ok := data["two_factor_enabled"]; ok {
			t.Logf("  Member: %s, 2FA: %v", data["login"], twoFA)
		} else {
			t.Logf("  Member: %s, 2FA: unknown (requires admin)", data["login"])
		}
	}
}

// TestGitHub_FullComplianceFlow tests the complete flow from collection to evaluation.
func TestGitHub_FullComplianceFlow(t *testing.T) {
	skipIfNoGitHub(t)

	ctx := context.Background()
	org := getGitHubOrg()

	// Step 1: Collect evidence
	collector := github.New()
	if org != "" {
		collector.WithOrganization(org)
	}

	require.NoError(t, collector.Init(ctx))

	result, err := collector.Collect(ctx)
	require.NoError(t, err, "Collection should succeed")

	t.Logf("Collected %d evidence items", len(result.Evidence))

	// Step 2: Load SOC2 framework and evaluate
	framework := soc2.New()
	eng := engine.New()

	policies := framework.Policies()
	require.NotEmpty(t, policies, "Framework should have policies")

	// Load only GitHub-related policies
	githubPoliciesLoaded := 0
	for _, policy := range policies {
		if strings.Contains(policy.Name, "github") {
			err := eng.LoadPolicy(policy.Name, policy.Source)
			require.NoError(t, err, "Should load policy %s", policy.Name)
			githubPoliciesLoaded++
		}
	}

	t.Logf("Loaded %d GitHub-related policies", githubPoliciesLoaded)

	if githubPoliciesLoaded == 0 {
		t.Log("No GitHub-specific policies found, skipping evaluation")
		return
	}

	// Step 3: Evaluate policies
	policyResults, err := eng.Evaluate(ctx, result.Evidence)
	require.NoError(t, err, "Evaluation should succeed")

	// Step 4: Validate results structure
	var passCount, failCount, skipCount int
	for _, pr := range policyResults {
		assert.NotEmpty(t, pr.PolicyID, "PolicyID should not be empty")

		switch pr.Status {
		case evidence.StatusPass:
			passCount++
		case evidence.StatusFail:
			failCount++
		case evidence.StatusSkip:
			skipCount++
		}

		t.Logf("Policy %s: %s - evaluated: %d, failed: %d",
			pr.PolicyID, pr.Status,
			pr.ResourcesEvaluated, pr.ResourcesFailed)
	}

	t.Logf("Summary: %d passed, %d failed, %d skipped", passCount, failCount, skipCount)
}

// TestGitHub_EvidenceHashing verifies that evidence hashes are computed correctly.
func TestGitHub_EvidenceHashing(t *testing.T) {
	skipIfNoGitHub(t)

	ctx := context.Background()
	org := getGitHubOrg()

	collector := github.New()
	if org != "" {
		collector.WithOrganization(org)
	}

	require.NoError(t, collector.Init(ctx))

	result, err := collector.Collect(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, result.Evidence)

	// Verify each evidence item has a valid hash
	for _, ev := range result.Evidence {
		assert.NotEmpty(t, ev.Hash, "Evidence should have hash: %s", ev.ResourceID)
		assert.Len(t, ev.Hash, 64, "Hash should be 64 hex chars (SHA-256): %s", ev.ResourceID)

		// Verify hash is valid hex
		for _, c := range ev.Hash {
			assert.True(t, (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
				"Hash should be lowercase hex: %s", ev.Hash)
		}
	}

	t.Logf("Verified hashes for %d evidence items", len(result.Evidence))
}

// TestGitHub_BranchProtectionEvidence tests that branch protection data is collected.
func TestGitHub_BranchProtectionEvidence(t *testing.T) {
	skipIfNoGitHub(t)

	ctx := context.Background()
	org := getGitHubOrg()

	collector := github.New()
	if org != "" {
		collector.WithOrganization(org)
	}

	require.NoError(t, collector.Init(ctx))

	result, err := collector.Collect(ctx)
	require.NoError(t, err)

	// Count repos with branch protection
	var withProtection, withoutProtection int

	for _, ev := range result.Evidence {
		if ev.ResourceType != "github:repository" {
			continue
		}

		var data map[string]interface{}
		json.Unmarshal(ev.Data, &data)

		if bp, ok := data["branch_protection"]; ok && bp != nil {
			bpMap := bp.(map[string]interface{})
			if enabled, ok := bpMap["enabled"].(bool); ok && enabled {
				withProtection++
				continue
			}
		}
		withoutProtection++
	}

	t.Logf("Repositories with branch protection: %d", withProtection)
	t.Logf("Repositories without branch protection: %d", withoutProtection)

	// Just log, don't fail - this is informational
	if withProtection == 0 && withoutProtection > 0 {
		t.Log("Note: No repositories have branch protection enabled")
	}
}
