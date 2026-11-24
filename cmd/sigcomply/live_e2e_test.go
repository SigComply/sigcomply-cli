//go:build live

package cmd

// Live E2E tier. Each test runs the sigcomply binary, as a process, against
// a real cloud or SaaS account, writes the vault to that provider's real
// storage, and reads the vault back to verify it. They are the only tests
// that send the release candidate's real requests to AWS, GCP and Azure.
//
// A test skips unless its provider's variables are set. With
// LIVE_E2E_REQUIRED=1 (set by .github/workflows/live-e2e.yml) a missing
// variable fails the test instead, so a release can never be promoted on a
// silent skip. SIGCOMPLY_E2E_BINARY names the binary to test (the release
// workflow installs the published asset); without it the test builds one
// from this checkout, unless LIVE_E2E_REQUIRED=1.
//
// The accounts are permanent fixtures: nothing is created or deleted here
// except the run's own vault folder, which the bucket's lifecycle rule
// expires. Setup, variables and the per-source requirements:
// docs/claude/live-e2e.md.
//
// The harness (runLiveE2E and its checks) is in live_e2e_harness_test.go,
// untagged so its self-tests run on every push.

import (
	"os"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// Committed source allowlists: every source of the provider that works in
// a cheap permanent fixture account. Sources that need something the
// fixture account may not have are added by liveProvider.extras when their
// variable is set. docs/claude/live-e2e.md lists what each one needs.
var (
	liveAWSSources = []string{
		"aws.acm", "aws.backup", "aws.cloudtrail", "aws.cloudwatch", "aws.config",
		"aws.dynamodb", "aws.ec2", "aws.ecr", "aws.eks", "aws.guardduty", "aws.iam",
		"aws.iam_access_key", "aws.kms", "aws.lambda", "aws.password_policy", "aws.rds",
		"aws.s3", "aws.secretsmanager", "aws.security_alert", "aws.security_group",
		"aws.security_services", "aws.vpc",
	}
	liveGCPSources = []string{
		"gcp.artifactregistry", "gcp.asset", "gcp.audit", "gcp.backup", "gcp.certs",
		"gcp.compute", "gcp.firestore", "gcp.firewall", "gcp.gke", "gcp.iam", "gcp.kms",
		"gcp.logging", "gcp.network", "gcp.secretmanager", "gcp.sql", "gcp.storage",
	}
	liveAzureSources = []string{
		"azure.acr", "azure.aks", "azure.backup", "azure.certs", "azure.compute",
		"azure.cosmos", "azure.defender", "azure.keyvault", "azure.monitor",
		"azure.network", "azure.policy", "azure.sql", "azure.storage",
	}
)

func TestLiveE2E_AWS(t *testing.T) {
	runLiveE2E(t, liveProvider{
		required: []string{"LIVE_E2E_AWS_REGION", "LIVE_E2E_AWS_VAULT_BUCKET"},
		sources: func(env map[string]string) []liveSource {
			return sameConfig(liveAWSSources, map[string]string{"region": env["LIVE_E2E_AWS_REGION"]})
		},
		extras: func() []liveSource {
			region := os.Getenv("LIVE_E2E_AWS_REGION")
			var out []liveSource
			if id := os.Getenv("LIVE_E2E_AWS_IDENTITY_STORE_ID"); id != "" {
				out = append(out, liveSource{"aws.identity_center", map[string]string{"region": region, "identity_store_id": id}})
			}
			if os.Getenv("LIVE_E2E_AWS_INSPECTOR") == "on" {
				out = append(out, liveSource{"aws.inspector", map[string]string{"region": region}})
			}
			return out
		},
		vault: func(env map[string]string, prefix string) spec.VaultConfig {
			return spec.VaultConfig{Backend: "s3", Config: map[string]any{
				"bucket": env["LIVE_E2E_AWS_VAULT_BUCKET"], "region": env["LIVE_E2E_AWS_REGION"], "prefix": prefix,
			}}
		},
	})
}

func TestLiveE2E_GCP(t *testing.T) {
	runLiveE2E(t, liveProvider{
		required: []string{"LIVE_E2E_GCP_PROJECT_ID", "LIVE_E2E_GCP_VAULT_BUCKET"},
		sources: func(env map[string]string) []liveSource {
			return sameConfig(liveGCPSources, map[string]string{"project_id": env["LIVE_E2E_GCP_PROJECT_ID"]})
		},
		extras: func() []liveSource {
			var out []liveSource
			if org := os.Getenv("LIVE_E2E_GCP_ORGANIZATION_ID"); org != "" {
				out = append(out, liveSource{"gcp.scc", map[string]string{"organization_id": org}})
			}
			sa, admin := os.Getenv("LIVE_E2E_GCP_WORKSPACE_SERVICE_ACCOUNT"), os.Getenv("LIVE_E2E_GCP_WORKSPACE_ADMIN")
			if sa != "" && admin != "" {
				ws := map[string]string{"target_service_account": sa, "impersonate_subject": admin}
				out = append(out, liveSource{"gcp.directory", ws}, liveSource{"gcp.cloud_identity", ws})
			}
			return out
		},
		vault: func(env map[string]string, prefix string) spec.VaultConfig {
			return spec.VaultConfig{Backend: "gcs", Config: map[string]any{
				"bucket": env["LIVE_E2E_GCP_VAULT_BUCKET"], "prefix": prefix,
			}}
		},
	})
}

func TestLiveE2E_Azure(t *testing.T) {
	runLiveE2E(t, liveProvider{
		required: []string{"LIVE_E2E_AZURE_SUBSCRIPTION_ID", "LIVE_E2E_AZURE_STORAGE_ACCOUNT", "LIVE_E2E_AZURE_VAULT_CONTAINER"},
		sources: func(env map[string]string) []liveSource {
			return sameConfig(liveAzureSources, map[string]string{"subscription_id": env["LIVE_E2E_AZURE_SUBSCRIPTION_ID"]})
		},
		vault: func(env map[string]string, prefix string) spec.VaultConfig {
			return spec.VaultConfig{Backend: "azure_blob", Config: map[string]any{
				"account": env["LIVE_E2E_AZURE_STORAGE_ACCOUNT"], "container": env["LIVE_E2E_AZURE_VAULT_CONTAINER"], "prefix": prefix,
			}}
		},
	})
}

// TestLiveE2E_SaaS reuses the variables of the per-source live tests.
// Entra reads AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET
// through the Azure default credential chain. SaaS has no storage of its
// own, so the vault is local.
func TestLiveE2E_SaaS(t *testing.T) {
	runLiveE2E(t, liveProvider{
		required: []string{
			"GITHUB_TEST_TOKEN", "GITHUB_TEST_ORG", "GITLAB_TEST_TOKEN", "GITLAB_TEST_GROUP",
			"OKTA_TEST_TOKEN", "OKTA_TEST_ORG_URL", "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
		},
		sources: func(env map[string]string) []liveSource {
			gitlab := map[string]string{"group": env["GITLAB_TEST_GROUP"], "token_env": "GITLAB_TEST_TOKEN"}
			if base := os.Getenv("GITLAB_TEST_BASE_URL"); base != "" {
				gitlab["base_url"] = base
			}
			return []liveSource{
				{"github", map[string]string{"org": env["GITHUB_TEST_ORG"], "token_env": "GITHUB_TEST_TOKEN"}},
				{"gitlab", gitlab},
				{"okta", map[string]string{"org_url": env["OKTA_TEST_ORG_URL"], "token_env": "OKTA_TEST_TOKEN"}},
				{"azure.entra", map[string]string{"tenant_id": env["AZURE_TENANT_ID"]}},
			}
		},
	})
}
