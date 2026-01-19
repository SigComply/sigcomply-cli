# OIDC Authentication Details

> **When to read**: Working on OIDC, credentials, cloud API auth, or CI/CD authentication flows.

TraceVault uses **ephemeral OIDC tokens** for authentication in two critical areas:

## A. Authenticating CLI with TraceVault Cloud API

The CLI uses OIDC to authenticate with the TraceVault Rails backend, eliminating the need for long-lived API keys.

**How it works:**

1. **CI/CD Environment Provides OIDC Token:**
   - GitHub Actions automatically generates OIDC tokens via `permissions: id-token: write`
   - GitLab CI provides OIDC tokens via `$CI_JOB_JWT_V2`
   - These tokens are short-lived (minutes to hours)

2. **CLI Obtains Token:**
   ```go
   // The CLI retrieves the OIDC token from the CI environment
   token := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") // GitHub
   // OR
   token := os.Getenv("CI_JOB_JWT_V2") // GitLab
   ```

3. **CLI Sends Signed Attestation:**
   ```go
   // Attestation includes:
   // - Evidence hashes (CheckResult, individual evidence, combined)
   // - Environment context (CI provider, repo, branch, commit)
   // - Version info (CLIVersion, PolicyVersions)
   // - Signature (HMAC or OIDC JWT)
   // NOTE: StorageLocation is NOT signed (operational metadata)

   attestation := &attestation.Attestation{
       ID:        uuid.New().String(),
       RunID:     checkResult.RunID,
       Framework: "soc2",
       Timestamp: time.Now().UTC(),
       Hashes:    evidenceHashes, // Computed using canonical JSON
       Environment: attestation.Environment{
           CI:        true,
           Provider:  "github-actions",
           Repository: "org/repo",
       },
       CLIVersion: "1.0.0",
   }

   // Sign with OIDC token
   signer := attestation.NewOIDCSigner(oidcToken)
   signer.Sign(attestation)

   // Send to Rails API
   client.Submit(ctx, &cloud.SubmitRequest{
       CheckResult: checkResult,
       Attestation: attestation,
   })
   ```

4. **Rails API Verifies Token:**
   - Validates OIDC token signature using GitHub/GitLab's public keys
   - Extracts repository and organization information from token claims
   - Ensures the token is valid and not expired
   - Associates attestation with correct customer account

## B. Authenticating with Third-Party Services (Preferred)

**CRITICAL DESIGN DECISION:** The GitHub Actions and GitLab CI reusable workflows should **prefer OIDC authentication** when fetching data from third-party services (AWS, GCP, Azure, GitHub, etc.) instead of using long-lived API keys stored as secrets.

### Supported OIDC Integrations

1. **AWS (via IAM Roles for OIDC)**
   ```yaml
   # GitHub Actions Example
   - name: Configure AWS Credentials
     uses: aws-actions/configure-aws-credentials@v4
     with:
       role-to-assume: arn:aws:iam::123456789012:role/TraceVaultComplianceRole
       aws-region: us-east-1

   # No AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY needed!
   ```

2. **Google Cloud (via Workload Identity Federation)**
   ```yaml
   - name: Authenticate to Google Cloud
     uses: google-github-actions/auth@v2
     with:
       workload_identity_provider: 'projects/123/locations/global/...'
       service_account: 'tracevault@project.iam.gserviceaccount.com'
   ```

3. **Azure (via Workload Identity Federation)**
   ```yaml
   - name: Azure Login
     uses: azure/login@v1
     with:
       client-id: ${{ secrets.AZURE_CLIENT_ID }}
       tenant-id: ${{ secrets.AZURE_TENANT_ID }}
       subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
   ```

4. **GitHub API (using GITHUB_TOKEN)**
   ```yaml
   # GitHub Actions automatically provides GITHUB_TOKEN
   - name: Fetch GitHub Data
     env:
       GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
     run: tracevault check --integration github
   ```

### Fallback Strategy

When OIDC is not available or not configured, fall back to traditional credential methods:
- Environment variables (AWS_ACCESS_KEY_ID, GITHUB_TOKEN, etc.)
- Service account keys (for GCP, Azure)
- User provides these as repository secrets

### CLI Implementation

The CLI must detect which authentication method is available:

```go
// Example: AWS authentication detection
func (c *AWSCollector) Authenticate() error {
    // 1. Try OIDC (check for Web Identity Token)
    if os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") != "" {
        return c.authenticateWithOIDC()
    }

    // 2. Fallback to IAM role (EC2, ECS, Lambda)
    if metadata := ec2metadata.New(session.New()); metadata.Available() {
        return c.authenticateWithIAMRole()
    }

    // 3. Fallback to environment variables
    if os.Getenv("AWS_ACCESS_KEY_ID") != "" {
        return c.authenticateWithCredentials()
    }

    return errors.New("No AWS credentials found")
}
```

### Security Benefits

- **No long-lived secrets** stored in customer repositories
- **Automatic credential rotation** - tokens expire after job completion
- **Principle of least privilege** - IAM roles can be scoped per repository
- **Audit trail** - Cloud providers log which repository/workflow accessed what resources
- **Impossible to exfiltrate** - Credentials only work from authorized CI/CD context
- **Revocation at scale** - Disable OIDC trust relationship instead of rotating keys

### AWS Setup Instructions

1. Create IAM role with trust policy for GitHub Actions OIDC provider
2. Attach read-only compliance policies (CloudTrail, IAM, Config, etc.)
3. Add role ARN to workflow configuration
4. No secrets needed in repository settings!

### Implementation Notes

- Reusable workflows should attempt OIDC first, then fall back to secrets
- CLI should log which authentication method is being used (for debugging)
- Clear error messages when OIDC setup is incorrect
- Documentation should strongly recommend OIDC over long-lived credentials
