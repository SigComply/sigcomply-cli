# OIDC Authentication Details

> **When to read**: Working on OIDC, credentials, cloud API auth, or CI/CD authentication flows.

SigComply uses **ephemeral OIDC tokens** for authentication in two critical areas:

## A. Authenticating CLI with SigComply Cloud API

The CLI uses OIDC tokens **for authentication only** — to prove to the SigComply Rails backend which CI run is submitting results, without needing long-lived API keys.

**Important distinction:**
- **OIDC token** → HTTP `Authorization: Bearer` header (authentication with Cloud API)
- **Ephemeral Ed25519 keypair** → attestation `Signature` field (evidence integrity, stored in customer S3)

These are two entirely separate concerns. OIDC is never used to sign attestations.

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

3. **CLI Signs Each Evidence File with Ephemeral Ed25519 and Submits Aggregated Results:**
   ```go
   // For each evidence file, a fresh EvidenceEnvelope is created and signed.
   // A new ephemeral Ed25519 keypair is generated per file — private key is
   // discarded immediately after signing. The public key and signature travel
   // inside the file itself (EvidenceEnvelope), so each file is independently
   // verifiable without any other artifact.
   envelope := attestation.NewEvidenceEnvelope(collectionTimestamp, rawEvidenceJSON)

   signer, _ := attestation.NewEd25519Signer()
   signer.Sign(envelope) // Sets envelope.PublicKey + envelope.Signature; private key zeroed
   // envelope is written to: {framework}/{policy_slug}/{timestamp}_{run_id}/evidence/{type}.json

   // Only aggregated results (counts, not resource IDs) go to the Cloud API.
   // OIDC token is used in the Authorization header for authentication.
   client.Submit(ctx, &cloud.SubmitRequest{
       RunID:         checkResult.RunID,
       Framework:     "soc2",
       PolicyResults: aggregated, // counts only, no ARNs, no usernames
       Summary:       summary,
   })
   ```

4. **Rails API Validates the OIDC Token:**
   - Validates OIDC token (in `Authorization` header) using GitHub/GitLab's public JWKS
   - Extracts repository and organization from OIDC claims to identify the customer account
   - Stores only the aggregated policy counts (pass/fail + resource counts)
   - Never receives the attestation or any resource identifiers

5. **Auditor Verifies Evidence Out-of-Band:**
   - Auditor requests specific evidence files directly from the customer
   - Each evidence file is a self-contained `EvidenceEnvelope` — it contains the raw evidence,
     a timestamp, the Ed25519 public key, and the signature, all in one JSON file
   - Auditor verifies the signature using the public key embedded inside the same file
   - No separate `attestation.json` or manifest needed; no SigComply involvement required

## B. Authenticating with Third-Party Services (Preferred)

**CRITICAL DESIGN DECISION:** The GitHub Actions and GitLab CI reusable workflows should **prefer OIDC authentication** when fetching data from third-party services (AWS, GCP, Azure, GitHub, etc.) instead of using long-lived API keys stored as secrets.

### Supported OIDC Integrations

1. **AWS (via IAM Roles for OIDC)**
   ```yaml
   # GitHub Actions Example
   - name: Configure AWS Credentials
     uses: aws-actions/configure-aws-credentials@v4
     with:
       role-to-assume: arn:aws:iam::123456789012:role/SigComplyComplianceRole
       aws-region: us-east-1

   # No AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY needed!
   ```

2. **Google Cloud (via Workload Identity Federation)**
   ```yaml
   - name: Authenticate to Google Cloud
     uses: google-github-actions/auth@v2
     with:
       workload_identity_provider: 'projects/123/locations/global/...'
       service_account: 'sigcomply@project.iam.gserviceaccount.com'
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
     run: sigcomply check --integration github
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
