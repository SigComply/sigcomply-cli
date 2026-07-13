# OIDC Authentication Details

> **When to read**: Working on OIDC, credentials, cloud API auth, or CI/CD authentication flows.

SigComply uses **ephemeral OIDC tokens** for authentication in two critical areas:

## A. Authenticating CLI with SigComply Cloud API

The CLI uses OIDC tokens **for authentication only** — to prove to the SigComply Rails backend which CI run is submitting results, without needing long-lived API keys.

**Important distinction:**
- **OIDC token** → HTTP `Authorization: Bearer` header (authentication with Cloud API)
- **Ephemeral Ed25519 keypair** → `EvidenceEnvelope.signature` field (evidence integrity, stored in customer storage)

These are two entirely separate concerns. OIDC is never used to sign evidence.

**How it works:**

1. **CI/CD Environment Provides OIDC Token:**
   - GitHub Actions automatically generates OIDC tokens via `permissions: id-token: write`
   - GitLab CI exposes an OIDC token as an env var via the `.gitlab-ci.yml`
     `id_tokens:` block (the CLI reads `SIGCOMPLY_ID_TOKEN`, falling back to
     `ID_TOKEN`)
   - These tokens are short-lived (minutes to hours)

2. **CLI Obtains Token** (`internal/submitter/submitter.go` — provider types
   are unexported and implement
   `Token(ctx, audience) (token, providerName string, err error)`):
   ```go
   // GitHub Actions: the two ACTIONS_ID_TOKEN_REQUEST_* env vars are NOT
   // the OIDC token themselves — they are the URL + bearer token used to
   // fetch the real OIDC JWT from GitHub's token service.
   requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
   requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

   req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
       requestURL+"?audience="+audience, http.NoBody)
   req.Header.Set("Authorization", "Bearer "+requestToken)
   req.Header.Set("Accept", "application/json")
   resp, _ := httpClient.Do(req)
   // resp body is { "value": "<the actual OIDC JWT>" }
   var parsed struct{ Value string `json:"value"` }
   _ = json.NewDecoder(resp.Body).Decode(&parsed)
   token := parsed.Value // GitHub

   // GitLab CI: the OIDC JWT is provided directly as an env var,
   // no HTTP fetch required. The .gitlab-ci.yml id_tokens: block populates it.
   token = os.Getenv("SIGCOMPLY_ID_TOKEN") // GitLab (fallback: ID_TOKEN)
   ```

3. **CLI Signs Each Evidence File with Ephemeral Ed25519 and Submits Aggregated Results:**
   ```go
   // For each evidence file, a fresh core.Envelope is signed. A new ephemeral
   // Ed25519 keypair is generated per file — the private key is discarded
   // immediately after signing. The public key and signature travel inside
   // the envelope itself (core.Envelope.Signature), so each file is
   // independently verifiable without any other artifact. Signing covers the
   // canonical JSON of the content fields, NOT a SHA-256 hash.
   // See internal/sign/envelope.go.
   env := &core.Envelope{ProducedAt: collectionTime, Records: records}
   if err := sign.Envelope(env); err != nil { /* ... */ } // sets env.Signature
   blob, _ := sign.EncodeEnvelope(env)
   // verification later: sign.VerifyEnvelope(env)

   // Only aggregated results (counts, not resource IDs) go to the Cloud API.
   // internal/submitter POSTs a core.SubmissionPayload (schema
   // sigcomply.cloud.v3) to /api/v1/runs with the OIDC token in the
   // Authorization header and an X-OIDC-Provider: github|gitlab header
   // telling Rails which JWKS/claim set to validate against. The payload is
   // structurally counts-only — no map[string]any, no Violations slice.
   ```

4. **Rails API Validates the OIDC Token:**
   - Validates OIDC token (in `Authorization` header) using GitHub/GitLab's public JWKS
   - Extracts the project identity from provider-specific OIDC claims — `repository` / `repository_owner` (GitHub) or `project_path` / `namespace_path` (GitLab) — to identify the customer account
   - Stores only the aggregated policy counts (pass/fail + resource counts)
   - Never receives any envelope or any resource identifiers

5. **Auditor Verifies Evidence Out-of-Band:**
   - Auditor requests specific evidence files directly from the customer
   - Each evidence file is a self-contained `core.Envelope` — it contains the
     records, a `produced_at` timestamp, the Ed25519 public key, and the
     signature, all in one JSON file
   - Auditor verifies the signature with `sign.VerifyEnvelope` using the public
     key embedded inside the same file
   - Whole-run integrity is covered separately by the signed `manifest.json`
     (`sign.VerifyManifest`); no SigComply involvement is required

## B. Authenticating with Third-Party Services (Preferred)

**CRITICAL DESIGN DECISION:** The CI workflow you run `sigcomply check` in
should **prefer OIDC authentication** when granting the CLI access to
third-party services (AWS, GCP, Azure, GitHub, etc.) instead of using
long-lived API keys stored as secrets.

> The CLI itself does **not** exchange OIDC tokens for cloud credentials. Its
> source collectors read whatever the ambient SDK credential chain provides
> (env vars, IAM role, instance metadata, GCP ADC, Azure
> `DefaultAzureCredential`). The OIDC→credential exchange below happens in the
> CI workflow YAML via the standard provider actions, *before* `sigcomply
> check` runs — the CLI does not perform `AssumeRoleWithWebIdentity`, GCP
> Workload Identity Federation, or Azure WIF on its own.

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
     run: sigcomply check   # org comes from sources.github.org in .sigcomply.yaml
   ```

### Fallback Strategy

When OIDC is not available or not configured, fall back to traditional credential methods:
- Environment variables (AWS_ACCESS_KEY_ID, GITHUB_TOKEN, etc.)
- Service account keys (for GCP, Azure)
- User provides these as repository secrets

### How the CLI sees these credentials

The CLI does not implement its own credential-detection ladder. Each source
plugin's `Init` builds a vendor SDK client using that SDK's default credential
chain, which already prefers OIDC/web-identity, then instance/role credentials,
then static env vars — in that order. So once the CI workflow has run the
provider action above (or exported the relevant env vars), the AWS/GCP/Azure
collectors pick the credentials up automatically with no SigComply-specific
configuration.

The pseudo-ladder below is **illustrative of what the underlying SDK does** —
it is not code in this repo:

```text
# What the ambient SDK credential chain resolves, in order:
1. OIDC / web identity   (AWS_WEB_IDENTITY_TOKEN_FILE, GCP WIF, Azure federated cred)
2. Instance / role       (EC2/ECS/Lambda role, GCP ADC, Azure managed identity)
3. Static env vars       (AWS_ACCESS_KEY_ID, GITHUB_TOKEN, GCP key file, ...)
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

- CI workflows should set up OIDC-based credentials first, falling back to
  secrets only where OIDC isn't available
- Credential resolution is delegated to each provider SDK's default chain; the
  CLI does not branch on auth method itself
- Source plugins surface clear errors when no usable credentials are found
- Documentation should strongly recommend OIDC over long-lived credentials
