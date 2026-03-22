# Attestation Signing & Verification — Design Idea

> **Status**: Idea / not implemented. Current implementation uses HMAC-SHA256 with `SIGCOMPLY_SIGNING_SECRET`.
> Come back to this when ready to implement zero-secret signing.

---

## The Problem with the Current Approach

The current implementation requires a `SIGCOMPLY_SIGNING_SECRET` environment variable — a long-lived shared secret that must be:
- Distributed to every customer
- Stored as a CI/CD secret in every customer repo
- Rotated if compromised

This conflicts with SigComply's zero-trust, zero-config philosophy.

---

## The Idea: Derive the HMAC Key from OIDC Token Claims

Instead of a pre-shared secret, derive the HMAC signing key from the OIDC token claims that are already present during every CI run.

```
key = f(commit_sha, repo, run_id)

e.g. key = HMAC-SHA256(commit_sha + ":" + repo + ":" + ci_run_id, oidc_issuer)
```

The key is:
- **Ephemeral** — exists only during the CI job, derived on the fly
- **Unique** to that specific run (commit + repo + run ID combination)
- **Not secret** — deterministically derivable from CI context data
- **Not requiring distribution** — no env var, no customer configuration

---

## Why "Not Secret" is Fine Here

The HMAC key doesn't need to be secret because the security comes from the OIDC JWT itself, not from key secrecy.

The OIDC JWT is signed by GitHub/GitLab with their private key. It can only be obtained during an actual CI job execution. You **cannot retroactively obtain an OIDC token for a past run** — so even though the key derivation formula is public, a forger cannot produce a valid HMAC for a past run without having been the actual CI job at that time.

---

## What Each Piece Proves

| Mechanism | Proves |
|-----------|--------|
| OIDC JWT (signed by GitHub/GitLab) | A real CI run happened for this repo/commit/run-id |
| HMAC over evidence hashes | The hashes were produced by whoever held the OIDC token at that time |
| SHA-256 hash comparison | The evidence files in storage match the hashes in the attestation |

The OIDC JWT and HMAC together prove: **these specific hashes were produced during this specific CI run, and have not been modified since.**

Without the HMAC, someone with S3 write access could take a valid JWT from a real run and swap the evidence hashes. The HMAC prevents this by binding the hashes to the run.

---

## Full Trust Chain — Zero Secrets

```
CLI (at run time):
  1. Gets OIDC JWT from GitHub Actions / GitLab CI
  2. Extracts claims: commit_sha, repo, run_id
  3. Derives signing key from those claims
  4. Signs attestation payload: HMAC-SHA256(payload, derived_key)
  5. Stores OIDC JWT in/alongside the attestation (in S3)
  6. Submits to Rails API:
       Authorization: Bearer <oidc_jwt>     ← authentication
       Body: { attestation: { signature: <hmac> }, ... }

Rails (at receive time):
  1. Verifies OIDC JWT via GitHub/GitLab public JWKS → trusts the request
  2. Stores OIDC claims alongside attestation record
  3. HMAC re-verification is optional here — OIDC already establishes trust

Auditor (months later):
  1. Downloads attestation.json from customer S3
  2. Extracts the OIDC JWT stored in the attestation
  3. Verifies JWT signature against GitHub/GitLab public JWKS (no secret needed)
  4. Extracts claims from verified JWT
  5. Re-derives signing key from claims (public formula)
  6. Verifies HMAC → confirms hashes haven't been tampered with
  7. Downloads evidence files from S3, hashes them, compares to attestation hashes
```

**The auditor needs no private key, no shared secret, no access to SigComply systems** (beyond fetching the OIDC JWT if not embedded in the attestation).

---

## Changes Required to Implement

### CLI (`sigcomply-cli`)

1. **Remove `SIGCOMPLY_SIGNING_SECRET`** from config and documentation
2. **Key derivation function** — new function in `internal/core/attestation/`:
   ```go
   func DeriveSigningKey(commitSHA, repo, runID, issuer string) []byte {
       input := commitSHA + ":" + repo + ":" + runID
       mac := hmac.New(sha256.New, []byte(issuer))
       mac.Write([]byte(input))
       return mac.Sum(nil)
   }
   ```
3. **Store OIDC JWT in attestation** — embed the raw JWT in the attestation so auditors can independently verify without needing Rails:
   ```go
   type Attestation struct {
       // ... existing fields ...
       OIDCToken string `json:"oidc_token,omitempty"` // Raw JWT for independent verification
   }
   ```
4. **Wire up in `cloud_submit.go`** — obtain OIDC token, derive key, sign before submitting

### Rails (`sigcomply`)

1. **Store OIDC claims** when receiving a run submission (already has the JWT for auth — just persist the claims)
2. **Expose claims via auditor API** — endpoint for auditors to fetch OIDC claims for a given run, enabling independent verification
3. **Auditor portal** — update verification flow to re-derive key from claims and verify HMAC

---

## Open Questions

- **Key derivation formula** — exact inputs and HMAC construction to agree on between CLI and Rails
- **JWT storage** — embed JWT directly in `attestation.json` (stored in S3), or rely on Rails to provide it? Embedding is more trustless but increases file size
- **OIDC token expiry** — JWTs expire (typically 1 hour). Auditors verifying months later need GitHub/GitLab to still serve valid JWKS public keys (they do — JWKS endpoints are long-lived). The JWT signature is still verifiable after expiry; expiry only matters for authentication use, not for signature verification.
- **GitLab OIDC** — GitLab's `CI_JOB_JWT_V2` is being deprecated in favour of ID tokens. Need to confirm the replacement and update the provider detection accordingly.
