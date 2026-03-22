# Attestation Signing & Verification — Design Idea

> **Status**: Idea / not implemented. Current implementation uses HMAC-SHA256 with `SIGCOMPLY_SIGNING_SECRET`.
> Come back to this when ready to implement zero-secret signing.

---

## Problem with the Current Approach

`SIGCOMPLY_SIGNING_SECRET` is a long-lived shared secret that must be distributed to every customer, stored as a CI/CD secret, and rotated if compromised. This conflicts with SigComply's zero-trust philosophy.

---

## Design Thinking — Q&A Summary

This section documents the key questions and conclusions reached when designing the replacement.

---

### Q: Can we derive the HMAC signing key from OIDC token claims instead of a pre-shared secret?

**No.** The HMAC key derived from public OIDC claims (commit SHA, repo, run ID) is publicly derivable by anyone who has the OIDC JWT. An attacker with S3 write access can:
1. Read the JWT stored in `attestation.json`
2. Derive the same key using the public formula
3. Tamper with evidence hashes and recompute a valid HMAC

The HMAC verification is security theatre. The auditor re-verifying the HMAC adds no value because anyone can produce a valid HMAC for tampered data.

---

### Q: Should signing use a shared key (HMAC) or asymmetric keys?

**Asymmetric.** With HMAC (shared key), the auditor needs the secret key to verify — meaning the auditor can also forge signatures. There is no meaningful signing.

With asymmetric signing (Ed25519): the private key signs, the public key verifies. The auditor only needs the public key, which can be published openly. The signer's private key never needs to leave them.

---

### Q: Should SigComply hold one private key and sign all customer attestations?

**No.** SigComply is an open-source CLI used by many customers across many projects. If SigComply signs everything with one private key, auditors are trusting SigComply — not the customer's pipeline. This makes SigComply a trusted intermediary, violating zero-trust.

The signing identity must belong to the customer's pipeline, not SigComply.

---

### Q: What if the CLI generates a fresh ephemeral keypair for every single run? No key management, private key discarded immediately.

**Correct approach, but incomplete on its own.** The ephemeral keypair generation is trivial (`ed25519.GenerateKey()`). The hard part is: what proves to the auditor that the public key stored in the attestation came from a legitimate CI run and not from an attacker who generated their own keypair?

Anyone can generate a keypair. Without anchoring the public key to something unforgeable, the tamper-then-resign attack still works:
1. Attacker tampers with evidence
2. Generates their own fresh keypair
3. Signs tampered hashes with new private key
4. Replaces `public_key` + `signature` in `attestation.json` on S3
5. Auditor verifies — passes

---

### Q: Can we store just the public key in Rails (not the full attestation) to prevent tampering?

**Partially.** If the CLI registers the public key with Rails at submission time (authenticated via OIDC), Rails holds an immutable record of the public key from the legitimate CI run. An attacker substituting their own keypair on S3 is detected because their public key doesn't match what Rails recorded.

But this is not sufficient if the customer modifies the CLI to retain the private key (see below).

---

### Q: What if the customer modifies the open-source CLI to retain the private key instead of discarding it?

**This is a real attack.** A modified CLI that retains the private key allows:
1. Modified CLI runs, signs evidence, retains private key
2. Public key is registered in Rails (looks legitimate — real OIDC auth)
3. Customer tampers with evidence, re-hashes → new hashes
4. Re-signs new hashes with retained private key → new signature
5. Replaces `attestation.json` on S3: `{ new_hashes, same_public_key, new_signature }`

Auditor verifies: public key matches Rails ✓, signature valid ✓, evidence matches hashes ✓. **Attack succeeds.**

**Defence: store evidence hashes in Rails too.** Rails records `{ public_key, evidence_hashes }` at submission time — write-once, immutable. The customer cannot update the hashes in Rails after the run. Auditor compares S3 hashes against Rails hashes → mismatch detected.

---

### Q: Is Sigstore/Fulcio/Rekor useful for SigComply?

**Conceptually yes, but as a platform — no.** Sigstore solves the identical cryptographic problem: ephemeral keypairs, OIDC-based identity binding, tamper-evident log. However:

- Sigstore tools (cosign, Fulcio, Rekor) are designed for software supply chain security, not compliance evidence
- SOC 2 auditors are not DevSecOps engineers — Sigstore tooling and terminology won't map to compliance workflows
- Compliance frameworks have specific retention requirements (often 7 years) that Sigstore's operational model isn't designed for

**Right approach**: implement the same cryptographic patterns using Go stdlib (`crypto/ed25519`, `crypto/x509`) with SigComply-specific tooling and compliance-oriented language.

---

### Q: Do we need to self-host private Rekor and Fulcio instances?

**No.** Hosting Rekor and Fulcio brings operational complexity without fitting the compliance use case. SigComply only needs:

- **Instead of Fulcio** — a simple certificate authority endpoint in Rails: receives an OIDC JWT + ephemeral public key, issues a short-lived X.509 cert binding the public key to the OIDC identity (~100-200 lines using Go stdlib `crypto/x509`)
- **Instead of Rekor** — a simple append-only table in the existing Rails PostgreSQL database (insert-only policy, no UPDATE or DELETE)

No new infrastructure. One new Rails controller and one new table.

---

### Q: Can customers use Fulcio to avoid storing attestations in Rails — store everything on their own S3?

**Yes, with Fulcio this becomes possible.** The Fulcio certificate cryptographically binds `{ ephemeral public key ↔ OIDC identity (repo, commit SHA, run ID) }`. The tamper-then-resign attack is impossible because getting a Fulcio certificate for a new keypair requires a valid OIDC JWT for that run — and OIDC tokens expire within an hour of the run completing.

Full customer-side storage flow:
```
CI run:
  1. CLI generates ephemeral keypair
  2. CLI presents OIDC JWT to SigComply's CA endpoint → receives cert
     binding { public_key ↔ repo, commit_sha, run_id }
  3. CLI hashes evidence files
  4. CLI signs hashes with private key → discards private key
  5. attestation.json stored on customer S3:
     { hashes, signature, cert }

Auditor:
  1. Downloads attestation.json from customer S3
  2. Verifies cert against SigComply's CA root cert (published once, fixed)
  3. Extracts public key, verifies OIDC claims in cert
  4. Verifies signature over hashes
  5. Hashes evidence files, compares
```

No Rails storage needed for tamper detection. Rails focuses on compliance scores, policy results, and the dashboard.

---

### Q: Does the modified-CLI attack still work with the Fulcio-based design?

**Yes — a retained private key can still re-sign tampered evidence.** The Fulcio cert is valid for the keypair regardless of whether the private key was discarded or retained.

**Defence: keep the append-only Rails evidence log.** Rails records the original hashes at submission time. A customer who retains the private key and re-signs tampered hashes produces a valid signature — but the hashes on S3 no longer match what Rails recorded. Tamper detected.

---

### Q: Can we use `job_workflow_sha` from the GitHub/GitLab OIDC JWT to prove the CLI wasn't tampered with?

**Yes for GitHub, no for GitLab.**

**GitHub Actions** includes two claims that prove which reusable workflow ran:
- `job_workflow_ref` — ref path to the called reusable workflow (e.g., `SigComply/sigcomply-cli/.github/workflows/check.yml@refs/tags/v1.2.3`)
- `job_workflow_sha` — resolved commit SHA of the reusable workflow file at execution time

These are set by GitHub (not the CLI), cryptographically signed in the OIDC JWT, and unforgeable. They prove which exact version of SigComply's reusable workflow ran. SigComply's reusable workflow controls which CLI binary is downloaded and its hash is verified before execution — so `job_workflow_sha` indirectly proves the CLI binary was unmodified.

**GitLab CI** provides `ci_config_ref_uri` and `ci_config_sha` — but these only track the customer's top-level `.gitlab-ci.yml`. There is no equivalent claim for CI catalog components or cross-project includes. If a job uses `include: component: gitlab.com/sigcomply/sigcomply-cli/...`, that component's identity and SHA do not appear anywhere in the OIDC token.

---

### Q: If Rails implements the CA and also stores the public key, can that prevent tampering even on GitLab?

**Yes — for all retroactive tampering attacks, on both platforms.**

When Rails acts as both the certificate authority and the evidence log, it holds at run time (authenticated via OIDC, write-once):

```
{ run_id, public_key, evidence_hashes }
```

This closes both attack vectors regardless of platform:

**New keypair attack** — attacker generates a fresh keypair after the run:
- Needs a cert for the new public key from Rails CA
- Rails CA requires a valid OIDC token for that run
- OIDC token expired → cert denied → attack blocked

**Retained private key attack** — customer's modified CLI kept the private key:
- Customer re-signs tampered hashes with retained private key
- Same public key → cert still valid → signature verifies
- But Rails evidence log has the original hashes
- Auditor compares: tampered hashes ≠ Rails original hashes → detected

Rails enforces one cert per `run_id` (the job/pipeline ID from the OIDC token). Any attempt to register a different key for the same run is rejected. Both GitLab's `job_id` and GitHub's `run_id` are present in their respective OIDC tokens, so this enforcement works identically on both platforms.

The GitLab gap (`job_workflow_sha` missing) only matters for one threat: a customer submitting **fabricated evidence from the very start** using a modified CLI. This is initial fraud — out of scope for all compliance tools that don't have direct infrastructure access (see boundary table below).

---

### Q: If Rails only implements the CA endpoint (no evidence log, no stored public keys), can that alone prevent evidence tampering after evidence creation?

**Yes — if the private key is honestly discarded. No — if the CLI is modified to retain it.**

The CA's sole role is ensuring nobody can obtain signing capability for a past run after the fact. If the private key is discarded and the OIDC token has expired, no valid signature can be produced for tampered evidence:

```
Private key discarded after signing
    +
OIDC token expired → can't get new cert for a new keypair
    ↓
Nobody has any signing capability after the run
    ↓
Attacker tampers with evidence → needs a valid signature → has none
→ Tamper detected
```

If the customer modifies the CLI to retain the private key, the CA alone is insufficient — the cert was already issued during the run and remains valid for that keypair. The evidence log is the only defence in that case.

| Assumption | CA alone sufficient? |
|---|---|
| CLI is unmodified, private key genuinely discarded | **Yes** |
| CLI modified to retain private key | **No** — evidence log also required |

The CA alone is a complete defence for honest customers. The evidence log is an additional layer specifically against a customer who deliberately modifies the open-source CLI — a more adversarial threat model. Whether to include the evidence log is a product decision about which threat model SigComply wants to defend against.

---

## Final Design

### Full Flow

```
CI run (both platforms):
  1. CLI generates ephemeral Ed25519 keypair (Go stdlib)
  2. CLI authenticates to Rails with OIDC JWT (existing flow)
  3. CLI posts ephemeral public key to Rails CA endpoint
     → Rails verifies OIDC JWT
     → Rails enforces one cert per run_id (rejects duplicate registrations)
     → Rails issues short-lived X.509 cert binding public key to OIDC claims
       (includes job_workflow_sha on GitHub — not available on GitLab)
     → Rails stores { run_id, public_key } — write-once
  4. CLI hashes evidence files
  5. CLI signs hashes with private key → discards private key immediately
  6. CLI posts { cert_id, evidence_hashes } to Rails evidence log
     → Rails stores { run_id, cert_id, hashes } — write-once, never modifiable
  7. attestation.json stored on customer S3:
     { hashes, signature, cert }

Auditor verification:
  1. Downloads attestation.json from customer S3
  2. Fetches SigComply CA root cert (published once, fixed)
  3. Verifies cert → extracts public key + OIDC claims
  4. (GitHub only) Verifies job_workflow_sha matches official SigComply workflow version
  5. Verifies signature over evidence hashes
  6. Fetches Rails evidence log entry → compares hashes (detects retained-key attack)
  7. Hashes evidence files from S3, compares
```

### What Rails Stores

```sql
-- Certificate authority: one cert per run, enforced by unique constraint
CREATE TABLE run_certificates (
  id          bigserial PRIMARY KEY,
  run_id      text NOT NULL UNIQUE,  -- enforces one cert per run
  public_key  text NOT NULL,
  oidc_claims jsonb NOT NULL,
  cert        text NOT NULL,
  inserted_at timestamptz DEFAULT now()
);
REVOKE UPDATE, DELETE ON run_certificates FROM app_user;

-- Evidence log: write-once hash anchor
CREATE TABLE evidence_logs (
  id          bigserial PRIMARY KEY,
  run_id      text NOT NULL UNIQUE,  -- enforces one submission per run
  cert_id     bigint NOT NULL REFERENCES run_certificates(id),
  hashes      jsonb NOT NULL,
  inserted_at timestamptz DEFAULT now()
);
REVOKE UPDATE, DELETE ON evidence_logs FROM app_user;
```

### What Each Component Proves

| Component | Proves |
|---|---|
| Ephemeral Ed25519 keypair | Signature is unique to this run — private key cannot be reused after discard |
| Rails CA (X.509 cert, one per run) | This public key was the one registered for this OIDC run — no substitution possible |
| `job_workflow_sha` in cert (GitHub only) | SigComply's official, unmodified reusable workflow ran |
| Rails evidence log (write-once) | These specific hashes were submitted at run time — retained-key re-signing detected |
| Evidence file hash comparison | Files in S3 match the hashes in the attestation |

### Boundary of What This Prevents

| Attack | GitHub | GitLab |
|---|---|---|
| Tamper evidence + substitute new keypair | Blocked — can't get cert for past run (OIDC expired) | Blocked — same reason |
| Tamper evidence + use retained private key | Blocked — Rails evidence log has original hashes | Blocked — same reason |
| Modified CLI submitting fake data from start | Blocked — `job_workflow_sha` proves official workflow ran | **Not blocked** — OIDC has no CI component claim |

Initial fraud — a customer fabricating compliance evidence from the very beginning using a modified CLI — cannot be prevented on GitLab while maintaining zero-trust. This is the same limitation as every compliance tool (Vanta, Drata, Secureframe): they all rely on the data source being genuine. The difference is they hide it behind their own direct infrastructure access. SigComply's value is an independently verifiable tamper-evident audit trail for genuine evidence.

### Implementation Notes

- **No Sigstore tools** — implement using Go stdlib (`crypto/ed25519`, `crypto/x509`)
- **No Rekor** — the append-only Rails tables are sufficient at SigComply's scale
- **No Fulcio** — Rails CA endpoint replaces it with compliance-specific terminology and enforcement (one cert per run)
- **Customer setup**: zero additional configuration — CLI comes pre-configured with SigComply's endpoints, same as today
- **OIDC token audiences remain separate** — Rails CA endpoint uses one audience, Rails API uses another; SigComply's existing OIDC detection logic handles both fetches
