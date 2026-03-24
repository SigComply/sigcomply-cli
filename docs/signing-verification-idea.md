# Attestation Signing & Verification — Design Decision

> **Status**: Design decided. Implementation pending.
> See [ARCHITECTURE.md - Signing Method](../ARCHITECTURE.md#signing-method) for the final design.

---

## Final Design

### Approach: Ephemeral Ed25519, Everything in Customer S3

The CLI generates a fresh Ed25519 keypair for every run. The private key is discarded immediately after signing. The public key, signature, and raw evidence are all stored together in the customer's S3 bucket. The SigComply Rails app is not involved in attestation at all.

```
CI run:
  1. CLI collects raw evidence from service APIs
  2. CLI computes SHA-256 hash of every evidence file
  3. CLI generates ephemeral Ed25519 keypair (Go stdlib crypto/ed25519)
  4. CLI signs the combined evidence hash with the private key
  5. Private key is discarded immediately — never stored anywhere
  6. attestation.json stored in customer S3:
     { hashes, signature, public_key, cli_version, policy_versions, environment }
  7. Raw evidence + full check results also stored in customer S3

Auditor spot-check (out-of-band, on request):
  1. Auditor selects a handful of evidence files to verify
  2. Auditor requests those files + attestation.json directly from the customer
  3. Auditor hashes each evidence file → compares against hashes in attestation.json
  4. Auditor verifies signature using the public key embedded in attestation.json
  5. Match confirms evidence was not modified since collection
```

### Threat Model

This design protects against:
- Accidental corruption (disk, transit, storage error)
- Unintentional evidence drift (file modified after collection without realising)

This design does not attempt to prevent:
- A customer deliberately fabricating evidence from the start
- This would be fraud — a legal matter, not a technical one
- Every compliance tool (Vanta, Drata, Secureframe) shares this limitation
- The difference: SigComply's audit trail is independently verifiable, not hidden behind vendor access

This threat is out of scope. Compliance products assume the customer is a legitimate actor trying to demonstrate conformance, not an adversary.

### Why Not Store Attestations in Rails?

The original design explored storing attestations (hashes and public keys) in the Rails app to prevent tampering. This was rejected for several reasons:

1. **Over-engineering for the threat model**: The only attack it meaningfully blocks is a customer with S3 write access substituting a new keypair — which already requires the customer to be an active bad actor (fraud). That scenario is out of scope.

2. **Contradicts zero-trust philosophy**: Involving Rails in the signing chain means Rails becomes a trusted intermediary for evidence integrity. The simpler design keeps the signing self-contained in customer infrastructure.

3. **Unnecessary complexity**: Rails would need a CA endpoint, append-only tables, and cert issuance logic. The ephemeral keypair approach requires zero additional infrastructure.

4. **Auditor workflow is out-of-band anyway**: Auditors spot-check a handful of files — they don't verify all evidence. An out-of-band flow (request file from customer, verify locally) is entirely appropriate for this use case.

---

## Design Exploration Archive

The sections below document the design thinking that led to the final decision. Kept for context.

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

With asymmetric signing (Ed25519): the private key signs, the public key verifies. The auditor only needs the public key, which is embedded in the attestation and can be published openly.

---

### Q: What if the CLI generates a fresh ephemeral keypair for every single run?

**This is the correct approach.** The ephemeral keypair generation is trivial (`ed25519.GenerateKey()`). No key management, no pre-shared secrets, no rotation.

The key question was: does the public key need to be anchored somewhere outside the customer's S3 bucket to be meaningful? After careful consideration: **no**, for this threat model.

Anyone could generate a new keypair and replace both the evidence and the attestation — but that is active fraud, which is out of scope. The signing proves *internal consistency* (evidence matches the signature), which is exactly what is needed for the compliance use case: verifying that evidence was not accidentally modified.

---

### Q: Should SigComply hold one private key and sign all customer attestations?

**No.** This makes SigComply a trusted intermediary, violating zero-trust. The signing identity must belong to the customer's pipeline, not SigComply.

---

### Q: Is Sigstore/Fulcio/Rekor useful for SigComply?

**Conceptually similar, but unnecessary complexity.** Sigstore solves the same cryptographic problem. However:

- SOC 2 auditors are not DevSecOps engineers — Sigstore tooling won't map to compliance workflows
- Compliance frameworks have specific retention requirements (often 7 years) that Sigstore's operational model isn't designed for
- Our use case is simpler: spot-check a handful of files, verify a signature, done

The right approach: implement using Go stdlib (`crypto/ed25519`) with compliance-oriented language and tooling.
