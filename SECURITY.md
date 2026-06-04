# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SigComply CLI, please report
it privately via [GitHub Security Advisories](https://github.com/SigComply/sigcomply-cli/security/advisories/new)
rather than opening a public issue.

We take security reports seriously and will acknowledge receipt within
48 hours and provide an estimated timeline for a fix.

## Supported Versions

Pre-1.0: the latest tagged release receives security fixes. Older
pre-releases are not supported.

Post-1.0 (planned): the current major version and the previous major
version receive security fixes for two years from the previous major's
release. SOC 2 / ISO 27001 evidence retention requirements (typically
7 years) mean the on-disk vault format is supported for a longer window
than the binary itself.

## Scope

In scope:
- The CLI binary (`sigcomply`) and its in-tree source plugins
- The vault format and per-file Ed25519 signing
- The cloud submission payload contract (privacy boundary)
- The Go/Rego rule-runner escape hatch (infrastructure present; no
  shipped policy currently uses it)

Out of scope (report upstream):
- Vulnerabilities in transitive Go dependencies (open a Dependabot PR
  or report to the upstream project)
- Vulnerabilities in OPA itself (report to open-policy-agent/opa)
- Vulnerabilities in cloud-provider SDKs (report to the SDK vendor)

## Threat Model

The CLI is designed under "Evidence without Access": raw evidence
never leaves the customer environment. Threats that violate this
boundary — e.g. a bug that causes resource identifiers to land in
the cloud SubmissionPayload — are treated as critical.

The boundary is enforced structurally, not by review alone: the
`SubmissionPayload` wire type carries no `map[string]any`, no
`Violations` slice, and no freeform field, so it is physically
incapable of carrying an identifier. A reflection test
(`internal/core/cloud_test.go`) walks the type graph and fails the
build if a freeform field is ever added. On the receiving side, Rails
strong-params under `Api::V1::RunsController` act as a second-layer
allow-list.

### What the signing scheme defends against

The per-file Ed25519 signing detects **accidental and unilateral
post-run drift**:

- A vault file corrupted by bit rot, a sync tool, or a misbehaving
  storage backend.
- A PDF swapped in place in the manual-evidence bucket while the
  original envelope is left untouched — the envelope's recorded
  `file_hash` will not match the new bytes.
- A modification to the per-run `manifest.json` after the run (the
  manifest is itself signed).

### What the signing scheme does NOT defend against

- **Customer-side fabrication at upload time.** A customer can produce
  a real-looking PDF whose contents do not reflect reality. The CLI
  signs what it reads; it cannot verify that what it read was true.
  This is and remains the auditor's job, and is out of scope for any
  compliance tool.
- **Determined re-signing by anyone with vault write access.** The
  public key lives inside the envelope (`EvidenceEnvelope.Signature.
  PublicKey`). A party with write access to the vault can generate a
  new ephemeral Ed25519 keypair, fabricate envelope + PDF + per-run
  manifest together, and sign all three. The result is cryptographic-
  ally indistinguishable from an original collection. Defending
  against this requires immutability at the storage layer, which the
  CLI does not configure.

### Required customer-side setup for tamper-resistance

For an auditor to trust that an envelope has not been re-signed since
the run, the storage holding the vault must enforce write-once or
version-controlled semantics at the object layer. Recommended setup
per backend:

| Backend | Required setting |
|---------|-----------------|
| **AWS S3** | Object Lock in **compliance mode** with a retention period matching audit retention (typically 7 years). Alternatively, bucket versioning + MFA delete + restrictive bucket policy. |
| **Google Cloud Storage** | Bucket Lock with a retention policy matching audit retention, plus Object Versioning. |
| **Azure Blob Storage** | Immutable storage with **time-based retention policies** (locked) matching audit retention. |
| **Local filesystem** | Not suitable for production audit retention. Use only for `sigcomply check` ad-hoc runs and ephemeral CI storage. |

Without one of these settings, the signing scheme still detects
accidental drift, but cannot defend against deliberate re-signing by
a party with vault write access. This is a customer responsibility
and a known limitation by design — the CLI explicitly does not
attempt to enforce immutability itself, because doing so would
require credentials the non-custodial model forbids.

### Manual evidence: explicit scope

The manual-evidence flow (`internal/sources/manual/`) performs
**presence + temporal window + cheap stdlib sanity checks** on each
uploaded PDF. See [CLAUDE.md §Manual evidence design contract](CLAUDE.md)
for the precise list of what is and is not checked. In short:

- The plugin verifies the file exists at the expected path within the
  configured temporal window.
- The plugin runs byte-level sanity checks (minimum size, `%PDF-`
  magic bytes, presence of a `/Page` token, and byte-equality with
  the prior period's file).
- The plugin does **not** inspect PDF contents, validate signatures
  inside the PDF, check internal dates, or verify that the document
  matches the policy's intent.

The auditor reads the PDF. The CLI provides a cryptographically-
signed timeline of what was uploaded when.
