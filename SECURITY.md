# Security policy

## Reporting a vulnerability

Report a security vulnerability in SigComply CLI privately through
[GitHub Security Advisories](https://github.com/SigComply/sigcomply-cli/security/advisories/new),
not in a public issue. The maintainers acknowledge reports within 48 hours and give an estimated
timeline for a fix.

## Supported versions

Before 1.0, only the latest tagged release receives security fixes.

After 1.0 (planned), the current and the previous major version receive security fixes for two
years from the previous major's release. Evidence retention requirements are often 7 years, so
the vault format is supported for longer than the binary.

## Scope

In scope:

- The CLI binary (`sigcomply`) and its in-tree source plugins.
- The vault format and per-file Ed25519 signing.
- The cloud submission payload (the privacy boundary).
- The Go and Rego `rule:` runner. No shipped policy uses it, but project-local policies can.

Out of scope (report upstream):

- Vulnerabilities in Go dependencies. Report them to the upstream project; Dependabot opens
  update pull requests here.
- Vulnerabilities in OPA itself (open-policy-agent/opa).
- Vulnerabilities in cloud-provider SDKs (the SDK vendor).

## Threat model

### The privacy boundary

Raw evidence stays in the customer's environment. A bug that puts a resource identifier (ARN,
email, username, account ID) into the cloud submission is a critical vulnerability.

The boundary is enforced by the type, not only by review. The `SubmissionPayload` wire type has
no `map[string]any`, no violations list and no freeform field, so it cannot carry an identifier.
A reflection test (`TestSubmissionPayload_StructurallyCountsOnly` in
`internal/core/cloud_test.go`) walks the type and fails the build if a freeform field is added.
On the receiving side, the dashboard's request allow-list drops any field it doesn't expect.

To see exactly what a run would send, run `sigcomply check --capture-cloud-payload payload.json`.
The CLI writes the payload to the file and doesn't send it.

### How evidence is signed

- The CLI generates a new Ed25519 keypair for every evidence file and discards the private key
  as soon as the file is signed. No key is reused across files or runs.
- The public key and the signature are stored inside the file itself (`signature.public_key`
  and `signature.value` in the envelope JSON). Anyone can verify one file offline, with no other
  file and no SigComply service.
- Each run also writes `manifest.json`, which lists a SHA-256 hash for every file the run wrote
  to the vault. The manifest is signed with its own new keypair.
- `sigcomply report --view integrity` checks each run's manifest signature and recomputes every
  hash it lists. The Evidence SPA's `/verify` page checks a single envelope in the browser.

### What signing detects

- A vault file changed or corrupted after the run (bit rot, a sync tool, a faulty backend). The
  file's signature fails, or its hash no longer matches the manifest.
- A change to `manifest.json` after the run. The manifest's signature fails.
- An uploaded manual-evidence file replaced after the run. The signed record lists the SHA-256 of
  every uploaded file (`source_files[].sha256`), so the replacement no longer matches. The CLI
  doesn't re-read the upload bucket to compare; whoever checks the documents computes the hash.

### What signing does not detect

- Re-signing by anyone with write access to the vault. Because the public key is inside the
  envelope, such a person can generate a new keypair, write new envelopes and a new manifest, and
  sign them. The result can't be told apart from an original run. Only storage that refuses
  overwrites and deletes prevents this.
- Evidence that was false when it was collected. The CLI signs what it reads. It can't tell
  whether an uploaded document is genuine or whether its contents are true. That is the
  auditor's judgment.

### Storage immutability is your job

For an auditor to trust that evidence wasn't re-signed after the run, the vault storage must
prevent overwrites and deletes at the object layer. The CLI doesn't configure this: doing so would
need permissions the CLI's read-only, non-custodial model doesn't ask for.

| Backend | Setting |
|---|---|
| AWS S3 | Object Lock in compliance mode, with retention matching your audit retention. Or bucket versioning with MFA delete and a restrictive bucket policy. |
| Google Cloud Storage | A locked retention policy (Bucket Lock) matching your audit retention, plus Object Versioning. |
| Azure Blob Storage | Immutable storage with a locked time-based retention policy matching your audit retention. |
| Local filesystem | Not suitable for audit retention. Use it for local trial runs and short-lived CI storage only. |

Without one of these settings, signing still detects accidental changes, but not deliberate
re-signing by someone with vault write access.

### Manual evidence

For uploaded documents the CLI checks that supported files are present in the period's folder,
that they were uploaded inside the period's window, that the merged PDF passes byte-level checks
(minimum size, a `%PDF-` header, at least one page marker), and that the set of files isn't
byte-for-byte the same as the previous period's. It doesn't read document contents, validate
signatures inside a PDF, check dates written in a document, or decide whether a document meets
the control. The merged PDF isn't stored in the vault; the signed record holds the hashes of the
uploaded files. The full contract is in
[`docs/architecture/14-manual-evidence.md`](docs/architecture/14-manual-evidence.md).

The auditor reads the documents. The CLI gives the auditor a signed record of which files were
present, and when they were uploaded.
