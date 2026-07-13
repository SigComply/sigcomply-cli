# Verify evidence

How you or your auditor independently verify the evidence SigComply wrote
to your vault — with the read-only `report` command, and with the Evidence
SPA `/verify` page in the browser. Both are offline: no cloud, no login.

Back to the [docs hub](../README.md).

## How signing works (the customer-level picture)

Every `sigcomply check` run writes signed evidence to your vault (your own
storage):

- Each evidence file is wrapped in an **`EvidenceEnvelope`** — signed JSON
  of `{timestamp, evidence}`. Signing uses a **fresh, per-file ephemeral
  Ed25519 keypair**; the private key is discarded the instant the signature
  is computed, and the public key + signature are embedded in the envelope.
- Each run also writes a **`manifest.json`** listing the SHA-256 hashes of
  every file in the run (a single-level Merkle list), itself signed with its
  own ephemeral keypair. One signature therefore covers whole-run
  integrity while each file stays independently checkable.
- A manual PDF is stored alongside the envelope and referenced by its
  SHA-256 hash.

Run folders use basic ISO 8601 timestamps without colons (e.g.
`20260325T100000Z`) because some S3-compatible tools reject colons.

### What signing does and does not guarantee (read this)

The signing scheme **detects**: accidental envelope corruption, and a PDF
swapped while its envelope hash is left intact.

It **does not, by itself, prevent** a party with write access to the vault
from regenerating an envelope + PDF with a fresh keypair — because the
public key lives inside the envelope, a re-signed file is indistinguishable
from the original.

**Real tamper-resistance requires write-once / versioned vault storage,
which you configure at the storage layer — the CLI does not set this up:**

- **S3** — Object Lock, or versioning + MFA delete.
- **GCS** — Object Versioning + retention, or Bucket Lock.
- **Azure** — immutable blob storage.
- **Local filesystem** — dev/CI-ephemeral only; not tamper-resistant.

Do not claim tamper-resistance your storage configuration does not deliver.
See [concepts.md](../concepts.md) for the full model.

## Part A — Verify with `sigcomply report`

`report` is a **read-only** snapshot of the vault. It never writes to the
vault, never calls the cloud, and never needs an OIDC token.

### Prerequisites

- A vault populated by at least one `sigcomply check` run.
- The `--period` you want to inspect (e.g. `2026-Q1`). **`--period` is
  required** — omitting it exits 3.

### Usage

```bash
sigcomply report --period 2026-Q1 --view latest
```

### Flags

| Flag | Values | Notes |
|------|--------|-------|
| `--period <id>` | e.g. `2026-Q1` | **Required**; missing → exit 3 |
| `--view <name>` | `latest` \| `exceptions` \| `integrity` | Default `latest` |
| `--format <fmt>` | `text` \| `json` \| `csv` \| `pdf` | Default `text`; `pdf` is deferred → exit 3 if used |
| `--out <file>` | path | **Required for non-`text` formats** (else exit 3); `text` prints to stdout |
| `--vault <uri>` | path, `s3://`, `gs://`, `az://`, `file://` | Point at an external vault |
| `-f/--framework` | framework id | Defaults to the config framework |
| `-c/--config <path>` | path | Config file |

### The three views

- **`latest`** — the current pass/fail state for each policy.
- **`exceptions`** — the register of waivers and not-applicable (NA)
  declarations in effect.
- **`integrity`** — run-by-run verification of every signature and the run
  manifest. This is the view an auditor uses to confirm nothing in the vault
  has drifted.

### Examples

```bash
# Human-readable latest state to the terminal
sigcomply report --period 2026-Q1 --view latest

# Machine-readable integrity report to a file (non-text requires --out)
sigcomply report --period 2026-Q1 --view integrity --format json --out integrity.json

# Verify a vault stored in S3
sigcomply report --period 2026-Q1 --view integrity --vault s3://my-vault-bucket
```

## Part B — The Evidence SPA `/verify` page

The [Evidence SPA](https://github.com/SigComply/sigcomply-evidence-spa) is a
static React app hosted on GitHub Pages. It has no backend and uploads
nothing to any server — verification runs entirely in your browser.

To verify a single evidence file:

1. Open the SPA's `/verify` page.
2. Paste a CLI-signed **`EvidenceEnvelope` JSON** (copy it from your vault).
3. Optionally attach the referenced **PDF**.
4. The page checks the **Ed25519 signature** on the envelope and re-hashes
   the PDF to confirm it matches the hash in the envelope — all in-browser,
   with no auth and no network calls.

This is the fastest way for an auditor to spot-check a single file without
installing the CLI. For whole-vault verification, use
`report --view integrity` above.

## Next steps

- [manual-evidence.md](manual-evidence.md) — produce PDFs the SPA can also
  generate for declaration/checklist entries.
- [concepts.md](../concepts.md) — signing, aggregation, and the
  non-custodial model.
- [cloud-dashboard.md](cloud-dashboard.md) — the optional counts-only
  dashboard.
- [troubleshooting.md](troubleshooting.md) — exit codes and common failures.
- Back to the [docs hub](../README.md).
