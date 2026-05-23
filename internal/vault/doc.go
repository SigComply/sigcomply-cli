// Package vault is L7 of the SigComply CLI: append-only persistence
// of envelopes, results, attachments, and run manifests to the
// customer's storage backend. Backend implementations: local, s3,
// gcs, azure_blob — all behind the core.Vault interface. The CLI
// never reads from the vault during the same run.
//
// See docs/architecture/02-layers.md and 05-vault-layout.md.
package vault
