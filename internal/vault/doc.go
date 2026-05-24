// Package vault is L7 of the SigComply CLI: append-only persistence
// of envelopes, results, attachments, and run manifests to the
// customer's storage backend. The customer's vault — never the CLI's
// — receives every signed evidence envelope, every PDF mirror, every
// run manifest. The CLI is the writer; auditors and the optional Cloud
// dashboard are the readers.
//
// Backend implementations: local, s3, gcs, azure_blob — all behind the
// core.Vault interface. Selection is by self-registering factory: each
// backend's package init() calls vault.RegisterBackend, and
// internal/vault/builtin blank-imports them all so cmd/sigcomply pulls
// in every in-tree backend with one import line. Third-party backends
// (SFTP, MinIO, on-prem NFS, custom object stores) follow the same
// pattern from a project-local plugin compiled in by `sigcomply build`
// (M16) — no edits to internal/vault required.
//
// The CLI never reads from the vault during the same run.
//
// See docs/architecture/00-three-plugin-axes.md §Axis B,
// docs/architecture/02-layers.md, 05-vault-layout.md,
// and 07-extensibility.md §Custom vault backends.
package vault
