// Package sign is the cross-cutting signing primitive: per-file
// ephemeral Ed25519 keypair generation, canonical JSON encoding
// (RFC 8785-style), and envelope signing/verification. The private
// key is discarded the instant the signature is computed; the public
// key + signature live inside the envelope, so every file is
// independently verifiable offline.
//
// See ARCHITECTURE.md §Core principles #4 and docs/architecture/02-layers.md
// §Per-file signing.
package sign
