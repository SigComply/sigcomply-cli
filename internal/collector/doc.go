// Package collector is L4 of the SigComply CLI: executes per-policy
// source fetches, validates records against their evidence type
// schemas, and writes one signed envelope per (slot, source) pair via
// the vault. Each policy is processed independently — there is no
// record cache spanning policies (KISS-no-DRY).
//
// See docs/architecture/02-layers.md for the full layer contract.
package collector
