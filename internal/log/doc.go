// Package log is the cross-cutting redaction logger. Plugins and core
// code MUST route all informational/diagnostic output through this
// logger; direct writes to os.Stdout / os.Stderr from plugin code are
// forbidden. The logger strips emails, ARNs, UUIDs, access key IDs,
// JWTs, and configured secret shapes at the write boundary, so CI
// log capture cannot exfiltrate identifiers even in --verbose mode.
//
// See docs/architecture/02-layers.md §Logging and redaction.
package log
