// Package builtin imports every in-tree vault backend for the side
// effect of running its init() — which registers a Factory under the
// vault.RegisterBackend registry. Anyone wanting all shipped backends
// available simply blank-imports this package; nothing else needs to
// be touched.
//
// Adding a new in-tree vault backend: drop its package under
// internal/vault/, give it an init() that calls vault.RegisterBackend,
// then add one line below. cmd/sigcomply does not need to know about
// it.
//
// Project-local backends under .sigcomply/plugins/ are wired in by
// `sigcomply build` (M16) — that command generates a similar import
// list into the project-specific binary. See
// docs/architecture/07-extensibility.md §Custom vault backends.
package builtin

import (
	_ "github.com/sigcomply/sigcomply-cli/internal/vault/azureblob"
	_ "github.com/sigcomply/sigcomply-cli/internal/vault/gcs"
	_ "github.com/sigcomply/sigcomply-cli/internal/vault/local"
	_ "github.com/sigcomply/sigcomply-cli/internal/vault/s3"
)
