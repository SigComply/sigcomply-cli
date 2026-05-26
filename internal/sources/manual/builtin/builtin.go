// Package builtin imports every in-tree manual.pdf reader backend for
// the side effect of running its init() — which registers a
// ReaderFactory under the manual.RegisterReader registry. Anyone
// wanting all shipped manual-evidence backends available simply
// blank-imports this package; nothing else needs to be touched.
//
// The "local" backend self-registers from the parent manual package's
// init() (it lives inline in internal/sources/manual/factory.go) and
// therefore does not appear in the import list below — pulling in the
// manual package already covers it.
//
// Adding a new in-tree backend: drop its package under
// internal/sources/manual/<id>/, give it an init() that calls
// manual.RegisterReader, then add one line below.
//
// Project-local backends under .sigcomply/plugins/ are wired in by
// `sigcomply build` (M16) — that command generates a similar import
// list into the project-specific binary. See
// docs/architecture/07-extensibility.md §Custom manual-evidence
// backends.
package builtin

import (
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/manual/azureblob"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/manual/gcs"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/manual/s3"
)
