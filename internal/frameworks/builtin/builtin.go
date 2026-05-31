// Package builtin imports every in-tree framework for the side effect
// of running its init() — which registers a Factory with the
// frameworks registry. Commands blank-import this package to make all
// shipped frameworks available; nothing else needs to change when a
// framework is added beyond one line here.
package builtin

import (
	_ "github.com/sigcomply/sigcomply-cli/internal/frameworks/iso27001"
	_ "github.com/sigcomply/sigcomply-cli/internal/frameworks/soc2"
)
