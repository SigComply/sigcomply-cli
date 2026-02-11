//go:build e2e

package e2e

import (
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/engine"
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/iso27001"
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/soc2"
)

// resolveFramework returns the engine.Framework for a given framework name.
func resolveFramework(name string) engine.Framework {
	switch name {
	case "soc2":
		return soc2.New()
	case "iso27001":
		return iso27001.New()
	default:
		return nil
	}
}
