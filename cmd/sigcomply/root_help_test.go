package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// The root help is the first product description most users read; it must
// name what the CLI does, not jargon the positioning has dropped.
func TestRootCmd_HelpDescribesProduct(t *testing.T) {
	root := newRootCmd()
	const wantShort = "SOC 2 and ISO 27001 checks and signed evidence, run in your own CI"
	if root.Short != wantShort {
		t.Errorf("Short = %q; want %q", root.Short, wantShort)
	}

	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"-h"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("Execute -h: %v", err)
	}
	// Cobra prints Long, not Short, on the root help; check both.
	help := strings.ToLower(root.Short + "\n" + out.String())
	for _, banned := range []string{"non-custodial", "zero-trust"} {
		if strings.Contains(help, banned) {
			t.Errorf("root description contains %q:\n%s", banned, help)
		}
	}
}
