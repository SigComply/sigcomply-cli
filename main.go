// SigComply CLI - Compliance automation without infrastructure access
package main

import (
	cmd "github.com/sigcomply/sigcomply-cli/cmd/sigcomply"
)

// Set via ldflags
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, commit, buildTime)
	cmd.Execute()
}
