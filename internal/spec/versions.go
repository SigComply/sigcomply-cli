package spec

import "fmt"

// expectSchemaVersion checks that a spec's schema_version equals the
// version this loader was written against. The kind string is included
// in error messages for diagnostic clarity ("policy spec", "framework
// spec", etc.).
//
// Every L0 spec carries a schema_version; bumping it is how the v2
// spec format would coexist with v1 during a migration window.
func expectSchemaVersion(got, want, kind string) error {
	if got == "" {
		return fmt.Errorf("%s: missing required field \"schema_version\" (want %q)", kind, want)
	}
	if got != want {
		return fmt.Errorf("%s: unsupported schema_version %q (this CLI only supports %q)", kind, got, want)
	}
	return nil
}
