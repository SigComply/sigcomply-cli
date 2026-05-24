package evidence_types

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"

	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

//go:embed schemas/*.json
var schemasFS embed.FS

// Register loads every embedded schema and inserts it into the
// EvidenceType registry. Intended to be called once at orchestrator
// bootstrap, before frameworks register policies (so the planner can
// later validate that slot.Accepts entries are known type IDs).
//
// Duplicates and parse errors short-circuit and return a configuration
// error (exit code 3).
func Register(set *registry.Set) error {
	if set == nil || set.EvidenceTypes == nil {
		return fmt.Errorf("evidence_types: nil registry set")
	}
	files, err := embeddedFiles()
	if err != nil {
		return err
	}
	for _, name := range files {
		data, err := schemasFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("evidence_types: read %s: %w", name, err)
		}
		et, err := spec.LoadEvidenceType(data)
		if err != nil {
			return fmt.Errorf("evidence_types: load %s: %w", name, err)
		}
		if err := set.EvidenceTypes.Register(et); err != nil {
			return fmt.Errorf("evidence_types: register %s: %w", name, err)
		}
	}
	return nil
}

// embeddedFiles returns the sorted list of embedded schema paths.
// Sorting keeps Register's failure ordering deterministic across runs
// — when something is wrong, the same file fails first every time.
func embeddedFiles() ([]string, error) {
	entries, err := fs.ReadDir(schemasFS, "schemas")
	if err != nil {
		return nil, fmt.Errorf("evidence_types: read embedded schemas dir: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, "schemas/"+e.Name())
	}
	sort.Strings(names)
	return names, nil
}
