package manual

import (
	"embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed catalogs/*.yaml
var catalogsFS embed.FS

// LoadCatalog loads and parses the embedded catalog YAML for the given framework.
func LoadCatalog(framework string) (*Catalog, error) {
	filename := fmt.Sprintf("catalogs/%s.yaml", framework)
	data, err := catalogsFS.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("no manual evidence catalog for framework %q: %w", framework, err)
	}

	var catalog Catalog
	if err := yaml.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("failed to parse catalog for %q: %w", framework, err)
	}

	return &catalog, nil
}
