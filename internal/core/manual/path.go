package manual

import (
	"fmt"
	"regexp"
	"strings"
)

// DefaultPathTemplate is the storage-key template used when a catalog entry
// does not specify path_template. Placeholders use {name} syntax (not Go
// template {{name}}) for YAML readability.
const DefaultPathTemplate = "{framework}/{evidence_id}/{period}/{filename}"

// EvidencePDFFilename is the default filename for manual evidence PDFs.
// (Defined here to keep all manual-evidence path defaults in one file —
// the legacy const in manual.go aliases this.)

// placeholderPattern matches {name} placeholders. Names are restricted to
// the small fixed set ResolvePath supports; anything else is a template
// authoring error.
var placeholderPattern = regexp.MustCompile(`\{([a-z_]+)\}`)

// ResolvePath produces the fully-resolved storage key for a manual
// evidence PDF, applying the entry's path_template (or the default) and
// substituting period-derived placeholders.
//
// Returned path is rejected if it would escape the storage prefix
// (contains "..") or starts with "/", and must end in ".pdf" in v1.
func ResolvePath(entry *CatalogEntry, framework string, period *Period) (string, error) {
	if entry == nil {
		return "", fmt.Errorf("ResolvePath: nil entry")
	}
	if period == nil {
		return "", fmt.Errorf("ResolvePath: nil period")
	}

	template := entry.PathTemplate
	if template == "" {
		template = DefaultPathTemplate
	}
	filename := entry.Filename
	if filename == "" {
		filename = EvidencePDFFilename
	}
	if !strings.HasSuffix(filename, ".pdf") {
		return "", fmt.Errorf("manual evidence filename must end in .pdf, got %q", filename)
	}

	values := buildPlaceholderValues(entry, framework, period, filename)
	out, err := applyTemplate(template, values)
	if err != nil {
		return "", err
	}

	if err := validateResolvedPath(out); err != nil {
		return "", err
	}
	return out, nil
}

// buildPlaceholderValues returns the substitution map for ResolvePath.
// Frequency-specific placeholders ({quarter}, {month}) are only populated
// for the matching frequency so that referencing them outside that
// frequency is a clear authoring error rather than silent emptiness.
func buildPlaceholderValues(entry *CatalogEntry, framework string, period *Period, filename string) map[string]string {
	values := map[string]string{
		"framework":   framework,
		"evidence_id": entry.ID,
		"period":      period.Key,
		"filename":    filename,
		"year":        fmt.Sprintf("%04d", period.Start.Year()),
	}
	switch entry.Frequency {
	case FrequencyQuarterly:
		q := (int(period.Start.Month())-1)/3 + 1
		values["quarter"] = fmt.Sprintf("Q%d", q)
	case FrequencyMonthly:
		values["month"] = fmt.Sprintf("%02d", int(period.Start.Month()))
	case FrequencyDaily:
		values["month"] = fmt.Sprintf("%02d", int(period.Start.Month()))
		values["day"] = fmt.Sprintf("%02d", period.Start.Day())
	}
	return values
}

// applyTemplate replaces {name} placeholders in template with the matching
// value from values. Returns an error if a placeholder is referenced but
// not provided (e.g. {quarter} on an annual policy).
func applyTemplate(template string, values map[string]string) (string, error) {
	var missing []string
	out := placeholderPattern.ReplaceAllStringFunc(template, func(match string) string {
		name := match[1 : len(match)-1]
		v, ok := values[name]
		if !ok {
			missing = append(missing, name)
			return match
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("path_template references unknown or frequency-incompatible placeholder(s): %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// validateResolvedPath rejects paths that would escape the storage prefix
// or otherwise violate the v1 manual-evidence contract.
func validateResolvedPath(p string) error {
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("resolved manual-evidence path must not start with /: %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf("resolved manual-evidence path must not contain '..': %q", p)
		}
	}
	if !strings.HasSuffix(p, ".pdf") {
		return fmt.Errorf("resolved manual-evidence path must end in .pdf: %q", p)
	}
	return nil
}
