package manualcatalog

import "strings"

// TitleFromID turns a snake_case catalog id into a Title Case display
// name, e.g. "security_awareness_training" → "Security Awareness
// Training". A few domain acronyms are upper-cased. Used as the default
// when a manual policy does not set an explicit name.
func TitleFromID(id string) string {
	acronyms := map[string]string{
		"nda": "NDA", "pii": "PII", "ict": "ICT", "sdlc": "SDLC",
		"bcp": "BCP", "soc2": "SOC 2", "iso": "ISO",
	}
	parts := strings.Split(id, "_")
	for i, p := range parts {
		if up, ok := acronyms[p]; ok {
			parts[i] = up
			continue
		}
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

// FrequencyFromCadence maps the CLI cadence DSL onto the SPA's Frequency
// union. The CLI uses "annual"; the SPA expects "yearly". Cadences with
// no SPA equivalent (continuous, hourly, every:<dur>) fall back to the
// coarsest sensible bucket so the export always validates.
func FrequencyFromCadence(cadence string) Frequency {
	switch cadence {
	case "annual", "yearly":
		return FrequencyYearly
	case "quarterly":
		return FrequencyQuarterly
	case "monthly":
		return FrequencyMonthly
	case "weekly":
		return FrequencyWeekly
	case "daily", "hourly", "continuous":
		return FrequencyDaily
	default:
		// every:<dur> and anything unrecognized — manual policies are
		// retrospective and low-frequency; yearly is the safe default.
		return FrequencyYearly
	}
}

// GraceForCadence returns the grace-period string used in the export,
// matching the framework runtime catalog (15d for quarterly, 30d
// otherwise).
func GraceForCadence(cadence string) string {
	if cadence == "quarterly" {
		return "15d"
	}
	return "30d"
}
