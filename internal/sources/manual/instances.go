package manual

import (
	"fmt"
	"time"
)

// Fan-out kinds. A catalog entry names the set it fans out over; the
// set itself comes from project config, which the framework-static
// catalog cannot see. Resolution happens in internal/vendorfanout.
const (
	// FanOutVendors fans out over every vendor in the register.
	FanOutVendors = "vendors"
	// FanOutSubserviceVendors fans out over the vendors marked as
	// subservice organizations — the ones whose own reports carry
	// complementary user entity controls.
	FanOutSubserviceVendors = "subservice_vendors"
)

// AssuranceMaxAge is how far back a declared assurance coverage date may
// sit before the evidence is treated as stale.
//
// Fifteen months is the working norm for third-party assurance: a SOC 2
// Type II covers twelve, and auditors accept a bridge (gap) letter for
// the months between the report's period end and the reporting date.
// Anything older is the single most common CC9.2 finding.
const AssuranceMaxAge = 15 * 30 * 24 * time.Hour

// Instance is one member of a fan-out catalog entry — today, one vendor
// in the project's third-party register.
//
// The entry keeps a single catalog ID and a single policy; the instances
// multiply only the *folders* scanned beneath it. That is what lets one
// requirement ("current assurance evidence for each vendor that needs
// it") span N third parties without minting N policy identities, which
// would leak the vendor list across the aggregation boundary and would
// have to be keyed by four other subsystems (state shards, project
// config overrides, the due catalog, and the report's control join).
type Instance struct {
	// ID is the path-safe slug appended to the catalog ID to form this
	// instance's folder: {prefix}{evidence_id}.{instance_id}/{period}/.
	ID string

	// Name is the human label, used in `evidence due` output and in the
	// signed record. It never crosses the aggregation boundary.
	Name string

	// Tier is the declared risk tier, recorded for the auditor.
	Tier string

	// Required says whether this instance owes an uploaded artifact. A
	// non-required instance is an *approved exemption*, not an absence:
	// ExemptionReason and ApprovedBy carry the justification, and the
	// instance still appears in the signed record so the decision is
	// visible rather than missing.
	Required bool

	// ExemptionReason and ApprovedBy justify a non-required instance.
	ExemptionReason string
	ApprovedBy      string

	// AssurancePeriodEnd is the declared last day the instance's own
	// assurance report covers, as YYYY-MM-DD. Optional; when set it is
	// compared against the audit period so a long-expired report stops
	// passing. DECLARED, never parsed out of the PDF — the CLI does not
	// read document contents and does not claim to.
	AssurancePeriodEnd string
}

// FolderID returns the catalog-entry ID this instance's folder hangs
// off. Keeping the join in one function means the collector and
// `evidence due` cannot drift into scanning different paths.
func (i *Instance) FolderID(evidenceID string) string {
	return evidenceID + "." + i.ID
}

// assuranceStale reports whether a declared coverage end date is too far
// before the audit period to still be current, and the failure string to
// record when it is.
//
// An unparseable or absent date is NOT stale: the field is optional, and
// the loader has already rejected malformed values, so treating a blank
// as a failure here would fail every vendor that has not declared one.
func assuranceStale(declared string, periodStart time.Time) (stale bool, reason string) {
	if declared == "" || periodStart.IsZero() {
		return false, ""
	}
	end, err := time.Parse("2006-01-02", declared)
	if err != nil {
		return false, ""
	}
	if end.After(periodStart.Add(-AssuranceMaxAge)) {
		return false, ""
	}
	return true, fmt.Sprintf("assurance_out_of_date (declared coverage ended %s, more than %d months before the period began)",
		declared, int(AssuranceMaxAge.Hours()/(24*30)))
}
