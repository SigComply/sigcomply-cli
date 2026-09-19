// Package vendorfanout resolves a framework's fan-out catalog entries
// against the project's third-party register.
//
// It is the seam between two things that deliberately cannot see each
// other: a framework's manual catalog is static and config-free (so the
// SPA export, the published coverage figures and the control-coverage
// tests stay deterministic), while the vendor register is per-project
// configuration. This package applies one to the other at wiring time,
// producing the runtime catalog the manual.pdf plugin and
// `sigcomply evidence due` both read.
//
// Nothing here crosses the aggregation boundary. Vendor names and
// approver emails end up in the signed vault record only; the evaluator
// reduces them to two counts before submission.
package vendorfanout

import (
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// Apply returns a copy of the framework's runtime manual catalog with
// every fan-out entry expanded against the register.
//
// It is a no-op in three cases, each of which must leave the original
// single-folder behavior byte-identical: no register declared, a
// register that resolves to no members for a given entry, and an entry
// that declares no fan-out at all. That property is what makes this
// feature purely additive for every existing project.
func Apply(catalog map[string]manual.CatalogEntry, reg *spec.VendorRegister) map[string]manual.CatalogEntry {
	if len(catalog) == 0 {
		return catalog
	}
	out := make(map[string]manual.CatalogEntry, len(catalog))
	for id := range catalog {
		entry := catalog[id]
		out[id] = expand(&entry, reg)
	}
	return out
}

func expand(entry *manual.CatalogEntry, reg *spec.VendorRegister) manual.CatalogEntry {
	if entry.FanOut == "" || reg == nil {
		return *entry
	}
	var vendors []spec.Vendor
	switch entry.FanOut {
	case manual.FanOutVendors:
		vendors = reg.Vendors
	case manual.FanOutSubserviceVendors:
		vendors = reg.SubserviceVendors()
	default:
		// An unrecognized fan-out kind must not silently drop the
		// entry's evidence requirement — fall back to the single
		// folder rather than scanning nothing.
		return *entry
	}
	if len(vendors) == 0 {
		return *entry
	}

	instances := make([]manual.Instance, 0, len(vendors))
	for i := range vendors {
		v := &vendors[i]
		inst := manual.Instance{
			ID:                 v.ID,
			Name:               v.Name,
			Tier:               v.Tier,
			AssurancePeriodEnd: v.AssurancePeriodEnd,
			ExemptionReason:    v.TierRationale,
			ApprovedBy:         v.ApprovedBy,
		}
		// Subservice fan-out is about which organizations carry CUECs,
		// not about risk tier, so every member owes the mapping.
		inst.Required = entry.FanOut == manual.FanOutSubserviceVendors || v.RequiresEvidence()
		instances = append(instances, inst)
	}
	entry.Instances = instances
	return *entry
}
