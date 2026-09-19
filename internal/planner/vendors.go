package planner

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// vendorCheckExempt are source keys that are not third parties in the
// sense the register means. manual.pdf is the project's own evidence
// bucket and test is the in-repo fixture plugin; neither is a supplier
// anyone performs due diligence on.
var vendorCheckExempt = map[string]struct{}{
	"manual.pdf": {},
	"test":       {},
}

// VendorWarnings reports the non-fatal findings about
// experimental.vendors: unrecognized subkeys, and configured sources
// that no register entry claims.
//
// The second is the point. The register is a declaration with nothing to
// diff it against, so a vendor the operator leaves out is invisible —
// the one gap the vendor policies cannot close, because they only
// evaluate what was declared. But a *configured source* is a third party
// the project demonstrably depends on, named in the operator's own
// config. Asserting that each one appears in the register is an observed
// baseline checking a declared one.
//
// It discovers nothing and widens nothing: it reads the sources block
// the operator already wrote, so it stays entirely inside the chosen
// estate. Warning, never error — deciding what belongs in the register
// is the operator's call, and a source may legitimately be out of scope
// for third-party risk.
//
// Silent when the register is undeclared: a project that never adopted
// experimental.vendors is not missing anything.
func VendorWarnings(cfg *spec.ProjectConfig) []string {
	reg, err := spec.LoadVendorRegister(cfg)
	if err != nil || reg == nil {
		return nil
	}

	var out []string
	for _, k := range reg.UnknownKeys {
		out = append(out, fmt.Sprintf("ignoring unrecognized key experimental.vendors.%s", k))
	}

	claimed := claimedProviders(reg)
	for _, id := range unclaimedSources(cfg, claimed) {
		out = append(out, fmt.Sprintf("source %q is configured but no register entry claims it; add it to experimental.vendors.register (or list %q under an existing entry's providers:) so the register covers every third party this project depends on",
			id, providerToken(id)))
	}
	return out
}

// claimedProviders is every providers: token in the register, lowercased.
func claimedProviders(reg *spec.VendorRegister) map[string]struct{} {
	out := map[string]struct{}{}
	for i := range reg.Vendors {
		for _, p := range reg.Vendors[i].Providers {
			out[strings.ToLower(strings.TrimSpace(p))] = struct{}{}
		}
	}
	return out
}

// unclaimedSources returns the configured source keys no register entry
// claims, sorted. A key matches on either its provider token ("aws") or
// its full base ID ("aws.iam"), so an operator can be as coarse or as
// precise as they like.
func unclaimedSources(cfg *spec.ProjectConfig, claimed map[string]struct{}) []string {
	var out []string
	for key := range cfg.Sources {
		base := baseSourceID(key)
		if _, exempt := vendorCheckExempt[base]; exempt {
			continue
		}
		if _, ok := claimed[base]; ok {
			continue
		}
		if _, ok := claimed[providerToken(base)]; ok {
			continue
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// baseSourceID strips a bracketed instance suffix: aws.iam[prod] →
// aws.iam. Two instances of one source are one vendor, so the check
// joins on the base.
func baseSourceID(key string) string {
	if open := strings.IndexByte(key, '['); open > 0 && strings.HasSuffix(key, "]") {
		return key[:open]
	}
	return key
}

// providerToken is the vendor-level half of a source ID: aws.iam → aws,
// github → github.
func providerToken(id string) string {
	base := baseSourceID(id)
	if dot := strings.IndexByte(base, '.'); dot > 0 {
		return base[:dot]
	}
	return base
}
