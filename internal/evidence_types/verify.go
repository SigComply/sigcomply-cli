package evidencetypes

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

// VerifyRegistrations enforces the evidence-type-registry-as-sole-mediator
// invariant (CLAUDE.md §Sacred Invariant #4) at bootstrap. Two checks:
//
//  1. Source coverage — every type ID a registered source plugin emits
//     must have a registered EvidenceType (with schema). A plugin that
//     emits an unregistered type would otherwise sail through to
//     signing because schema validation has no schema to consult.
//
//  2. Policy coverage — every type ID a registered policy lists in
//     slot.Accepts must have a registered EvidenceType. A typo or a
//     reference to a deleted type would otherwise produce empty-set
//     plan failures at run time rather than a clear startup error.
//
// Both failures are configuration errors; the orchestrator turns them
// into exit code 3. Call after both Sources and Policies are populated.
func VerifyRegistrations(set *registry.Set) error {
	if set == nil {
		return fmt.Errorf("evidence_types: nil registry set")
	}
	if set.EvidenceTypes == nil {
		return fmt.Errorf("evidence_types: nil EvidenceTypes registry")
	}
	if err := verifySourceCoverage(set); err != nil {
		return err
	}
	return verifyPolicyCoverage(set)
}

func verifySourceCoverage(set *registry.Set) error {
	if set.Sources == nil {
		return nil
	}
	var lines []string
	for _, src := range set.Sources.All() {
		for _, typeID := range src.Emits() {
			if _, ok := set.EvidenceTypes.Lookup(typeID); !ok {
				lines = append(lines, fmt.Sprintf("source %q emits %q", src.ID(), typeID))
			}
		}
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return fmt.Errorf("evidence_types: %d emitted type(s) without a registered schema: %s",
		len(lines), strings.Join(lines, "; "))
}

func verifyPolicyCoverage(set *registry.Set) error {
	if set.Policies == nil {
		return nil
	}
	var lines []string
	policies := set.Policies.All()
	for i := range policies {
		pol := &policies[i]
		slotNames := make([]string, 0, len(pol.Slots))
		for name := range pol.Slots {
			slotNames = append(slotNames, name)
		}
		sort.Strings(slotNames)
		for _, slotName := range slotNames {
			for _, typeID := range pol.Slots[slotName].Accepts {
				if _, ok := set.EvidenceTypes.Lookup(typeID); !ok {
					lines = append(lines, fmt.Sprintf("policy %q slot %q accepts %q", pol.ID, slotName, typeID))
				}
			}
		}
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return fmt.Errorf("evidence_types: %d slot.accepts type(s) without a registered schema: %s",
		len(lines), strings.Join(lines, "; "))
}
