package planner

import (
	"sort"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

// SourceCaveatWarning reports that a source bound to a slot declared it
// cannot really observe a field this policy's pass_when reads.
//
// It is advisory. The policy still plans, collects and evaluates exactly as
// it would have — a caveat changes no status, no count and nothing on the
// wire. What it changes is that the operator finds out, at plan time, that a
// control is being graded partly on a value nobody measured.
type SourceCaveatWarning struct {
	Slot         string
	SourceID     string
	EvidenceType string
	Field        string
	Detail       string
	// Alternatives names the other sources bound to the same slot that
	// declared no caveat on this field, sorted. When non-empty the remedy is
	// a bindings: pin, because those sources hold the real answer for the
	// same humans and the evaluator is unioning them with this one. When
	// empty there is nothing to pin to and the finding is genuine.
	Alternatives []string
}

// caveatWarnings returns the caveats that actually bite for one planned
// policy: a bound source declares a caveat, the caveated type is one this
// binding accepts, and the policy reads that field on that slot.
//
// All three conditions matter. A caveat on a type the slot did not accept is
// irrelevant; a caveat on a field no clause reads costs the policy nothing.
// Warning on either would train operators to ignore the output.
func caveatWarnings(policy *core.Policy, bindings map[string][]Binding, sources *registry.Registry[core.SourcePlugin]) []SourceCaveatWarning {
	if policy == nil || len(bindings) == 0 || sources == nil {
		return nil
	}
	read := fieldsReadBySlot(policy.PassWhen)
	if len(read) == 0 {
		return nil
	}

	var out []SourceCaveatWarning
	for _, slot := range sortedKeys(bindings) {
		fields := read[slot]
		if len(fields) == 0 {
			continue
		}
		caveated := map[string][]core.SourceCaveat{} // sourceID -> biting caveats
		for _, b := range bindings[slot] {
			for _, c := range bindingCaveats(b, sources) {
				if fields[c.Field] {
					caveated[b.SourceID] = append(caveated[b.SourceID], c)
				}
			}
		}
		if len(caveated) == 0 {
			continue
		}
		for _, srcID := range sortedKeys(caveated) {
			for _, c := range caveated[srcID] {
				out = append(out, SourceCaveatWarning{
					Slot: slot, SourceID: srcID,
					EvidenceType: c.EvidenceType, Field: c.Field, Detail: c.Detail,
					Alternatives: uncaveatedPeers(bindings[slot], caveated, c.Field),
				})
			}
		}
	}
	return out
}

// bindingCaveats returns the caveats a binding's source declares that apply
// to a type this binding actually accepts.
func bindingCaveats(b Binding, sources *registry.Registry[core.SourcePlugin]) []core.SourceCaveat {
	plugin := lookupSourcePlugin(sources, b.SourceID)
	if plugin == nil {
		return nil
	}
	c, ok := plugin.(core.CaveatedSource)
	if !ok {
		return nil
	}
	accepted := make(map[string]bool, len(b.AcceptedTypes))
	for _, t := range b.AcceptedTypes {
		accepted[t] = true
	}
	var out []core.SourceCaveat
	for _, cav := range c.Caveats() {
		if accepted[cav.EvidenceType] {
			out = append(out, cav)
		}
	}
	return out
}

// uncaveatedPeers names the other sources on the slot that did not declare a
// caveat on this field — the ones a bindings: pin could hand the slot to.
func uncaveatedPeers(slotBindings []Binding, caveated map[string][]core.SourceCaveat, field string) []string {
	var out []string
	for _, b := range slotBindings {
		bites := false
		for _, c := range caveated[b.SourceID] {
			if c.Field == field {
				bites = true
				break
			}
		}
		if !bites {
			out = append(out, b.SourceID)
		}
	}
	sort.Strings(out)
	return out
}

// fieldsReadBySlot maps each slot to the set of payload field names the
// pass_when clauses read against that slot's records.
//
// Every existing clause walker in this repo misses at least one of these
// paths, so this one is deliberately exhaustive:
//   - clause.Condition AND clause.Filter (the filter-guard walker sees only
//     filters, which would miss mfa_enabled in root_mfa_enabled);
//   - nested all_of / any_of subtrees (the admin-MFA policies bury
//     mfa_enabled one level down);
//   - the matches_in Where subtree (collectMatchesIn skips it by design);
//   - clause.IdentityKey, which is also a field path.
//
// RemoteField is attributed to cond.InSlot, not the clause's own slot: it is
// read against the OTHER slot's records. Getting that backwards would warn
// about the wrong source.
//
// Known limit: the virtual account.* namespace is computed from payload
// fields (email, principal_id, username, is_active…) that never appear as a
// literal Field, so a caveat on one of those is not detected through an
// account.* reference. No shipped caveat is affected; revisit if one is.
func fieldsReadBySlot(spec *core.PassWhenSpec) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	if spec == nil {
		return out
	}
	add := func(slot, path string) {
		name, ok := payloadField(path)
		if !ok || slot == "" {
			return
		}
		if out[slot] == nil {
			out[slot] = map[string]bool{}
		}
		out[slot][name] = true
	}
	for i := range spec.Clauses {
		cl := &spec.Clauses[i]
		add(cl.Slot, cl.IdentityKey)
		collectFields(cl.Condition, cl.Slot, add)
		collectFields(cl.Filter, cl.Slot, add)
	}
	return out
}

// collectFields walks one condition tree, reporting each field path with the
// slot its records come from.
func collectFields(cond *core.PassWhenCondition, slot string, add func(slot, path string)) {
	if cond == nil {
		return
	}
	add(slot, cond.Field)
	if cond.Op == core.OpMatchesIn {
		// RemoteField and Where both read the remote slot's records.
		add(cond.InSlot, cond.RemoteField)
		collectFields(cond.Where, cond.InSlot, add)
	}
	for _, sub := range cond.Conditions {
		collectFields(sub, slot, add)
	}
}

// payloadField reduces a field path to the payload field name it reads, or
// reports false for a path that is not a payload read (id, source_id, the
// virtual account.* namespace, or empty). A nested path keeps only its root
// key, which is the granularity a caveat is declared at.
func payloadField(path string) (string, bool) {
	if !strings.HasPrefix(path, "payload.") {
		return "", false
	}
	name := strings.TrimPrefix(path, "payload.")
	if root, _, nested := strings.Cut(name, "."); nested {
		name = root
	}
	if name == "" {
		return "", false
	}
	return name, true
}

// sortedKeys returns a map's keys in deterministic order, so warnings come
// out the same on every run.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
