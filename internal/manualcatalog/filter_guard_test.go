package manualcatalog_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/iso27001"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

// TestEveryFilterGuardsOptionalFields keeps a clause filter from reading a
// field the evidence type does not guarantee.
//
// Why this exists: a filter that cannot be evaluated errors the policy
// (see internal/evaluator/pass_when.go filterRecords). That is the right
// runtime behavior — scope that cannot be decided must not be guessed —
// but it means a filter on a schema-OPTIONAL field is a live failure
// waiting for the first source that omits it. Before the evaluator was
// fixed the same filter failed the other way, silently: the record was
// dropped, and `all`/`none` over the empty set passed, so one unpopulated
// field turned a real check into a permanent green tick.
//
// Three shipped filters read an optional field when this was written. All
// three now carry an is_set guard, which makes tolerating the absence a
// decision visible in the policy source rather than an accident in the
// engine. This test stops a fourth appearing.
//
// The rule: every comparison leaf inside a clause Filter must reference
// either a record-level field (id/type/source_id, always present) or a
// payload field that is `required` in EVERY evidence type the slot
// accepts — unless an is_set on the same path guards it from an enclosing
// all_of. Only all_of guards: it short-circuits on the first false
// sub-condition, so the comparison is never reached. any_of does not —
// it keeps evaluating after a false, and the comparison still errors.
func TestEveryFilterGuardsOptionalFields(t *testing.T) {
	set := registry.NewSet()
	if err := evidencetypes.Register(set); err != nil {
		t.Fatalf("register evidence types: %v", err)
	}

	required := map[string]map[string]bool{}
	for _, et := range set.EvidenceTypes.All() {
		var schema struct {
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(et.Schema, &schema); err != nil {
			t.Fatalf("evidence type %q: parse schema: %v", et.ID, err)
		}
		fields := map[string]bool{}
		for _, f := range schema.Required {
			fields[f] = true
		}
		required[et.ID] = fields
	}

	var findings []string
	for _, fw := range []struct {
		id       string
		policies func() []core.Policy
	}{
		{fwSOC2, soc2.Policies},
		{fwISO27001, iso27001.Policies},
	} {
		for _, pol := range fw.policies() {
			if pol.PassWhen == nil {
				continue
			}
			for i := range pol.PassWhen.Clauses {
				clause := &pol.PassWhen.Clauses[i]
				if clause.Filter == nil {
					continue
				}
				accepts := pol.Slots[clause.Slot].Accepts
				for _, f := range unguardedFields(clause.Filter, nil) {
					for _, typeID := range accepts {
						req, known := required[typeID]
						if !known {
							t.Fatalf("policy %q accepts unregistered evidence type %q", pol.ID, typeID)
						}
						if !req[f] {
							findings = append(findings, pol.ID+": filter reads "+f+
								", which is not required in "+typeID+" — guard it with is_set")
						}
					}
				}
			}
		}
	}

	if len(findings) > 0 {
		sort.Strings(findings)
		t.Errorf("%d filter(s) read a field the evidence type does not guarantee:\n  %s",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// unguardedFields returns the payload field paths a condition tree
// compares against without an is_set guard in scope. guarded carries the
// paths an enclosing all_of has already proven present.
func unguardedFields(cond *core.PassWhenCondition, guarded map[string]bool) []string {
	switch cond.Op {
	case "is_set":
		return nil
	case "all_of":
		// Siblings of an is_set in the same all_of are guarded by it:
		// all_of short-circuits, so a false is_set stops evaluation.
		inner := map[string]bool{}
		for f := range guarded {
			inner[f] = true
		}
		for _, sub := range cond.Conditions {
			if sub.Op == "is_set" {
				inner[sub.Field] = true
			}
		}
		var out []string
		for _, sub := range cond.Conditions {
			out = append(out, unguardedFields(sub, inner)...)
		}
		return out
	case "any_of":
		// any_of keeps evaluating past a false, so an is_set sibling
		// guards nothing. Only an inherited guard counts.
		var out []string
		for _, sub := range cond.Conditions {
			out = append(out, unguardedFields(sub, guarded)...)
		}
		return out
	}

	if guarded[cond.Field] {
		return nil
	}
	// Only payload paths map onto an evidence-type schema, so only they
	// can be checked for optionality here. `id`/`type`/`source_id` are
	// structural and always present, and any other namespace is either a
	// construct this walker does not model or unresolvable at run time —
	// in which case getField errors loudly on its own, which is a
	// different problem from the silent one this test guards.
	if !strings.HasPrefix(cond.Field, "payload.") {
		return nil
	}
	field := strings.TrimPrefix(cond.Field, "payload.")
	// Nested paths (payload.a.b) are not modeled: `required` lists
	// top-level keys only. Report the root, which is the part the schema
	// can actually speak to.
	if root, _, nested := strings.Cut(field, "."); nested {
		field = root
	}
	return []string{field}
}
