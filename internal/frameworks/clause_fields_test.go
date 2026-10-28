package frameworks_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	fwregistry "github.com/sigcomply/sigcomply-cli/internal/frameworks"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

// recordFields are the record-level paths the evaluator resolves without a
// payload (evaluator getField), and accountFields the virtual account.*
// paths it computes for every record (evaluator accountContext).
var (
	recordFields  = map[string]bool{"id": true, "type": true, "source_id": true}
	accountFields = map[string]bool{"account.ref": true, "account.key": true, "account.linked_by": true, "account.non_human": true, "account.active": true}
)

// msgVar matches a {{.path}} token in a violation message, as the evaluator's
// renderMsg does.
var msgVar = regexp.MustCompile(`\{\{\.([^}]+)\}\}`)

// TestClauseFieldsExistInAcceptedSchemas checks that every field a policy
// reads exists in the schema of every evidence type its slot accepts.
//
// Why this exists: evidence-type schemas allow additional properties, so a
// record never fails validation for lacking a field a policy expects, and
// VerifyRegistrations checks type IDs only. A misspelled field, or a field
// that one accepted type has and a sibling version lacks, errors the policy
// on every run with a source of that type. Nothing caught that before a
// customer did.
//
// Checked: clause filters and conditions (against the clause's slot), each
// matches_in remote field and where (against its in_slot), identity keys,
// and {{.payload.*}} tokens in violation messages.
//
// A field must be declared by every accepted type, with one exception: a
// clause written to read two versions of a type (password_policy and
// password_policy.v2) may read a field only one version declares, as long
// as it reads it through is_set or behind an is_set on the same path in an
// enclosing all_of, which short-circuits for the version without it. The
// field must still be declared by at least one accepted type. Whether an
// optional field is guarded is TestEveryFilterGuardsOptionalFields.
func TestClauseFieldsExistInAcceptedSchemas(t *testing.T) {
	set := registry.NewSet()
	if err := evidencetypes.Register(set); err != nil {
		t.Fatal(err)
	}
	schemas := map[string]json.RawMessage{}
	for _, et := range set.EvidenceTypes.All() {
		schemas[et.ID] = et.Schema
	}

	var findings []string
	checked := 0
	for _, fwID := range fwregistry.IDs() {
		for _, p := range frameworkPolicies(t, fwID) {
			if p.PassWhen == nil {
				continue
			}
			for i := range p.PassWhen.Clauses {
				c := &p.PassWhen.Clauses[i]
				fc := fieldCheck{policy: p.ID, slots: p.Slots, schemas: schemas, findings: &findings, checked: &checked}
				fc.cond(c.Slot, c.Filter, nil)
				fc.cond(c.Slot, c.Condition, nil)
				if c.IdentityKey != "" {
					fc.path(c.Slot, c.IdentityKey, "identity_key", false)
				}
				for _, m := range msgVar.FindAllStringSubmatch(c.ViolationMsg, -1) {
					// An unresolved token renders as-is rather than erroring, so
					// a field one version lacks is tolerated here.
					fc.path(c.Slot, m[1], "violation message", true)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no field reference checked")
	}
	if len(findings) > 0 {
		sort.Strings(findings)
		findings = slices.Compact(findings)
		t.Errorf("%d field reference(s) name a field an accepted evidence type does not declare:\n  %s",
			len(findings), strings.Join(findings, "\n  "))
	}
}

type fieldCheck struct {
	policy   string
	slots    map[string]core.Slot
	schemas  map[string]json.RawMessage
	findings *[]string
	checked  *int
}

// cond walks a condition tree. guarded holds the paths an is_set in an
// enclosing all_of has already proven present.
func (fc fieldCheck) cond(slot string, c *core.PassWhenCondition, guarded map[string]bool) {
	if c == nil {
		return
	}
	switch c.Op {
	case "all_of":
		inner := maps.Clone(guarded)
		if inner == nil {
			inner = map[string]bool{}
		}
		for _, sub := range c.Conditions {
			if sub.Op == "is_set" {
				inner[sub.Field] = true
			}
		}
		for _, sub := range c.Conditions {
			fc.cond(slot, sub, inner)
		}
		return
	case "any_of":
		for _, sub := range c.Conditions {
			fc.cond(slot, sub, guarded)
		}
		return
	case core.OpMatchesIn:
		fc.path(slot, c.Field, "matches_in field", guarded[c.Field])
		fc.path(c.InSlot, c.RemoteField, "matches_in remote_field", false)
		fc.cond(c.InSlot, c.Where, nil)
		return
	case "is_set":
		fc.path(slot, c.Field, c.Op, true)
		return
	}
	fc.path(slot, c.Field, c.Op, guarded[c.Field])
}

// path checks one field reference. tolerant allows the field to be missing
// from some accepted types, but not from all of them.
func (fc fieldCheck) path(slot, path, where string, tolerant bool) {
	*fc.checked++
	if recordFields[path] || accountFields[path] {
		return
	}
	s, ok := fc.slots[slot]
	if !ok {
		*fc.findings = append(*fc.findings, fmt.Sprintf("%s: %s reads %q from undeclared slot %q", fc.policy, where, path, slot))
		return
	}
	rest, ok := strings.CutPrefix(path, "payload.")
	if !ok {
		*fc.findings = append(*fc.findings, fmt.Sprintf("%s: %s reads %q, which is neither a record field nor payload.*", fc.policy, where, path))
		return
	}
	var missing []string
	for _, typeID := range s.Accepts {
		schema, known := fc.schemas[typeID]
		if !known {
			*fc.findings = append(*fc.findings, fmt.Sprintf("%s: slot %q accepts unregistered type %q", fc.policy, slot, typeID))
			continue
		}
		if !schemaHasPath(schema, strings.Split(rest, ".")) {
			missing = append(missing, typeID)
		}
	}
	switch {
	case len(missing) == 0:
	case len(missing) == len(s.Accepts):
		*fc.findings = append(*fc.findings, fmt.Sprintf("%s: %s reads %q, which no accepted type (%s) declares", fc.policy, where, path, strings.Join(s.Accepts, ", ")))
	case !tolerant:
		*fc.findings = append(*fc.findings, fmt.Sprintf("%s: %s reads %q unguarded, which %s does not declare (read it behind is_set)", fc.policy, where, path, strings.Join(missing, ", ")))
	}
}

// schemaHasPath walks properties (and array items) of a JSON schema.
func schemaHasPath(schema json.RawMessage, parts []string) bool {
	var node struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Items      json.RawMessage            `json:"items"`
	}
	if err := json.Unmarshal(schema, &node); err != nil {
		return false
	}
	if len(parts) == 0 {
		return true
	}
	if child, ok := node.Properties[parts[0]]; ok {
		return schemaHasPath(child, parts[1:])
	}
	if len(node.Items) > 0 {
		return schemaHasPath(node.Items, parts)
	}
	return false
}
