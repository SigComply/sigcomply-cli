package evaluator

import (
	"fmt"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

// evalCtx is everything a pass_when evaluation reads besides the record
// under test: the policy's slots (for cross-slot matches_in), its
// parameters, the project's roster link (for account.* fields) and the
// matches_in indexes built for the current policy.
type evalCtx struct {
	slots  map[string][]core.EvidenceRecord
	params map[string]any
	roster *planner.RosterLink
	// declared is the policy's slot declaration. When set, a matches_in
	// in_slot must be declared, and a declared slot with no records (the
	// collector writes no key for an unbound slot) is an empty slot. When
	// nil, an in_slot must be present as a key of slots.
	declared map[string]core.Slot
	// index maps each matches_in condition to the normalized remote keys
	// it matches against.
	index map[*core.PassWhenCondition]map[string]struct{}
}

func newEvalCtx(slots map[string][]core.EvidenceRecord, params map[string]any, roster *planner.RosterLink) *evalCtx {
	return &evalCtx{
		slots:  slots,
		params: params,
		roster: roster,
		index:  map[*core.PassWhenCondition]map[string]struct{}{},
	}
}

// buildIndexes builds the index of every matches_in condition in the
// clause's condition and filter trees. It reports whether any of them
// reads an empty slot (a vacuous comparison). Any error here is a policy
// error: an index is never silently empty.
func (ec *evalCtx) buildIndexes(clause *core.PassWhenClause) (emptyRemote bool, err error) {
	var conds []*core.PassWhenCondition
	collectMatchesIn(clause.Filter, &conds)
	collectMatchesIn(clause.Condition, &conds)
	for _, cond := range conds {
		empty, err := ec.buildIndex(cond)
		if err != nil {
			return false, fmt.Errorf("matches_in on slot %q: %w", clause.Slot, err)
		}
		emptyRemote = emptyRemote || empty
	}
	return emptyRemote, nil
}

// collectMatchesIn appends every matches_in node of a condition tree.
// where trees are not descended: matches_in is forbidden there, and an
// unindexed matches_in errors at evaluation.
func collectMatchesIn(cond *core.PassWhenCondition, out *[]*core.PassWhenCondition) {
	if cond == nil {
		return
	}
	if cond.Op == core.OpMatchesIn {
		*out = append(*out, cond)
	}
	for _, sub := range cond.Conditions {
		collectMatchesIn(sub, out)
	}
}

func (ec *evalCtx) buildIndex(cond *core.PassWhenCondition) (empty bool, err error) {
	if _, done := ec.index[cond]; done {
		return len(ec.slots[cond.InSlot]) == 0, nil
	}
	if cond.InSlot == "" || cond.RemoteField == "" {
		return false, fmt.Errorf("matches_in requires in_slot and remote_field")
	}
	if !ec.slotKnown(cond.InSlot) {
		return false, fmt.Errorf("in_slot %q is not a slot of this policy", cond.InSlot)
	}
	remote := ec.slots[cond.InSlot]
	idx := make(map[string]struct{}, len(remote))
	for i := range remote {
		r := &remote[i]
		if cond.Where != nil {
			ok, err := ec.evalCondition(cond.Where, r)
			if err != nil {
				return false, fmt.Errorf("where on slot %q: %w", cond.InSlot, err)
			}
			if !ok {
				continue
			}
		}
		key, ok, err := ec.matchKey(r, cond.RemoteField, cond.Normalize)
		if err != nil {
			return false, err
		}
		if ok {
			idx[key] = struct{}{}
		}
	}
	ec.index[cond] = idx
	return len(remote) == 0, nil
}

func (ec *evalCtx) slotKnown(name string) bool {
	if ec.declared != nil {
		_, ok := ec.declared[name]
		return ok
	}
	_, ok := ec.slots[name]
	return ok
}

// matchesIn reports whether the record's normalized Field value is in the
// condition's index. A record without a usable key (absent, non-string,
// or empty after normalizing) never matches: an account without a key
// can never be proven linked.
func (ec *evalCtx) matchesIn(cond *core.PassWhenCondition, rec *core.EvidenceRecord) (bool, error) {
	idx, ok := ec.index[cond]
	if !ok {
		return false, fmt.Errorf("matches_in on in_slot %q has no index (matches_in is not allowed inside where)", cond.InSlot)
	}
	key, ok, err := ec.matchKey(rec, cond.Field, cond.Normalize)
	if err != nil || !ok {
		return false, err
	}
	_, hit := idx[key]
	return hit, nil
}

// matchKey returns the normalized string value of path on rec; ok is
// false when there is no usable key. err is set only for an unknown
// normalize mode.
func (ec *evalCtx) matchKey(rec *core.EvidenceRecord, path, normalize string) (key string, ok bool, err error) {
	var norm func(string) string
	switch normalize {
	case "":
		norm = func(s string) string { return s }
	case core.NormalizeLowerTrim:
		norm = lowerTrim
	default:
		return "", false, fmt.Errorf("unknown normalize %q (want %q or empty)", normalize, core.NormalizeLowerTrim)
	}
	v, found := ec.getField(rec, path)
	s, isString := v.(string)
	if !found || !isString {
		return "", false, nil
	}
	s = norm(s)
	return s, s != "", nil
}

func lowerTrim(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// inSlotOnlySlots returns the slots a pass_when spec reads only as a
// matches_in in_slot — never as a clause's own slot. Their records are a
// lookup table, not resources under evaluation, so countResources leaves
// them out. A nil spec (rule: path) excludes nothing.
func inSlotOnlySlots(spec *core.PassWhenSpec) map[string]struct{} {
	if spec == nil {
		return nil
	}
	own := map[string]struct{}{}
	var conds []*core.PassWhenCondition
	for i := range spec.Clauses {
		own[spec.Clauses[i].Slot] = struct{}{}
		collectMatchesIn(spec.Clauses[i].Filter, &conds)
		collectMatchesIn(spec.Clauses[i].Condition, &conds)
	}
	out := map[string]struct{}{}
	for _, c := range conds {
		if _, isOwn := own[c.InSlot]; !isOwn {
			out[c.InSlot] = struct{}{}
		}
	}
	return out
}
