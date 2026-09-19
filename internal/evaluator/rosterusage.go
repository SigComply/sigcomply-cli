package evaluator

import (
	"sort"
	"sync"

	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

// RosterKey identifies one declared roster entry: the source ID keying
// the aliases / non_human map and the account name inside it. Both are
// already lowercased by the config loader.
type RosterKey struct {
	SourceID string
	Name     string
}

// RosterUsage accumulates, across a whole run, which experimental.roster
// account names actually met a collected account.
//
// The source-ID half of a typo is fatal at plan time
// (planner.checkRosterSourceKeys). The account-name half cannot be: only
// the evaluator ever sees the universe of account names, and it sees it
// one record at a time. So the keys are recorded as they match and the
// leftovers — declared minus matched — are what the orchestrator warns
// about.
//
// It must be run-scoped, not per-policy. The planner copies the same
// Aliases/NonHuman maps into every roster policy's RosterLink, but each
// policy gets its own evalCtx over its own bound accounts; a per-policy
// verdict would call an alias unused in the policy whose accounts slot
// did not bind that source even though the sibling policy used it.
//
// Nothing here crosses the aggregation boundary: these are account names
// and source IDs, which is identity data. It reaches local stdout only.
//
// The zero value is not usable; call NewRosterUsage. A nil *RosterUsage
// is a no-op accumulator, which is what every caller that does not care
// (rule: policies, most tests) passes.
type RosterUsage struct {
	mu sync.Mutex
	// declared and matched are keyed the same way; unused is the
	// difference. Sets, never slices: resolveAccount runs once per
	// account.* field reference per record with no memoization.
	declaredAliases  map[RosterKey]struct{}
	matchedAliases   map[RosterKey]struct{}
	declaredNonHuman map[RosterKey]struct{}
	matchedNonHuman  map[RosterKey]struct{}
}

// NewRosterUsage returns an empty, ready-to-use accumulator for one run.
// It collects which experimental.roster alias and non_human keys actually
// matched a collected account, run-scoped across every policy evaluated,
// so the orchestrator can warn about the keys that matched nothing — the
// typo half no plan-time check can catch.
func NewRosterUsage() *RosterUsage {
	return &RosterUsage{
		declaredAliases:  map[RosterKey]struct{}{},
		matchedAliases:   map[RosterKey]struct{}{},
		declaredNonHuman: map[RosterKey]struct{}{},
		matchedNonHuman:  map[RosterKey]struct{}{},
	}
}

// Declare records every key a policy's roster link carries. It is called
// for each policy the run actually evaluates — never for one that is
// carried forward or excepted, which looks at no account and so can
// prove nothing about a key. Idempotent: every roster policy in a run
// declares the same maps.
func (u *RosterUsage) Declare(link *planner.RosterLink) {
	if u == nil || link == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for sourceID, byName := range link.Aliases {
		for name := range byName {
			u.declaredAliases[RosterKey{SourceID: sourceID, Name: name}] = struct{}{}
		}
	}
	for sourceID, names := range link.NonHuman {
		for _, name := range names {
			u.declaredNonHuman[RosterKey{SourceID: sourceID, Name: name}] = struct{}{}
		}
	}
}

func (u *RosterUsage) markAlias(sourceID, name string) {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.matchedAliases[RosterKey{SourceID: sourceID, Name: name}] = struct{}{}
}

func (u *RosterUsage) markNonHuman(sourceID, name string) {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.matchedNonHuman[RosterKey{SourceID: sourceID, Name: name}] = struct{}{}
}

// UnusedAliases returns the declared alias keys no collected account
// carried, sorted by source then name. Nil when there are none.
func (u *RosterUsage) UnusedAliases() []RosterKey {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return difference(u.declaredAliases, u.matchedAliases)
}

// UnusedNonHuman is UnusedAliases for the non_human map.
func (u *RosterUsage) UnusedNonHuman() []RosterKey {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return difference(u.declaredNonHuman, u.matchedNonHuman)
}

func difference(declared, matched map[RosterKey]struct{}) []RosterKey {
	var out []RosterKey
	for k := range declared {
		if _, used := matched[k]; !used {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceID != out[j].SourceID {
			return out[i].SourceID < out[j].SourceID
		}
		return out[i].Name < out[j].Name
	})
	return out
}
