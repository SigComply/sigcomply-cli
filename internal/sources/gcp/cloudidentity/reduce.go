package cloudidentity

import (
	"sort"
	"strings"

	ciapi "google.golang.org/api/cloudidentity/v1"
)

// reduce.go turns the flat list of `settings/security.password` policies
// the API returns into the ranked, field-by-field-resolved records the
// plugin emits.
//
// # Why a reduction is needed at all
//
// The Cloud Identity Policy API has NO effective-policy endpoint. It
// returns the policies an administrator created, each carrying only the
// fields that administrator explicitly set, and leaves the resolution to
// the caller. Google's documented rule is a per-field one: among the
// policies that apply to an identity, the highest `policyQuery.sortOrder`
// that SETS a field supplies that field's value. A policy on its own is
// therefore a fragment, not a rule in force, and emitting fragments would
// under-report — an OU policy that sets only `minimumLength` would look
// like a tenant with no expiry policy at all.
//
// # Which way sortOrder runs, and how it becomes `precedence`
//
// They run in OPPOSITE directions and one of them has to be inverted.
// Google's `sortOrder` is a decimal where the HIGHEST value wins;
// password_policy.v2's `precedence` is a rank where 1 wins (it was
// modeled on Okta's priority, which is already 1-is-highest). So the
// policies are sorted by sortOrder DESCENDING and `precedence` is the
// 1-based position in that order — position 1 is the highest sortOrder,
// i.e. the winner. Nothing arithmetic is done to the number itself:
// sortOrder is a sparse decimal with no defined range, so it is an
// ordering, and only the ordering survives into the record.
//
// # Defending the order against the 2026-09-01 SYSTEM-policy change
//
// Google shipped a documented BREAKING change to SYSTEM policies' `name`
// and `sortOrder` on 2026-09-01. Two consequences are handled here rather
// than assumed away.
//
//  1. SYSTEM policies are ranked BELOW every ADMIN policy regardless of
//     their sortOrder. A SYSTEM policy is Google's own baseline, not an
//     administrator's decision, so letting a renumbered system sortOrder
//     outrank an explicit admin setting would report the baseline as the
//     rule in force. Ordering by type first makes the ranking immune to
//     whatever Google renumbers next.
//  2. The order never depends on a SYSTEM policy's `name` for anything
//     but a final deterministic tie-break, and the emitted record ID is
//     the resource name as returned — stable output, and if Google
//     renames its system policies the effect is a changed record ID, not
//     a changed verdict.
//
// # The approximation, stated plainly
//
// Filling a policy's gaps requires knowing which lower-ranked policies
// also apply to its population, and that needs the org-unit tree, which
// this API does not return. What the API does give is a total order
// across all of the customer's policies for this setting type
// ("relative to all other policies with the same setting type for the
// customer... no duplicates within this set"), so the reduction walks
// that total order: each record is completed from the policies ranked
// below it. For the common shape — a root-OU or SYSTEM baseline plus a
// handful of narrower overrides — this is exactly Google's own rule,
// because the baseline applies to everyone. Where an estate has two
// genuinely disjoint branches, a gap may be filled from a sibling rather
// than from a shared ancestor. That is an approximation the docs record
// (docs/architecture/12-multicloud-sources.md) rather than one the code
// hides, and closing it means reading the OU tree from the Admin SDK —
// a second API, a second scope, and a second thing to get wrong.

// Canonical password_policy.v2 vocabulary this plugin emits.
const (
	providerGoogle         = "google_workspace"
	scopeAccount           = "account"
	scopeOrgUnit           = "org_unit"
	scopeGroup             = "group"
	complexityStrengthEnum = "strength_enum"
	strengthStrong         = "strong"
	strengthWeak           = "weak"
)

// The four attribute names `defaulted` (and `not_configurable`) are
// spelled with. They are a closed vocabulary shared with the schema, so
// they are constants rather than literals scattered through the mapper.
const (
	attrMinLength  = "min_length"
	attrMaxAgeDays = "max_age_days"
	attrReuse      = "reuse"
	attrComplexity = "complexity"
)

// Google's documented defaults for a field the tenant never set. These
// are NOT a fallback for an unread value — see the payload comment in
// cloudidentity.go for the distinction, which is the whole reason the
// `defaulted` marker exists.
const (
	defaultMinimumLength   = 8
	defaultAllowReuse      = false
	defaultExpirationDays  = 0
	defaultAllowedStrength = "STRONG"
)

// Google's allowedStrength enum, as sent on the wire.
const (
	googleStrengthStrong = "STRONG"
	googleStrengthWeak   = "WEAK"
)

// settingTypePassword is the Setting type this plugin consumes.
//
// Matching is EXACT. If Google ever versions the type string, this
// constant is the single line to change — a prefix or regex match here
// would be a second guess layered on the ones the package already has to
// make, and would risk silently consuming a differently-shaped value.
const settingTypePassword = "settings/security.password"

// rankedPolicy is one matched policy, already decoded and placed in the
// customer-wide order.
type rankedPolicy struct {
	// id is the policy resource name ("policies/{policy}") — unique
	// within the customer, which is exactly what the schema's `id`
	// requires (violations are deduplicated by it).
	id string
	// customer is "customers/{customerId}" as the API reported it, the
	// only honest source for the record's scope stamp: it is observed
	// rather than declared by the operator.
	customer string
	// system marks a Google-authored SYSTEM policy (see the file comment).
	system bool
	// sortOrder is Google's raw decimal, kept only for ordering.
	sortOrder float64
	// scope is the v2 scope this policy's PolicyQuery describes.
	scope   string
	setting passwordSetting
}

// matchPasswordPolicies filters the listing down to the password setting
// and decodes each value.
//
// The filter is CLIENT-SIDE on purpose. The API does support a server-side
// `filter` (`setting.type.matches('^settings/security\\.password$')`), and
// using it would be the obvious move — but the escaping of that regex is
// one of the three details Google publishes no example of, and a
// production collector in the wild reports `Error(7003)` for every escaped
// variant it tried. A filter that silently matches nothing would present
// as "this tenant has no password policy", i.e. as zero records and six
// vacuous passes: a wrong answer that looks like a legitimate one. Listing
// everything and comparing a string in Go cannot fail that way. The cost
// is a page or two extra at 1 QPS on a daily cadence, which is nothing.
func matchPasswordPolicies(policies []*ciapi.Policy) ([]rankedPolicy, error) {
	out := make([]rankedPolicy, 0, len(policies))
	for _, p := range policies {
		if p == nil || p.Setting == nil || p.Setting.Type != settingTypePassword {
			continue
		}
		ps, err := decodePasswordSetting(p.Setting.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, rankedPolicy{
			id:        p.Name,
			customer:  p.Customer,
			system:    p.Type == policyTypeSystem,
			sortOrder: querySortOrder(p.PolicyQuery),
			scope:     queryScope(p.PolicyQuery),
			setting:   ps,
		})
	}
	rank(out)
	return out, nil
}

// policyTypeSystem is the Policy.Type value for Google-authored baseline
// policies, as opposed to "ADMIN" for administrator-created ones.
const policyTypeSystem = "SYSTEM"

// queryScope maps a PolicyQuery onto the schema's scope vocabulary.
// Group is checked first: Google sets both helper fields when a query
// names a group inside an org unit, and the narrower population is the
// one the record describes. A query naming neither governs the whole
// customer, which is `account`.
func queryScope(q *ciapi.PolicyQuery) string {
	switch {
	case q == nil:
		return scopeAccount
	case strings.TrimSpace(q.Group) != "":
		return scopeGroup
	case strings.TrimSpace(q.OrgUnit) != "":
		return scopeOrgUnit
	default:
		return scopeAccount
	}
}

func querySortOrder(q *ciapi.PolicyQuery) float64 {
	if q == nil {
		return 0
	}
	return q.SortOrder
}

// rank orders policies highest-authority first: administrator policies
// before Google's SYSTEM baseline, then sortOrder descending (Google's
// direction: highest wins), then resource name ascending so two policies
// that tie produce byte-identical output on every run.
func rank(ps []rankedPolicy) {
	sort.SliceStable(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if a.system != b.system {
			return !a.system
		}
		if a.sortOrder != b.sortOrder {
			return a.sortOrder > b.sortOrder
		}
		return a.id < b.id
	})
}

// effective is one policy resolved against the ranked list: every field
// answered, and every field that fell through to Google's documented
// default flagged.
type effective struct {
	minLength        int64
	maxAgeDays       int64
	reusePrevented   bool
	passwordStrength string
	// strengthKnown is false when Google reported an allowedStrength this
	// plugin does not recognize. See mapStrength.
	strengthKnown bool
	defaulted     []string
}

// resolve answers every field for the policy at index i, consulting the
// policies ranked below it for anything i does not set, and falling back
// to Google's documented default when nothing in the order sets it.
//
// The `defaulted` marker names only the fields that reached that last
// step. A field inherited from a lower-ranked policy is NOT defaulted —
// an administrator did set it, just not on this policy.
func resolve(ranked []rankedPolicy, i int) effective {
	var eff effective

	if v := firstMinLength(ranked, i); v != nil {
		eff.minLength = int64(*v)
	} else {
		eff.minLength = defaultMinimumLength
		eff.defaulted = append(eff.defaulted, attrMinLength)
	}

	if v := firstExpiration(ranked, i); v != nil {
		eff.maxAgeDays = v.days()
	} else {
		eff.maxAgeDays = defaultExpirationDays
		eff.defaulted = append(eff.defaulted, attrMaxAgeDays)
	}

	if v := firstAllowReuse(ranked, i); v != nil {
		// Google states the PERMISSION ("may a previous password be set
		// again?"); the schema states the CONTROL ("is reuse prevented?").
		// The inversion belongs here, in the source — a clause containing
		// a vendor's polarity is how substitutability rots.
		eff.reusePrevented = !*v
	} else {
		eff.reusePrevented = !defaultAllowReuse
		eff.defaulted = append(eff.defaulted, attrReuse)
	}

	if v := firstStrength(ranked, i); v != nil {
		eff.passwordStrength, eff.strengthKnown = mapStrength(*v)
	} else {
		eff.passwordStrength, eff.strengthKnown = mapStrength(defaultAllowedStrength)
		if eff.strengthKnown {
			eff.defaulted = append(eff.defaulted, attrComplexity)
		}
	}

	return eff
}

// mapStrength translates Google's enum into the schema's.
//
// An unrecognized value — a new enum arm, or ALLOWED_STRENGTH_UNSPECIFIED
// — reports "not known" rather than erroring the run or picking a side.
// The caller then omits complexity_model and password_strength entirely,
// so the complexity clause filters the record out of scope and reports a
// vacuous clause: "nothing here was examined", which is true. Guessing
// `strong` would hand out a green tick on a value we could not read, and
// erroring would break a customer's CI because Google extended an enum.
func mapStrength(s string) (string, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case googleStrengthStrong:
		return strengthStrong, true
	case googleStrengthWeak:
		return strengthWeak, true
	default:
		return "", false
	}
}

// The four field-walkers below are spelled out rather than expressed
// through reflection or generics-over-struct-fields: each one names the
// field it reads, so a field added to passwordSetting that nobody wired
// in is visible as an absent walker rather than as a silently-skipped
// attribute.

func firstMinLength(ranked []rankedPolicy, from int) *flexInt {
	for i := from; i < len(ranked); i++ {
		if v := ranked[i].setting.MinimumLength; v != nil {
			return v
		}
	}
	return nil
}

func firstExpiration(ranked []rankedPolicy, from int) *flexDuration {
	for i := from; i < len(ranked); i++ {
		if v := ranked[i].setting.ExpirationDuration; v != nil {
			return v
		}
	}
	return nil
}

func firstAllowReuse(ranked []rankedPolicy, from int) *bool {
	for i := from; i < len(ranked); i++ {
		if v := ranked[i].setting.AllowReuse; v != nil {
			return v
		}
	}
	return nil
}

func firstStrength(ranked []rankedPolicy, from int) *string {
	for i := from; i < len(ranked); i++ {
		if v := ranked[i].setting.AllowedStrength; v != nil {
			return v
		}
	}
	return nil
}
