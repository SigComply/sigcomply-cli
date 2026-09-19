package evaluator

import (
	"encoding/json"
	"slices"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// accountFieldPrefix introduces the virtual account-link fields. They are
// defined on every record, so a policy can use them without knowing which
// source produced the account:
//
//   - account.ref       source_id + "/" + id — unique across sources
//   - account.key       lower_trim(alias ?? payload.email ?? payload.principal_id ?? "")
//   - account.linked_by "alias" | "email" | "principal" | "none"
//   - account.non_human listed in the roster's non_human map, payload.is_root == true,
//     or a payload.principal_type naming something other than a person
//   - account.active    payload.is_active, or true when absent
//
// Alias and non-human entries are looked up per source by the record's
// lowercased id, lowercased payload.username or lowercased
// payload.principal_id — never display_name, which is free text and not
// unique.
//
// payload.principal_id is what lets an IAM grant join the roster.
// An iam_binding record carries neither email nor username, and its id
// is "<role>|<member>" — the name of a grant, not of a person. Without
// the principal fallback every binding would resolve to an empty key,
// which is not merely unhelpful: it would mass-fail the linked-to-roster
// policies for every project that collects IAM bindings.
const accountFieldPrefix = "account."

const (
	linkedByAlias     = "alias"
	linkedByEmail     = "email"
	linkedByPrincipal = "principal"
	linkedByNone      = "none"
)

// principalTypeUser is the iam_binding principal_type of a human. Every
// other non-empty value — service_account, group, and a passed-through
// prefix such as domain — names a principal no workforce directory can
// list, so it is non-human by construction rather than by declaration.
//
// An empty principal_type is treated as human on purpose. It is what
// allUsers and allAuthenticatedUsers carry (they have no prefix to map),
// and a public binding is the last thing that should fall out of the
// population: it can never match a roster entry, so it is reported.
// Reporting a grant we cannot classify is fail-safe; dropping it is not.
const principalTypeUser = "user"

// accountLink is the resolved set of account.* values for one record.
type accountLink struct {
	ref      string
	key      string
	linkedBy string
	nonHuman bool
	active   bool
}

func (ec *evalCtx) resolveAccount(rec *core.EvidenceRecord) accountLink {
	var payload map[string]any
	if len(rec.Payload) > 0 {
		_ = json.Unmarshal(rec.Payload, &payload) //nolint:errcheck // an undecodable payload simply has no account facts
	}
	names := accountNames(rec, payload)
	link := accountLink{
		ref:      rec.SourceID + "/" + rec.ID,
		linkedBy: linkedByNone,
		active:   true,
	}
	if alias := ec.aliasFor(rec.SourceID, names); alias != "" {
		link.key, link.linkedBy = alias, linkedByAlias
	} else if email, ok := payload["email"].(string); ok && lowerTrim(email) != "" {
		link.key, link.linkedBy = lowerTrim(email), linkedByEmail
	} else if principal, ok := payload["principal_id"].(string); ok && lowerTrim(principal) != "" {
		link.key, link.linkedBy = lowerTrim(principal), linkedByPrincipal
	}
	if isRoot, ok := payload["is_root"].(bool); ok && isRoot {
		link.nonHuman = true
	}
	if pt, ok := payload["principal_type"].(string); ok && lowerTrim(pt) != "" && lowerTrim(pt) != principalTypeUser {
		link.nonHuman = true
	}
	// Consulted even when the record is already non-human by
	// construction (is_root, a non-person principal_type): a declared
	// name that matched a real account is used, and skipping the lookup
	// would report it as a typo it is not.
	if ec.nonHumanListed(rec.SourceID, names) {
		link.nonHuman = true
	}
	if active, ok := payload["is_active"].(bool); ok {
		link.active = active
	}
	return link
}

// accountNames are the lowercased names an alias or non-human entry can
// refer to: the record id and, when present, payload.username or
// payload.principal_id. The principal is included because it is the only
// name in an IAM grant an operator can recognize — the record id names
// the grant, not the person holding it.
func accountNames(rec *core.EvidenceRecord, payload map[string]any) []string {
	names := []string{lowerTrim(rec.ID)}
	for _, f := range []string{"username", "principal_id"} {
		if v, ok := payload[f].(string); ok && lowerTrim(v) != "" {
			names = append(names, lowerTrim(v))
		}
	}
	return names
}

// aliasFor returns the roster email declared for any of the record's
// names, and records every key that matched. Every matching name is
// marked, not just the first: a key shadowed by an earlier name still
// names a real account, and reporting it as unused would be a lie.
func (ec *evalCtx) aliasFor(sourceID string, names []string) string {
	if ec.roster == nil {
		return ""
	}
	aliases := ec.roster.Aliases[sourceID]
	if len(aliases) == 0 {
		return ""
	}
	found := ""
	for _, n := range names {
		email, declared := aliases[n]
		if !declared {
			continue
		}
		ec.usage.markAlias(sourceID, n)
		if normalized := lowerTrim(email); normalized != "" && found == "" {
			found = normalized
		}
	}
	return found
}

// nonHumanListed reports whether any of the record's names is declared
// non-human for its source, recording each key that matched.
func (ec *evalCtx) nonHumanListed(sourceID string, names []string) bool {
	if ec.roster == nil {
		return false
	}
	listed := ec.roster.NonHuman[sourceID]
	if len(listed) == 0 {
		return false
	}
	hit := false
	for _, n := range names {
		if slices.Contains(listed, n) {
			ec.usage.markNonHuman(sourceID, n)
			hit = true
		}
	}
	return hit
}

// accountField resolves account.<name>; ok is false for an unknown name.
func (ec *evalCtx) accountField(rec *core.EvidenceRecord, name string) (any, bool) {
	v, ok := ec.accountContext(rec)[name]
	return v, ok
}

// accountContext is the account.* map exposed to getField and to
// violation_message templates ({{.account.ref}}).
func (ec *evalCtx) accountContext(rec *core.EvidenceRecord) map[string]any {
	link := ec.resolveAccount(rec)
	return map[string]any{
		"ref":       link.ref,
		"key":       link.key,
		"linked_by": link.linkedBy,
		"non_human": link.nonHuman,
		"active":    link.active,
	}
}
