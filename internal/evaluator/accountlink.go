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
//   - account.key       lower_trim(alias ?? payload.email ?? "")
//   - account.linked_by "alias" | "email" | "none"
//   - account.non_human listed in the roster's non_human map, or payload.is_root == true
//   - account.active    payload.is_active, or true when absent
//
// Alias and non-human entries are looked up per source by the record's
// lowercased id or lowercased payload.username — never display_name,
// which is free text and not unique.
const accountFieldPrefix = "account."

const (
	linkedByAlias = "alias"
	linkedByEmail = "email"
	linkedByNone  = "none"
)

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
	}
	if isRoot, ok := payload["is_root"].(bool); ok && isRoot {
		link.nonHuman = true
	}
	if !link.nonHuman && ec.roster != nil {
		listed := ec.roster.NonHuman[rec.SourceID]
		link.nonHuman = slices.ContainsFunc(names, func(n string) bool { return slices.Contains(listed, n) })
	}
	if active, ok := payload["is_active"].(bool); ok {
		link.active = active
	}
	return link
}

// accountNames are the lowercased names an alias or non-human entry can
// refer to: the record id and, when present, payload.username.
func accountNames(rec *core.EvidenceRecord, payload map[string]any) []string {
	names := []string{lowerTrim(rec.ID)}
	if u, ok := payload["username"].(string); ok && lowerTrim(u) != "" {
		names = append(names, lowerTrim(u))
	}
	return names
}

func (ec *evalCtx) aliasFor(sourceID string, names []string) string {
	if ec.roster == nil {
		return ""
	}
	aliases := ec.roster.Aliases[sourceID]
	for _, n := range names {
		if email := lowerTrim(aliases[n]); email != "" {
			return email
		}
	}
	return ""
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
