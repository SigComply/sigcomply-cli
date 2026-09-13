package spec

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// RosterKey is the subkey under `experimental:` that designates the
// organization's roster source. Like experimental.scope it lives under
// the escape hatch so a config written for a newer CLI keeps loading on
// an older pinned one (docs/architecture/08-project-config.md §Config
// evolution policy).
const RosterKey = "roster"

// RosterConfig designates the one source whose people are the
// authoritative roster, plus the operator's declarations for accounts
// that cannot be linked to the roster by email alone.
//
// The roster must come from a system other than the one being checked:
// the planner never binds the roster source to a policy's accounts slot
// (a directory cannot vouch for its own accounts).
//
// Nothing in here crosses the aggregation boundary. Aliases carry email
// addresses and account names — identity data that must never reach the
// cloud payload (root CLAUDE.md §Privacy invariant).
type RosterConfig struct {
	// Source is the designated roster source ID. Required when the
	// block is present. Bracketed multi-instance IDs are not supported.
	Source string

	// Aliases maps source ID → lowercased account name → roster email,
	// for accounts whose own email is absent or differs from the
	// roster's. Account names match a record's id or payload.username,
	// case-insensitively.
	Aliases map[string]map[string]string

	// NonHuman maps source ID → lowercased account names that are not
	// people (CI bots, deploy users). Sorted and de-duplicated.
	NonHuman map[string][]string

	// UnknownKeys are subkeys of experimental.roster this CLI does not
	// understand — tolerated, never fatal, but surfaced as warnings.
	UnknownKeys []string
}

var knownRosterKeys = map[string]struct{}{
	"source":    {},
	"aliases":   {},
	"non_human": {},
}

// LoadRosterConfig projects the experimental.roster block out of a
// loaded project config. It returns (nil, nil) when the block is absent:
// no roster source is designated, so roster slots stay unbound and the
// policies that need one are skipped.
//
// Validation here is shape-only. Whether the named sources are
// configured, and whether the roster source emits what a roster slot
// accepts, needs the registries and belongs to the planner.
func LoadRosterConfig(cfg *ProjectConfig) (*RosterConfig, error) {
	if cfg == nil || cfg.Experimental == nil {
		return nil, nil
	}
	raw, ok := cfg.Experimental[RosterKey]
	if !ok || raw == nil {
		return nil, nil
	}
	asMap, ok := stringKeyedMap(raw)
	if !ok {
		return nil, fmt.Errorf("project config: experimental.roster must be a mapping with a source key, e.g. {source: okta}")
	}

	out := &RosterConfig{}
	for k := range asMap {
		if _, known := knownRosterKeys[k]; !known {
			out.UnknownKeys = append(out.UnknownKeys, k)
		}
	}
	sort.Strings(out.UnknownKeys)

	source, err := parseRosterSource(asMap["source"])
	if err != nil {
		return nil, err
	}
	out.Source = source

	if out.Aliases, err = parseRosterAliases(asMap["aliases"]); err != nil {
		return nil, err
	}
	if out.NonHuman, err = parseRosterNonHuman(asMap["non_human"]); err != nil {
		return nil, err
	}
	return out, nil
}

func parseRosterSource(v any) (string, error) {
	s, ok := v.(string)
	if v != nil && !ok {
		return "", fmt.Errorf("project config: experimental.roster.source must be a single source ID, e.g. source: okta")
	}
	if strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("project config: experimental.roster.source is required: name the one configured source that holds the organization's roster, e.g. source: okta")
	}
	if strings.ContainsAny(s, "[]") {
		return "", fmt.Errorf("project config: experimental.roster.source: %q: bracketed multi-instance source IDs are not supported for the roster source", s)
	}
	return s, nil
}

func parseRosterAliases(v any) (map[string]map[string]string, error) {
	if v == nil {
		return nil, nil
	}
	bySource, ok := stringKeyedMap(v)
	if !ok {
		return nil, fmt.Errorf("project config: experimental.roster.aliases must map source IDs to {account: email} mappings, e.g. aliases: {github: {jdoe: jane@example.com}}")
	}
	out := make(map[string]map[string]string, len(bySource))
	for sourceID, accountsRaw := range bySource {
		accounts, ok := stringKeyedMap(accountsRaw)
		if !ok {
			return nil, fmt.Errorf("project config: experimental.roster.aliases[%q] must be a mapping of account name to roster email", sourceID)
		}
		m := make(map[string]string, len(accounts))
		for name, emailRaw := range accounts {
			key := normalizeAccountName(name)
			if key == "" {
				return nil, fmt.Errorf("project config: experimental.roster.aliases[%q]: empty account name", sourceID)
			}
			email, isStr := emailRaw.(string)
			email = strings.TrimSpace(email)
			if !isStr || email == "" {
				return nil, fmt.Errorf("project config: experimental.roster.aliases[%q][%q]: alias must be a non-empty roster email", sourceID, name)
			}
			if prev, dup := m[key]; dup && prev != email {
				return nil, fmt.Errorf("project config: experimental.roster.aliases[%q]: account %q is listed more than once (names are case-insensitive) with different emails", sourceID, key)
			}
			m[key] = email
		}
		out[sourceID] = m
	}
	return out, nil
}

func parseRosterNonHuman(v any) (map[string][]string, error) {
	if v == nil {
		return nil, nil
	}
	bySource, ok := stringKeyedMap(v)
	if !ok {
		return nil, fmt.Errorf("project config: experimental.roster.non_human must map source IDs to lists of account names, e.g. non_human: {github: [acme-ci-bot]}")
	}
	out := make(map[string][]string, len(bySource))
	for sourceID, listRaw := range bySource {
		list, ok := listRaw.([]any)
		if !ok {
			return nil, fmt.Errorf("project config: experimental.roster.non_human[%q] must be a list of account names", sourceID)
		}
		seen := make(map[string]struct{}, len(list))
		names := make([]string, 0, len(list))
		for i, item := range list {
			name, isScalar := scalarString(item)
			key := normalizeAccountName(name)
			if !isScalar || key == "" {
				return nil, fmt.Errorf("project config: experimental.roster.non_human[%q][%d]: must be a non-empty account name", sourceID, i)
			}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			names = append(names, key)
		}
		sort.Strings(names)
		out[sourceID] = names
	}
	return out, nil
}

// normalizeAccountName is the case-insensitive form account names are
// stored and matched in.
func normalizeAccountName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// stringKeyedMap accepts the two shapes yaml.v3 decodes a mapping into.
// A mapping with a non-string key (an unquoted numeric account name such
// as `1234:`) arrives as map[any]any; its keys are stringified.
func stringKeyedMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			s, ok := scalarString(k)
			if !ok {
				return nil, false
			}
			out[s] = val
		}
		return out, true
	default:
		return nil, false
	}
}

// scalarString renders a YAML string or integer scalar as a string. An
// unquoted numeric account name (a GitHub login of digits) decodes as an
// int; anything else (maps, lists, booleans) is not an account name.
func scalarString(v any) (string, bool) {
	switch s := v.(type) {
	case string:
		return s, true
	case int:
		return strconv.Itoa(s), true
	case int64:
		return strconv.FormatInt(s, 10), true
	case uint64:
		return strconv.FormatUint(s, 10), true
	default:
		return "", false
	}
}
