package spec

import (
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// ScopeKey is the subkey under `experimental:` that carries the estate
// declaration. It lives under the escape hatch rather than at the top
// level so a config written for a newer CLI keeps loading on an older
// pinned one — the loader runs with KnownFields(true), which would
// hard-fail any brand-new top-level key. See
// docs/architecture/08-project-config.md §Config evolution policy.
const ScopeKey = "scope"

// ScopeConfig is the operator's declaration of the estate this project
// asserts coverage over — the authoritative baseline the run is checked
// against, and the auditor-legible scope object.
//
// Without it the CLI can only evaluate the evidence it happened to
// collect, against itself: a source the operator forgot to configure
// leaves its policies with an unbound required slot, which is skipped at
// evaluation and drops out of the compliance-score denominator. The run
// then reports a perfect score for an estate it never looked at. The
// declaration is what turns that silence into a finding.
//
// Semantics are deliberately per-project, not per-organization: one
// project is one repo is one framework (ARCHITECTURE.md Core Principle
// #9), so this declares the estate *this project* asserts coverage over.
// Rolling several projects up into one view is the Cloud dashboard's job.
//
// Nothing in here crosses the aggregation boundary. DeclaredBy is an
// email address and must never reach the cloud payload (root CLAUDE.md
// §Privacy invariant); the scope report is a vault-side artifact only.
type ScopeConfig struct {
	// DeclaredBy and DeclaredAt are the audit trail for the assertion,
	// matching the approved_by/approved_at idiom used by exceptions and
	// control applicability. Both optional.
	DeclaredBy string
	DeclaredAt string

	// RequiredSources lists the source IDs this project asserts are in
	// scope. Sorted on load so the derived report is deterministic
	// (Core Principle #7 — auditors diff runs).
	RequiredSources []string

	// UnknownKeys are subkeys of experimental.scope this CLI does not
	// understand. They are tolerated, never fatal — that tolerance is
	// the whole point of the experimental: hatch — but they are
	// surfaced so a typo is loud without breaking the run.
	UnknownKeys []string
}

// scopeRaw mirrors the YAML shape. Decoded leniently (no KnownFields):
// unknown subkeys are reported, not rejected.
type scopeRaw struct {
	DeclaredBy      string   `yaml:"declared_by"`
	DeclaredAt      string   `yaml:"declared_at"`
	RequiredSources []string `yaml:"required_sources"`
}

// knownScopeKeys is the set scopeRaw understands, used to report the
// rest rather than to reject them.
var knownScopeKeys = map[string]struct{}{
	"declared_by":      {},
	"declared_at":      {},
	"required_sources": {},
}

// LoadScopeConfig projects the experimental.scope block out of a loaded
// project config. It returns (nil, nil) when the block is absent — the
// undeclared case, which leaves every existing behaviour untouched.
//
// Validation here is shape-only. Whether a declared source ID actually
// exists is a cross-reference question that needs the registries, and so
// belongs to the planner (see the layering note on LoadProjectConfig).
func LoadScopeConfig(cfg *ProjectConfig) (*ScopeConfig, error) {
	if cfg == nil || cfg.Experimental == nil {
		return nil, nil
	}
	raw, ok := cfg.Experimental[ScopeKey]
	if !ok || raw == nil {
		return nil, nil
	}

	// experimental: decodes into map[string]any, so the original
	// yaml.Node is gone by the time we get here. Round-tripping through
	// the marshaller is what gives us a typed decode; the cost is that
	// error messages carry no line numbers, which is acceptable for a
	// block this small.
	asMap, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("project config: experimental.scope must be a mapping of scope settings")
	}

	// Check the one non-scalar field's shape up front. The round-trip
	// above costs us line numbers, and yaml's own type error names the Go
	// type rather than the YAML key ("cannot unmarshal !!str into
	// []string"), which is not a message a hand-editing operator can act
	// on. Naming the key is worth the extra branch.
	if v, present := asMap["required_sources"]; present {
		if _, isList := v.([]any); !isList {
			return nil, fmt.Errorf("project config: experimental.scope.required_sources must be a list of source IDs, e.g. [aws.iam, github]")
		}
	}

	buf, err := yaml.Marshal(asMap)
	if err != nil {
		return nil, fmt.Errorf("project config: experimental.scope: %w", err)
	}
	var rawScope scopeRaw
	if err := yaml.Unmarshal(buf, &rawScope); err != nil {
		return nil, fmt.Errorf("project config: experimental.scope: %w", err)
	}

	out := &ScopeConfig{
		DeclaredBy: rawScope.DeclaredBy,
		DeclaredAt: rawScope.DeclaredAt,
	}
	for k := range asMap {
		if _, known := knownScopeKeys[k]; !known {
			out.UnknownKeys = append(out.UnknownKeys, k)
		}
	}
	sort.Strings(out.UnknownKeys)

	if err := validateOptionalDate(rawScope.DeclaredAt); err != nil {
		return nil, fmt.Errorf("project config: experimental.scope.declared_at: %w", err)
	}

	if len(rawScope.RequiredSources) == 0 {
		return nil, fmt.Errorf("project config: experimental.scope: required_sources must list at least one source (remove the scope block entirely to leave the estate undeclared)")
	}
	seen := make(map[string]struct{}, len(rawScope.RequiredSources))
	for i, id := range rawScope.RequiredSources {
		if id == "" {
			return nil, fmt.Errorf("project config: experimental.scope.required_sources[%d]: empty source ID", i)
		}
		if _, dup := seen[id]; dup {
			return nil, fmt.Errorf("project config: experimental.scope.required_sources: duplicate source ID %q", id)
		}
		seen[id] = struct{}{}
		out.RequiredSources = append(out.RequiredSources, id)
	}
	sort.Strings(out.RequiredSources)

	return out, nil
}
