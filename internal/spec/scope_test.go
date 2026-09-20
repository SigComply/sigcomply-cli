package spec_test

import (
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// loadScope is the common path under test: parse a full project config,
// then project its experimental.scope block.
func loadScope(t *testing.T, body string) (*spec.ScopeConfig, error) {
	t.Helper()
	cfg, err := spec.LoadProjectConfig([]byte(body))
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}
	return spec.LoadScopeConfig(&cfg)
}

const scopeBase = `schema_version: project.v1
framework: soc2
sources:
  aws.iam: {}
  github: {}
`

func TestLoadScopeConfig_AbsentIsUndeclared(t *testing.T) {
	sc, err := loadScope(t, scopeBase)
	if err != nil {
		t.Fatalf("LoadScopeConfig: %v", err)
	}
	if sc != nil {
		t.Fatalf("scope = %+v; want nil when experimental.scope is absent", sc)
	}
}

func TestLoadScopeConfig_ExperimentalWithoutScopeIsUndeclared(t *testing.T) {
	sc, err := loadScope(t, scopeBase+`experimental:
  some_other_knob: true
`)
	if err != nil {
		t.Fatalf("LoadScopeConfig: %v", err)
	}
	if sc != nil {
		t.Fatalf("scope = %+v; want nil", sc)
	}
}

func TestLoadScopeConfig_Full(t *testing.T) {
	sc, err := loadScope(t, scopeBase+`experimental:
  scope:
    declared_by: ciso@example.com
    declared_at: "2026-09-13"
    required_sources:
      - github
      - aws.iam
`)
	if err != nil {
		t.Fatalf("LoadScopeConfig: %v", err)
	}
	if sc == nil {
		t.Fatal("scope = nil; want a declaration")
	}
	if sc.DeclaredBy != "ciso@example.com" {
		t.Errorf("DeclaredBy = %q", sc.DeclaredBy)
	}
	if sc.DeclaredAt != "2026-09-13" {
		t.Errorf("DeclaredAt = %q", sc.DeclaredAt)
	}
	// Sorted for determinism (Core Principle #7) regardless of file order.
	if len(sc.RequiredSources) != 2 || sc.RequiredSources[0] != testSourceAWSIAM || sc.RequiredSources[1] != testSourceGitHub {
		t.Errorf("RequiredSources = %v; want sorted [aws.iam github]", sc.RequiredSources)
	}
}

// Unknown subkeys must NOT be fatal: docs/architecture/08-project-config.md
// §Config evolution policy promises that every CLI recognizing
// `experimental:` tolerates and ignores subkeys it does not understand, so
// a newer config never hard-fails an older pinned CLI. They are collected
// so the orchestrator can warn.
func TestLoadScopeConfig_UnknownKeysTolerated(t *testing.T) {
	sc, err := loadScope(t, scopeBase+`experimental:
  scope:
    required_sources: [github]
    future_knob: 42
    another_one: hello
`)
	if err != nil {
		t.Fatalf("unknown subkeys must not be fatal; got %v", err)
	}
	if sc == nil {
		t.Fatal("scope = nil")
	}
	if len(sc.UnknownKeys) != 2 || sc.UnknownKeys[0] != "another_one" || sc.UnknownKeys[1] != "future_knob" {
		t.Errorf("UnknownKeys = %v; want sorted [another_one future_knob]", sc.UnknownKeys)
	}
}

func TestLoadScopeConfig_Rejects(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "empty required_sources",
			body: "experimental:\n  scope:\n    required_sources: []\n",
			want: "required_sources must list at least one source",
		},
		{
			name: "blank source id",
			body: "experimental:\n  scope:\n    required_sources: [\"\"]\n",
			want: "required_sources[0]: empty source ID",
		},
		{
			name: "duplicate source id",
			body: "experimental:\n  scope:\n    required_sources: [github, github]\n",
			want: "duplicate source ID \"github\"",
		},
		{
			name: caseBadDeclaredAt,
			body: "experimental:\n  scope:\n    required_sources: [github]\n    declared_at: \"13/09/2026\"\n",
			want: "declared_at",
		},
		{
			name: "scope not a mapping",
			body: "experimental:\n  scope: [github]\n",
			want: "experimental.scope must be a mapping",
		},
		{
			name: "required_sources not a list",
			body: "experimental:\n  scope:\n    required_sources: github\n",
			want: "required_sources",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadScope(t, scopeBase+c.body)
			if err == nil {
				t.Fatalf("want error containing %q; got nil", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v; want it to contain %q", err, c.want)
			}
		})
	}
}

// A pass_when clause naming an undeclared slot is a silent compliance
// bypass, not a cosmetic typo: the evaluator looks the slot up by name,
// an unmatched name yields an empty record set, and all/none pass
// vacuously over one. The check would report green while examining
// nothing, so the loader must refuse it.
func TestLoadPolicy_RejectsClauseNamingUndeclaredSlot(t *testing.T) {
	const policy = `schema_version: policy.v1
id: acme.test.typo
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "Typo slot name"
slots:
  users:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: userz
  quantifier: all
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
`
	_, err := spec.LoadPolicy([]byte(policy))
	if err == nil {
		t.Fatal("want an error for a clause naming an undeclared slot; got nil")
	}
	for _, want := range []string{"userz", "does not declare", "users"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v; want it to mention %q", err, want)
		}
	}
}

func TestLoadPolicy_AcceptsDeclaredSlot(t *testing.T) {
	const policy = `schema_version: policy.v1
id: acme.test.ok
control: SOC2.CC6.1
severity: high
cadence: daily
evidence_mode: automated
description: "Correct slot name"
slots:
  users:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
pass_when:
  slot: users
  quantifier: all
  condition:
    op: eq
    field: payload.mfa_enabled
    value: true
`
	if _, err := spec.LoadPolicy([]byte(policy)); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
}
