package orchestrator

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

const projectLocalPolicyYAML = `schema_version: policy.v1
id: acme.custom.contractor_access
control: ACME.CTL.1
severity: medium
category: access
cadence: quarterly
evidence_mode: automated
description: Contractor access is reviewed each quarter.
slots:
  reviews:
    accepts: [acme_review]
    cardinality: one-or-more
    required: true
pass_when:
  slot: reviews
  quantifier: all
  condition:
    op: eq
    field: payload.approved
    value: true
`

const projectLocalEvidenceTypeJSON = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://example.com/acme_review/v1.json",
  "title": "acme_review",
  "version": 1,
  "type": "object",
  "required": ["id"],
  "properties": { "id": { "type": "string" }, "approved": { "type": "boolean" } }
}
`

const projectLocalRuleRego = `package acme.rules.contractor_v1

result := {"status": "pass"}
`

// writeProjectLocal lays out a .sigcomply/ tree under dir with one
// evidence type, one policy, and one Rego rule.
func writeProjectLocal(t *testing.T, dir string) {
	t.Helper()
	mustMkdir(t, filepath.Join(dir, ".sigcomply", "evidence_types"))
	mustMkdir(t, filepath.Join(dir, ".sigcomply", "policies", "acme.custom.contractor_access"))
	mustMkdir(t, filepath.Join(dir, ".sigcomply", "policies", "acme.rule_only"))

	mustWrite(t, filepath.Join(dir, ".sigcomply", "evidence_types", "acme_review.v1.json"), projectLocalEvidenceTypeJSON)
	mustWrite(t, filepath.Join(dir, ".sigcomply", "policies", "acme.custom.contractor_access", "policy.yaml"), projectLocalPolicyYAML)
	mustWrite(t, filepath.Join(dir, ".sigcomply", "policies", "acme.rule_only", "rule.rego"), projectLocalRuleRego)
}

func TestRegisterProjectLocal_RegistersAllThreeKinds(t *testing.T) {
	dir := t.TempDir()
	writeProjectLocal(t, dir)

	cfg := &spec.ProjectConfig{Framework: "soc2"}
	set := registry.NewSet()

	if err := registerProjectLocal(dir, cfg, set); err != nil {
		t.Fatalf("registerProjectLocal: %v", err)
	}

	// Evidence type registered under its title.
	if _, ok := set.EvidenceTypes.Lookup("acme_review"); !ok {
		t.Error("evidence type acme_review not registered")
	}
	// Policy registered AND its ref recorded on cfg for the planner.
	if _, ok := set.Policies.Lookup("acme.custom.contractor_access"); !ok {
		t.Error("policy acme.custom.contractor_access not registered")
	}
	if len(cfg.ProjectLocalPolicies) != 1 || cfg.ProjectLocalPolicies[0].PolicyID != "acme.custom.contractor_access" {
		t.Errorf("cfg.ProjectLocalPolicies = %+v; want one ref to acme.custom.contractor_access", cfg.ProjectLocalPolicies)
	}
	// Rego rule registered under its package path.
	if _, ok := set.Rules.Lookup("acme.rules.contractor_v1"); !ok {
		t.Error("rego rule acme.rules.contractor_v1 not registered")
	}
}

func TestRegisterProjectLocal_NoSigcomplyDirIsNoOp(t *testing.T) {
	dir := t.TempDir() // no .sigcomply/
	cfg := &spec.ProjectConfig{Framework: "soc2"}
	set := registry.NewSet()
	if err := registerProjectLocal(dir, cfg, set); err != nil {
		t.Fatalf("registerProjectLocal on empty project: %v", err)
	}
	if len(cfg.ProjectLocalPolicies) != 0 {
		t.Errorf("expected no project-local policies; got %d", len(cfg.ProjectLocalPolicies))
	}
}

func TestRegisterProjectLocal_MalformedPolicyIsConfigError(t *testing.T) {
	dir := t.TempDir()
	mustMkdir(t, filepath.Join(dir, ".sigcomply", "policies", "bad"))
	mustWrite(t, filepath.Join(dir, ".sigcomply", "policies", "bad", "policy.yaml"), "schema_version: policy.v1\nid: bad\n")

	cfg := &spec.ProjectConfig{Framework: "soc2"}
	if err := registerProjectLocal(dir, cfg, registry.NewSet()); err == nil {
		t.Error("expected a configuration error for a malformed policy.yaml")
	}
}

func TestRegoPackage(t *testing.T) {
	cases := map[string]string{
		"package a.b.c\nresult := 1\n":               "a.b.c",
		"# comment\n\npackage x\n":                   "x",
		"   package  sigcomply.rules.v2  \nx := 1\n": "sigcomply.rules.v2",
	}
	for in, want := range cases {
		got, err := regoPackage([]byte(in))
		if err != nil {
			t.Errorf("regoPackage(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("regoPackage(%q) = %q; want %q", in, got, want)
		}
	}
	if _, err := regoPackage([]byte("x := 1\n")); err == nil {
		t.Error("expected error when first line is not a package declaration")
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
