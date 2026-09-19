package orchestrator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
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

	cfg := &spec.ProjectConfig{Framework: testFramework}
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
	cfg := &spec.ProjectConfig{Framework: testFramework}
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

	cfg := &spec.ProjectConfig{Framework: testFramework}
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

const projectLocalRosterPolicyYAML = `schema_version: policy.v1
id: acme.custom.accounts_linked
control: ACME.CTL.2
severity: high
category: access
cadence: daily
evidence_mode: automated
description: Every active human account belongs to someone in the roster.
slots:
  roster:
    accepts: [roster_entry]
    cardinality: exactly-one
    required: true
    role: roster
  accounts:
    accepts: [directory_user]
    cardinality: one-or-more
    required: true
    role: roster_subject
pass_when:
  slot: accounts
  quantifier: all
  identity_key: account.ref
  filter:
    op: all_of
    conditions:
      - {op: eq, field: account.active, value: true}
      - {op: eq, field: account.non_human, value: false}
  condition:
    op: matches_in
    field: account.key
    in_slot: roster
    remote_field: payload.email
    normalize: lower_trim
    where: {op: neq, field: payload.status, value: inactive}
  violation_message: "account {{.account.ref}} is not linked to anyone in the roster"
`

func jsonRecord(t *testing.T, source, typ, id string, payload map[string]any) core.EvidenceRecord {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return core.EvidenceRecord{ID: id, Type: typ, SourceID: source, Payload: b}
}

// A YAML project-local policy using role slots and matches_in loads and
// evaluates end to end: aliases and non-human declarations from the
// roster link apply, the roster slot is left out of resources_evaluated,
// and the violation names the account by source-qualified ref.
func TestRegisterProjectLocal_RosterPolicyEvaluates(t *testing.T) {
	dir := t.TempDir()
	mustMkdir(t, filepath.Join(dir, ".sigcomply", "policies", "acme.custom.accounts_linked"))
	mustWrite(t, filepath.Join(dir, ".sigcomply", "policies", "acme.custom.accounts_linked", "policy.yaml"), projectLocalRosterPolicyYAML)

	set := registry.NewSet()
	if err := registerProjectLocal(dir, &spec.ProjectConfig{Framework: testFramework}, set); err != nil {
		t.Fatalf("registerProjectLocal: %v", err)
	}
	pol, ok := set.Policies.Lookup("acme.custom.accounts_linked")
	if !ok {
		t.Fatal("roster policy not registered")
	}

	const id = "acme.custom.accounts_linked"
	pp := planner.PlannedPolicy{
		Spec:           pol,
		ShouldEvaluate: true,
		Roster: &planner.RosterLink{
			Source:   sourceOkta,
			Aliases:  map[string]map[string]string{sourceGitHub: {"jdoe": "jane@acme.com"}},
			NonHuman: map[string][]string{sourceGitHub: {"acme-ci-bot"}},
		},
	}
	records := map[string][]core.EvidenceRecord{
		slotRoster: {
			jsonRecord(t, sourceOkta, "roster_entry", "p1", map[string]any{fieldEmail: "Jane@Acme.com", "status": "active"}),
			jsonRecord(t, sourceOkta, "roster_entry", "p2", map[string]any{fieldEmail: "left@acme.com", "status": "inactive"}),
		},
		slotAccounts: {
			jsonRecord(t, sourceGitHub, evidenceTypeDirectoryUser, "1", map[string]any{"username": "JDoe"}),
			jsonRecord(t, sourceGitHub, evidenceTypeDirectoryUser, "2", map[string]any{"username": "acme-ci-bot"}),
			jsonRecord(t, sourceAWSIAM, evidenceTypeDirectoryUser, "root", map[string]any{"is_root": true}),
			jsonRecord(t, "gitlab", evidenceTypeDirectoryUser, "9", map[string]any{fieldEmail: "left@acme.com"}),
		},
	}
	res, err := evaluator.Evaluate(context.Background(), &evaluator.Input{
		Plan:            &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{id: records},
		Now:             time.Now(),
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	r := res[0]
	if r.Status != core.StatusFail {
		t.Fatalf("status = %q (diag %v); want fail", r.Status, r.Diag)
	}
	if len(r.Violations) != 1 || r.Violations[0].ResourceID != "gitlab/9" {
		t.Fatalf("violations = %+v; want one for gitlab/9", r.Violations)
	}
	if want := "account gitlab/9 is not linked to anyone in the roster"; r.Violations[0].Reason != want {
		t.Errorf("reason = %q; want %q", r.Violations[0].Reason, want)
	}
	if r.ResourcesEvaluated != 4 || r.ResourcesFailed != 1 {
		t.Errorf("evaluated=%d failed=%d; want 4 and 1 (roster slot not counted)", r.ResourcesEvaluated, r.ResourcesFailed)
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
