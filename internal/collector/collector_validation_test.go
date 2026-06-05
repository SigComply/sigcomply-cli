package collector

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

// directoryUserSchema is a minimal JSON Schema draft-07 document used to
// exercise the collector's schema-validation path (validateRecords).
const directoryUserSchema = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["mfa_enabled"],
  "properties": {
    "mfa_enabled": {"type": "boolean"}
  }
}`

func registerDirectoryUserType(t *testing.T, reg *registry.Set) {
	t.Helper()
	if err := reg.EvidenceTypes.Register(core.EvidenceType{
		ID:      "directory_user",
		Version: 1,
		Schema:  json.RawMessage(directoryUserSchema),
	}); err != nil {
		t.Fatalf("register evidence type: %v", err)
	}
}

// A record whose payload conforms to the registered schema passes
// validation and is signed/persisted.
func TestCollect_SchemaValidation_ConformingRecordPasses(t *testing.T) {
	reg := registry.NewSet()
	registerDirectoryUserType(t, reg)
	src := &stubSource{
		id: "aws.iam", emits: []string{"directory_user"},
		records: []core.EvidenceRecord{
			{Type: "directory_user", ID: "u1", SourceID: "aws.iam", Payload: json.RawMessage(`{"mfa_enabled": true}`)},
		},
	}
	mustRegister(t, reg.Sources.Register(src))
	pp := makePolicy("p1", "u", "directory_user", "aws.iam")
	out, err := Collect(context.Background(), &Input{
		Plan:          &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Sources:       reg.Sources,
		EvidenceTypes: reg.EvidenceTypes,
		Vault:         newMemVault(),
		RunRoot:       "r",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if out.CollectErrorsByPolicy["p1"] != nil {
		t.Errorf("conforming record should not error: %v", out.CollectErrorsByPolicy["p1"])
	}
	if len(out.RecordsByPolicy["p1"]["u"]) != 1 {
		t.Errorf("expected 1 record; got %d", len(out.RecordsByPolicy["p1"]["u"]))
	}
}

// A record violating the schema (missing required field / wrong type)
// tags the policy with a collect error — exit code 3 semantics.
func TestCollect_SchemaValidation_NonConformingRecordTagsPolicy(t *testing.T) {
	reg := registry.NewSet()
	registerDirectoryUserType(t, reg)
	src := &stubSource{
		id: "aws.iam", emits: []string{"directory_user"},
		records: []core.EvidenceRecord{
			// mfa_enabled is a string, schema requires boolean → fails.
			{Type: "directory_user", ID: "u1", SourceID: "aws.iam", Payload: json.RawMessage(`{"mfa_enabled": "yes"}`)},
		},
	}
	mustRegister(t, reg.Sources.Register(src))
	pp := makePolicy("p1", "u", "directory_user", "aws.iam")
	out, err := Collect(context.Background(), &Input{
		Plan:          &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Sources:       reg.Sources,
		EvidenceTypes: reg.EvidenceTypes,
		Vault:         newMemVault(),
		RunRoot:       "r",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := out.CollectErrorsByPolicy["p1"]
	if got == nil || !strings.Contains(got.Error(), "schema validation") {
		t.Errorf("want schema-validation error; got %v", got)
	}
}

// A record whose Type has no registered schema is a plugin contract bug
// (emitted a type outside its own Emits()) and tags the policy.
func TestCollect_SchemaValidation_UnregisteredTypeTagsPolicy(t *testing.T) {
	reg := registry.NewSet()
	// Note: directory_user is NOT registered as an evidence type, but the
	// source emits it and the binding accepts it.
	src := &stubSource{
		id: "aws.iam", emits: []string{"directory_user"},
		records: []core.EvidenceRecord{
			{Type: "directory_user", ID: "u1", SourceID: "aws.iam", Payload: json.RawMessage(`{}`)},
		},
	}
	mustRegister(t, reg.Sources.Register(src))
	pp := makePolicy("p1", "u", "directory_user", "aws.iam")
	out, err := Collect(context.Background(), &Input{
		Plan:          &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Sources:       reg.Sources,
		EvidenceTypes: reg.EvidenceTypes, // empty registry
		Vault:         newMemVault(),
		RunRoot:       "r",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := out.CollectErrorsByPolicy["p1"]
	if got == nil || !strings.Contains(got.Error(), "no registered schema") {
		t.Errorf("want no-registered-schema error; got %v", got)
	}
}

// A plugin that returns a record whose Type is outside the binding's
// AcceptedTypes is a contract violation surfaced as a collect error.
func TestCollect_RecordOutsideAcceptedTypes_TagsPolicy(t *testing.T) {
	reg := registry.NewSet()
	src := &stubSource{
		id: "aws.iam", emits: []string{"directory_user"},
		records: []core.EvidenceRecord{
			{Type: "unexpected_type", ID: "u1", SourceID: "aws.iam"},
		},
	}
	mustRegister(t, reg.Sources.Register(src))
	pp := makePolicy("p1", "u", "directory_user", "aws.iam")
	out, err := Collect(context.Background(), &Input{
		Plan:    &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Sources: reg.Sources,
		Vault:   newMemVault(),
		RunRoot: "r",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := out.CollectErrorsByPolicy["p1"]
	if got == nil || !strings.Contains(got.Error(), "outside the binding's AcceptedTypes") {
		t.Errorf("want accepted-types violation; got %v", got)
	}
}

// failingVault returns an error from PutEnvelope so writeEnvelope's
// error branch is exercised.
type failingVault struct{ *memVault }

func (failingVault) PutEnvelope(context.Context, string, *core.Envelope) error {
	return errors.New("vault write failed")
}

func TestCollect_EnvelopeWriteFailure_TagsPolicy(t *testing.T) {
	reg := registry.NewSet()
	src := &stubSource{
		id: "aws.iam", emits: []string{"directory_user"},
		records: []core.EvidenceRecord{{Type: "directory_user", ID: "u1", SourceID: "aws.iam"}},
	}
	mustRegister(t, reg.Sources.Register(src))
	pp := makePolicy("p1", "u", "directory_user", "aws.iam")
	out, err := Collect(context.Background(), &Input{
		Plan:    &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		Sources: reg.Sources,
		Vault:   failingVault{newMemVault()},
		RunRoot: "r",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := out.CollectErrorsByPolicy["p1"]
	if got == nil || !strings.Contains(got.Error(), "write envelope") {
		t.Errorf("want write-envelope error; got %v", got)
	}
}

// Collect with a nil vault errors out at the top level.
func TestCollect_NilVaultErrors(t *testing.T) {
	reg := registry.NewSet()
	_, err := Collect(context.Background(), &Input{
		Plan:    &planner.RunPlan{},
		Sources: reg.Sources,
		Vault:   nil,
	})
	if err == nil || !strings.Contains(err.Error(), "nil vault") {
		t.Errorf("want nil-vault error; got %v", err)
	}
}

// A carry-forward (ShouldEvaluate=false) policy collects no evidence —
// no plugin call, no envelope.
func TestCollect_CarryForwardSkipsCollection(t *testing.T) {
	reg := registry.NewSet()
	src := &stubSource{id: "aws.iam", emits: []string{"directory_user"},
		records: []core.EvidenceRecord{{Type: "directory_user", ID: "u1"}}}
	mustRegister(t, reg.Sources.Register(src))
	pp := makePolicy("p1", "u", "directory_user", "aws.iam")
	pp.ShouldEvaluate = false
	vault := newMemVault()
	if _, err := Collect(context.Background(), &Input{
		Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}}, Sources: reg.Sources, Vault: vault, RunRoot: "r",
	}); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if src.calls != 0 {
		t.Errorf("carry-forward must not call Collect; got %d calls", src.calls)
	}
	if len(vault.envelopes) != 0 {
		t.Errorf("carry-forward must write no envelopes; got %d", len(vault.envelopes))
	}
}
