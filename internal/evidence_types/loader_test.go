package evidence_types

import (
	"encoding/json"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

func TestRegister_LoadsEmbeddedSchemas(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	for _, want := range []string{"user_record", "signed_document", "s3_bucket", "gcs_bucket"} {
		if _, ok := set.EvidenceTypes.Lookup(want); !ok {
			t.Errorf("expected %s in EvidenceTypes registry", want)
		}
	}
}

func TestRegister_RejectsNilSet(t *testing.T) {
	if err := Register(nil); err == nil {
		t.Fatal("expected error on nil set")
	}
}

func TestValidate_HappyPath(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	et, ok := set.EvidenceTypes.Lookup("user_record")
	if !ok {
		t.Fatal("user_record missing")
	}
	payload := json.RawMessage(`{"id":"u-1","user_name":"alice","mfa_enabled":true}`)
	if err := Validate(et.Schema, payload); err != nil {
		t.Errorf("expected pass; got %v", err)
	}
}

func TestValidate_RejectsMissingRequired(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	et, _ := set.EvidenceTypes.Lookup("user_record")
	payload := json.RawMessage(`{"id":"u-1"}`) // missing mfa_enabled
	err := Validate(et.Schema, payload)
	if err == nil {
		t.Fatal("expected error for missing required field")
	}
}

func TestValidate_RejectsWrongFieldType(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	et, _ := set.EvidenceTypes.Lookup("user_record")
	payload := json.RawMessage(`{"id":"u-1","mfa_enabled":"yes"}`) // string, not bool
	err := Validate(et.Schema, payload)
	if err == nil {
		t.Fatal("expected type-mismatch error")
	}
}

func TestValidate_AllowsExtraFields(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	et, _ := set.EvidenceTypes.Lookup("user_record")
	payload := json.RawMessage(`{"id":"u-1","mfa_enabled":true,"unknown_field":42}`)
	if err := Validate(et.Schema, payload); err != nil {
		t.Errorf("additional properties should be allowed; got %v", err)
	}
}

func TestValidate_RejectsNonObjectPayload(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	et, _ := set.EvidenceTypes.Lookup("user_record")
	err := Validate(et.Schema, json.RawMessage(`[1,2,3]`))
	if err == nil {
		t.Fatal("expected error for non-object payload")
	}
}

func TestValidate_RejectsEmptyInputs(t *testing.T) {
	if err := Validate(nil, json.RawMessage(`{"id":"x","mfa_enabled":true}`)); err == nil {
		t.Error("expected error on empty schema")
	}
	if err := Validate(json.RawMessage(`{"type":"object"}`), nil); err == nil {
		t.Error("expected error on empty payload")
	}
}
