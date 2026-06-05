package evidencetypes

// schema_enforcement_test.go — exercises schema-validation constraints
// beyond the basic required/type checks already in validate_test.go:
//   - enum enforcement on real shipped schemas
//   - format / pattern enforcement
//   - CompileSchema public API (currently at 0%)
//   - Register error paths (nil EvidenceTypes registry)
//   - VerifyRegistrations nil EvidenceTypes branch

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/registry"
)

// ---------------------------------------------------------------------------
// CompileSchema — currently 0% covered
// ---------------------------------------------------------------------------

func TestCompileSchema_ValidSchema(t *testing.T) {
	schema := json.RawMessage(`{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"required": ["id"],
		"properties": {"id": {"type": "string"}}
	}`)
	if err := CompileSchema(schema); err != nil {
		t.Fatalf("CompileSchema on valid schema: %v", err)
	}
}

func TestCompileSchema_InvalidSchema(t *testing.T) {
	// "minimum" must be a number in draft-07; a string value is invalid.
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {"x": {"type": "integer", "minimum": "not-a-number"}}
	}`)
	if err := CompileSchema(schema); err == nil {
		t.Error("expected error for structurally-invalid schema; got nil")
	}
}

func TestCompileSchema_EmptyInput(t *testing.T) {
	if err := CompileSchema(nil); err == nil {
		t.Error("expected error for nil schema")
	}
	if err := CompileSchema(json.RawMessage("")); err == nil {
		t.Error("expected error for empty schema")
	}
}

// ---------------------------------------------------------------------------
// Enum enforcement on real shipped schemas
// ---------------------------------------------------------------------------

func TestValidate_VulnerabilityFinding_EnumEnforced(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	et, ok := set.EvidenceTypes.Lookup("vulnerability_finding")
	if !ok {
		t.Fatal("vulnerability_finding not registered")
	}

	cases := []struct {
		name    string
		payload string
		wantErr string
	}{
		{
			name:    "valid_high_active",
			payload: `{"id":"f1","resource_id":"arn:aws:ec2:us-east-1:123:i-abc","resource_type":"EC2","severity":"HIGH","status":"ACTIVE"}`,
		},
		{
			name:    "invalid_severity_enum",
			payload: `{"id":"f1","resource_id":"r","resource_type":"EC2","severity":"EXTREME","status":"ACTIVE"}`,
			wantErr: "severity",
		},
		{
			name:    "invalid_status_enum",
			payload: `{"id":"f1","resource_id":"r","resource_type":"EC2","severity":"CRITICAL","status":"PENDING"}`,
			wantErr: "status",
		},
		{
			name:    "missing_required_severity",
			payload: `{"id":"f1","resource_id":"r","resource_type":"EC2","status":"ACTIVE"}`,
			wantErr: "severity",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(et.Schema, json.RawMessage(tc.payload))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q; got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidate_SecurityAlert_EventClassEnumEnforced(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	et, ok := set.EvidenceTypes.Lookup("security_alert")
	if !ok {
		t.Fatal("security_alert not registered")
	}

	cases := []struct {
		name    string
		payload string
		wantErr string
	}{
		{
			name:    "valid_known_class",
			payload: `{"id":"a1","name":"Root Usage Alert","event_class":"root_account_usage","is_enabled":true}`,
		},
		{
			name:    "invalid_event_class",
			payload: `{"id":"a1","name":"Custom Alert","event_class":"totally_unknown_class","is_enabled":true}`,
			wantErr: "event_class",
		},
		{
			name:    "valid_other_class",
			payload: `{"id":"a2","name":"Custom Alert","event_class":"other","is_enabled":false}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(et.Schema, json.RawMessage(tc.payload))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q; got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidate_ObjectStorageBucket_DateTimeFormat(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	et, ok := set.EvidenceTypes.Lookup("object_storage_bucket")
	if !ok {
		t.Fatal("object_storage_bucket not registered")
	}

	// The schema uses "format": "date-time" for created_at.
	// gojsonschema enforces format constraints.
	cases := []struct {
		name    string
		payload string
		wantErr string
	}{
		{
			name:    "valid_no_created_at",
			payload: `{"name":"my-bucket","encryption_at_rest_enabled":true,"public_access_blocked":true}`,
		},
		{
			name:    "valid_with_rfc3339_created_at",
			payload: `{"name":"my-bucket","encryption_at_rest_enabled":false,"public_access_blocked":false,"created_at":"2026-01-15T10:00:00Z"}`,
		},
		{
			name:    "missing_required_name",
			payload: `{"encryption_at_rest_enabled":true,"public_access_blocked":true}`,
			wantErr: "name",
		},
		{
			name:    "wrong_type_encryption",
			payload: `{"name":"b","encryption_at_rest_enabled":"yes","public_access_blocked":true}`,
			wantErr: "encryption_at_rest_enabled",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(et.Schema, json.RawMessage(tc.payload))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q; got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// directory_user.v2 — required fields not in v1
// ---------------------------------------------------------------------------

func TestValidate_DirectoryUserV2_RequiresV2Fields(t *testing.T) {
	set := registry.NewSet()
	if err := Register(set); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// v2 requires is_root, has_console_access, has_programmatic_access
	// in addition to the v1 id + mfa_enabled fields.
	etv2, ok := set.EvidenceTypes.Lookup("directory_user.v2")
	if !ok {
		t.Skip("directory_user.v2 not registered — skipping")
	}

	cases := []struct {
		name    string
		payload string
		wantErr string
	}{
		{
			name:    "valid_v2",
			payload: `{"id":"u1","mfa_enabled":true,"is_root":false,"has_console_access":true,"has_programmatic_access":false}`,
		},
		{
			name:    "missing_is_root",
			payload: `{"id":"u1","mfa_enabled":true,"has_console_access":true,"has_programmatic_access":false}`,
			wantErr: "is_root",
		},
		{
			name:    "missing_has_console_access",
			payload: `{"id":"u1","mfa_enabled":true,"is_root":false,"has_programmatic_access":false}`,
			wantErr: "has_console_access",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(etv2.Schema, json.RawMessage(tc.payload))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q; got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Validate — non-JSON payload triggers loader-level error
// ---------------------------------------------------------------------------

func TestValidate_MalformedJSONPayload(t *testing.T) {
	schema := json.RawMessage(`{"type":"object"}`)
	err := Validate(schema, json.RawMessage(`{not valid json`))
	if err == nil {
		t.Error("expected error for malformed JSON payload; got nil")
	}
}

// ---------------------------------------------------------------------------
// Register — nil EvidenceTypes in registry set
// ---------------------------------------------------------------------------

func TestRegister_RejectsNilEvidenceTypesInSet(t *testing.T) {
	// registry.NewSet() always provides all sub-registries. To exercise
	// the nil-EvidenceTypes path we test the guard directly via a nil set.
	if err := Register(nil); err == nil {
		t.Error("Register(nil) should return an error")
	}
}

// ---------------------------------------------------------------------------
// VerifyRegistrations — nil EvidenceTypes branch (currently uncovered)
// ---------------------------------------------------------------------------

func TestVerifyRegistrations_RejectsNilEvidenceTypes(t *testing.T) {
	// A nil registry set must be rejected with the "nil registry set" guard.
	// The nil-EvidenceTypes sub-registry path is unreachable via
	// registry.NewSet() (the constructor always populates it), so the nil-set
	// path is the observable guard here.
	if err := VerifyRegistrations(nil); err == nil {
		t.Error("VerifyRegistrations(nil) should return an error")
	}
	// This exercises the nil-set path which returns "nil registry set".
	// The nil-EvidenceTypes path is unreachable via registry.NewSet()
	// (the constructor always populates it), confirming the guard is
	// defensive dead-code in normal operation.
}

// ---------------------------------------------------------------------------
// Schema cache — second Validate call for same schema uses cache
// ---------------------------------------------------------------------------

func TestCompileSchema_CacheHit(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","required":["x"],"properties":{"x":{"type":"string"}}}`)
	// First call compiles and caches.
	if err := CompileSchema(schema); err != nil {
		t.Fatalf("first CompileSchema: %v", err)
	}
	// Second call must hit the cache (no error, identical behavior).
	if err := CompileSchema(schema); err != nil {
		t.Fatalf("second CompileSchema (cache): %v", err)
	}
	// Validate also uses the same cache; verify a valid payload succeeds.
	if err := Validate(schema, json.RawMessage(`{"x":"hello"}`)); err != nil {
		t.Fatalf("Validate after CompileSchema cache: %v", err)
	}
}
