package evidencetypes

import (
	"encoding/json"
	"fmt"
	"sort"
)

// typeObject is the only top-level schema type this validator
// supports. Repeated three times (top-level guard, object check,
// error messages) so it lives as a named constant.
const typeObject = "object"

// Validate checks that a JSON payload conforms to a schema document.
// The check is deliberately a small subset of JSON Schema draft-07:
//
//   - "type": "object" — payload must unmarshal as a JSON object
//   - "required": [...] — every listed key must be present
//   - "properties": {...} — each present key's value must match the
//     declared type when the property's schema names one
//
// This subset is what every in-tree evidence-type schema uses today
// and what any sensible third-party schema will use. Richer features
// (anyOf, patternProperties, format checks beyond a string type) are
// deferred — adding them is additive.
//
// Validation enforces the contract between a slot's `accepts:` list
// and the records bound sources emit: a payload that omits a required
// field, or misnames a type, can never reach the evaluator. The
// collector calls Validate before signing; a failure surfaces as a
// configuration error (exit code 3).
func Validate(schema, payload json.RawMessage) error {
	if len(schema) == 0 {
		return fmt.Errorf("validate: empty schema")
	}
	if len(payload) == 0 {
		return fmt.Errorf("validate: empty payload")
	}
	var s schemaDoc
	if err := json.Unmarshal(schema, &s); err != nil {
		return fmt.Errorf("validate: parse schema: %w", err)
	}
	if s.Type != "" && s.Type != typeObject {
		return fmt.Errorf("validate: schema top-level type %q not supported (only %q)", s.Type, typeObject)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(payload, &obj); err != nil {
		return fmt.Errorf("validate: payload not a JSON object: %w", err)
	}
	for _, key := range s.Required {
		if _, ok := obj[key]; !ok {
			return fmt.Errorf("validate: required field %q missing", key)
		}
	}
	if len(s.Properties) > 0 {
		// Deterministic walk so the first failure is the same across
		// runs.
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			prop, ok := s.Properties[k]
			if !ok || prop.Type == "" {
				continue
			}
			if err := checkType(k, prop.Type, obj[k]); err != nil {
				return err
			}
		}
	}
	return nil
}

// schemaDoc is the subset of JSON Schema this validator inspects.
type schemaDoc struct {
	Type       string                 `json:"type"`
	Required   []string               `json:"required"`
	Properties map[string]propertyDoc `json:"properties"`
}

type propertyDoc struct {
	Type string `json:"type"`
}

func checkType(key, wantType string, raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		// JSON null is acceptable for any property — the schema's
		// `required` array already enforces presence vs. absence.
		return nil
	}
	checker, ok := typeCheckers[wantType]
	if !ok {
		return nil
	}
	return checker(key, raw)
}

// typeCheckers dispatches the per-type validation. Lifted out of
// checkType so each case is a small function and the table itself
// keeps cyclomatic complexity in checkType trivial.
var typeCheckers = map[string]func(key string, raw json.RawMessage) error{
	"string": func(key string, raw json.RawMessage) error {
		var v string
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("validate: field %q: expected string, got %s", key, kindOf(raw))
		}
		return nil
	},
	"boolean": func(key string, raw json.RawMessage) error {
		var v bool
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("validate: field %q: expected boolean, got %s", key, kindOf(raw))
		}
		return nil
	},
	"integer": func(key string, raw json.RawMessage) error {
		// JSON Schema "integer" is stricter than json.Number, but
		// pragmatically we accept 3 and 3.0 (3.5 is rejected).
		var v float64
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("validate: field %q: expected integer, got %s", key, kindOf(raw))
		}
		if v != float64(int64(v)) {
			return fmt.Errorf("validate: field %q: expected integer, got non-integer number", key)
		}
		return nil
	},
	"number": func(key string, raw json.RawMessage) error {
		var v float64
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("validate: field %q: expected number, got %s", key, kindOf(raw))
		}
		return nil
	},
	typeObject: func(key string, raw json.RawMessage) error {
		var v map[string]json.RawMessage
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("validate: field %q: expected object, got %s", key, kindOf(raw))
		}
		return nil
	},
	"array": func(key string, raw json.RawMessage) error {
		var v []json.RawMessage
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("validate: field %q: expected array, got %s", key, kindOf(raw))
		}
		return nil
	},
}

// kindOf produces a short label for the actual JSON kind so error
// messages stay readable without dumping the entire payload bytes.
func kindOf(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "<empty>"
	}
	switch raw[0] {
	case '"':
		return "string"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	case '{':
		return "object"
	case '[':
		return "array"
	default:
		return "number"
	}
}
