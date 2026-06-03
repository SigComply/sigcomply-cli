package evidencetypes

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/xeipuuv/gojsonschema"
)

// Validate checks that a JSON payload conforms to a schema document.
//
// Unlike the earlier hand-rolled checker (which only enforced
// "type":"object", "required", and the primitive type of top-level
// properties), this is a full JSON Schema draft-07 validation via
// gojsonschema. Every constraint a schema declares is now enforced:
// enum, format, pattern, minimum/maximum, additionalProperties, and —
// critically — nested object `properties` and array `items` are
// validated recursively. A schema that declares a constraint can now
// rely on it being checked, instead of it being silently decorative.
//
// Validation enforces the contract between a slot's `accepts:` list and
// the records bound sources emit: a payload that omits a required
// field, names a type wrong, or carries an out-of-enum value can never
// reach the evaluator. The collector calls Validate before signing; a
// failure surfaces as a configuration error (exit code 3).
func Validate(schema, payload json.RawMessage) error {
	if len(schema) == 0 {
		return fmt.Errorf("validate: empty schema")
	}
	if len(payload) == 0 {
		return fmt.Errorf("validate: empty payload")
	}
	compiled, err := compileSchema(schema)
	if err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	result, err := compiled.Validate(gojsonschema.NewBytesLoader(payload))
	if err != nil {
		// A loader-level error means the payload was not valid JSON, or
		// not the kind the schema's top-level type allows.
		return fmt.Errorf("validate: %w", err)
	}
	if result.Valid() {
		return nil
	}
	// Deterministic first error: gojsonschema does not guarantee order,
	// so pick the lexicographically smallest description. This keeps the
	// "same bad record fails the same way every run" property the
	// collector relies on for reproducible exit-3 diagnostics.
	errs := result.Errors()
	first := errs[0].String()
	for _, e := range errs[1:] {
		if s := e.String(); s < first {
			first = s
		}
	}
	return fmt.Errorf("validate: %s", strings.TrimSpace(first))
}

// schemaCache memoizes compiled schemas keyed by the SHA-256 of their
// bytes. The collector calls Validate once per record; without this a
// run with thousands of records of one type would recompile the same
// schema thousands of times. Schemas are embedded and immutable, so the
// cache never needs invalidation.
var (
	schemaCacheMu sync.RWMutex
	schemaCache   = map[[32]byte]*gojsonschema.Schema{}
)

func compileSchema(schema json.RawMessage) (*gojsonschema.Schema, error) {
	key := sha256.Sum256(schema)

	schemaCacheMu.RLock()
	cached, ok := schemaCache[key]
	schemaCacheMu.RUnlock()
	if ok {
		return cached, nil
	}

	compiled, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(schema))
	if err != nil {
		return nil, fmt.Errorf("compile schema: %w", err)
	}

	schemaCacheMu.Lock()
	schemaCache[key] = compiled
	schemaCacheMu.Unlock()
	return compiled, nil
}
