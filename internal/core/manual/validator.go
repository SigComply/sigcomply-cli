package manual

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

var (
	schemaOnce     sync.Once
	compiledSchema *jsonschema.Schema
	compileErr     error
)

// ValidateSubmittedEvidence validates raw JSON bytes against the SubmittedEvidence schema.
// Returns a nil error if the document conforms; otherwise a human-readable error describing
// which field failed validation. This upgrades confusing downstream errors (e.g. "no items
// checked") into upfront schema violations (e.g. "missing required property: items").
func ValidateSubmittedEvidence(data []byte) error {
	schema, err := loadSchema()
	if err != nil {
		return fmt.Errorf("load schema: %w", err)
	}

	var doc interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}

	if err := schema.Validate(doc); err != nil {
		return fmt.Errorf("schema violation: %w", err)
	}
	return nil
}

func loadSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		raw, err := json.Marshal(SubmittedEvidenceSchema())
		if err != nil {
			compileErr = err
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource("submitted-evidence.json", bytes.NewReader(raw)); err != nil {
			compileErr = err
			return
		}
		compiledSchema, compileErr = c.Compile("submitted-evidence.json")
	})
	return compiledSchema, compileErr
}
