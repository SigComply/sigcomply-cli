package sourcetest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
)

// This file is the L2 fixture-vs-spec seam (WU-1.4). A recorded cassette's
// response bodies are validated against the slice of the vendor's own OpenAPI
// model committed under contracts/<provider>/, so a cassette that drifts from
// the real response shape — or a spec slice that no longer matches what we
// record — fails the per-PR suite. It complements the schema/completeness
// checks in conformance.go (which guard our *mapped* records) by guarding the
// *raw vendor responses* the mappers are written against.

// SpecValidator validates decoded JSON values against component schemas from a
// trimmed OpenAPI 3.0 spec snapshot. Internal "#/components/schemas/..." refs
// are resolved on load; doc.Validate is deliberately skipped so a hand-trimmed
// slice (pared-down paths/info) still loads.
type SpecValidator struct {
	doc *openapi3.T
}

// NewSpecValidator loads an OpenAPI spec slice (e.g.
// "../../../contracts/github/api.github.com@2026-06-28.json") for validation.
func NewSpecValidator(t *testing.T, specPath string) *SpecValidator {
	t.Helper()
	data, err := os.ReadFile(specPath) //nolint:gosec // test-controlled fixed path
	if err != nil {
		t.Fatalf("sourcetest: read spec %q: %v", specPath, err)
	}
	loader := openapi3.NewLoader() // IsExternalRefsAllowed defaults false → offline
	doc, err := loader.LoadFromData(data)
	if err != nil {
		t.Fatalf("sourcetest: load spec %q: %v", specPath, err)
	}
	return &SpecValidator{doc: doc}
}

// Check validates a decoded JSON value (map/slice/scalar from encoding/json)
// against the named component schema. It returns the validation error rather
// than failing t, so negative tests can assert that an off-spec value is
// rejected. An unknown component name is itself an error.
func (v *SpecValidator) Check(component string, value any) error {
	ref := v.doc.Components.Schemas[component]
	if ref == nil || ref.Value == nil {
		return fmt.Errorf("component %q not in spec", component)
	}
	if err := ref.Value.VisitJSON(value, openapi3.MultiErrors()); err != nil {
		return fmt.Errorf("component %q: %w", component, err)
	}
	return nil
}

// CheckArray validates each element of an array value against the named
// component schema, prefixing element errors with their index.
func (v *SpecValidator) CheckArray(component string, value any) error {
	arr, ok := value.([]any)
	if !ok {
		return fmt.Errorf("component %q: expected JSON array, got %T", component, value)
	}
	var errs []error
	for i, el := range arr {
		if err := v.Check(component, el); err != nil {
			errs = append(errs, fmt.Errorf("[%d]: %w", i, err))
		}
	}
	return errors.Join(errs...)
}

// LoadCassetteInteractions loads a go-vcr cassette (path without ".yaml") and
// returns its interactions, for tests that replay recorded responses against a
// spec. It is read-only — no recorder/transport is started.
func LoadCassetteInteractions(t *testing.T, cassetteName string) []*cassette.Interaction {
	t.Helper()
	cs, err := cassette.Load(cassetteName)
	if err != nil {
		t.Fatalf("sourcetest: load cassette %q: %v", cassetteName, err)
	}
	return cs.Interactions
}

// DecodeJSONBody decodes an interaction's response body into an `any` value for
// spec validation. Empty bodies (204/304) decode to (nil, false).
func DecodeJSONBody(t *testing.T, body string) (value any, ok bool) {
	t.Helper()
	if strings.TrimSpace(body) == "" {
		return nil, false
	}
	if err := json.Unmarshal([]byte(body), &value); err != nil {
		t.Fatalf("sourcetest: decode response body: %v\nbody: %.200s", err, body)
	}
	return value, true
}
