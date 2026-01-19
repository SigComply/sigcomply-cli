package attestation

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalJSON_SortsMapKeys(t *testing.T) {
	// Map with keys that would be randomly ordered
	data := map[string]string{
		"zebra":    "z",
		"apple":    "a",
		"mango":    "m",
		"banana":   "b",
		"cherry":   "c",
		"date":     "d",
		"elephant": "e",
	}

	result, err := CanonicalJSON(data)
	require.NoError(t, err)

	// Keys should be alphabetically sorted in output
	expected := `{"apple":"a","banana":"b","cherry":"c","date":"d","elephant":"e","mango":"m","zebra":"z"}`
	assert.Equal(t, expected, string(result))
}

func TestCanonicalJSON_NestedMaps(t *testing.T) {
	data := map[string]interface{}{
		"z_outer": map[string]interface{}{
			"b_inner": "value1",
			"a_inner": "value2",
		},
		"a_outer": "simple",
	}

	result, err := CanonicalJSON(data)
	require.NoError(t, err)

	// Both outer and inner maps should have sorted keys
	expected := `{"a_outer":"simple","z_outer":{"a_inner":"value2","b_inner":"value1"}}`
	assert.Equal(t, expected, string(result))
}

func TestCanonicalJSON_Deterministic(t *testing.T) {
	// Run multiple times to catch non-determinism
	data := map[string]interface{}{
		"key3": "value3",
		"key1": "value1",
		"key2": map[string]string{
			"nested2": "n2",
			"nested1": "n1",
		},
	}

	var results []string
	for i := 0; i < 100; i++ {
		result, err := CanonicalJSON(data)
		require.NoError(t, err)
		results = append(results, string(result))
	}

	// All results should be identical
	for i := 1; i < len(results); i++ {
		assert.Equal(t, results[0], results[i], "Iteration %d produced different result", i)
	}
}

func TestCanonicalJSON_SlicesPreserveOrder(t *testing.T) {
	data := map[string]interface{}{
		"items": []string{"third", "first", "second"},
	}

	result, err := CanonicalJSON(data)
	require.NoError(t, err)

	// Slice order should be preserved (not sorted)
	expected := `{"items":["third","first","second"]}`
	assert.Equal(t, expected, string(result))
}

func TestCanonicalJSON_StructFields(t *testing.T) {
	type Inner struct {
		B string `json:"b"`
		A string `json:"a"`
	}
	type Outer struct {
		Z     string `json:"z"`
		Inner Inner  `json:"inner"`
		A     string `json:"a"`
	}

	data := Outer{
		Z:     "last",
		Inner: Inner{B: "b_val", A: "a_val"},
		A:     "first",
	}

	result, err := CanonicalJSON(data)
	require.NoError(t, err)

	// Struct fields should be sorted by JSON key name
	expected := `{"a":"first","inner":{"a":"a_val","b":"b_val"},"z":"last"}`
	assert.Equal(t, expected, string(result))
}

func TestCanonicalJSON_MapWithInterfaceValues(t *testing.T) {
	// This is like Violation.Details - map[string]interface{}
	data := map[string]interface{}{
		"z_string":  "text",
		"m_number":  42,
		"a_boolean": true,
		"b_null":    nil,
		"c_nested": map[string]interface{}{
			"inner_z": "z",
			"inner_a": "a",
		},
	}

	result, err := CanonicalJSON(data)
	require.NoError(t, err)

	// All map keys should be sorted, including nested
	expected := `{"a_boolean":true,"b_null":null,"c_nested":{"inner_a":"a","inner_z":"z"},"m_number":42,"z_string":"text"}`
	assert.Equal(t, expected, string(result))
}

func TestCanonicalJSON_EmptyStructures(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"empty map", map[string]string{}, "{}"},
		{"empty slice", []string{}, "[]"},
		{"nil", nil, "null"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CanonicalJSON(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

func TestCanonicalJSON_SpecialCharacters(t *testing.T) {
	data := map[string]string{
		"key": "value with \"quotes\" and \\ backslash",
	}

	result, err := CanonicalJSON(data)
	require.NoError(t, err)

	// Should properly escape special characters
	var parsed map[string]string
	err = json.Unmarshal(result, &parsed)
	require.NoError(t, err)
	assert.Equal(t, data["key"], parsed["key"])
}

func TestCanonicalJSON_Unicode(t *testing.T) {
	data := map[string]string{
		"emoji":    "👍",
		"chinese":  "中文",
		"japanese": "日本語",
	}

	result, err := CanonicalJSON(data)
	require.NoError(t, err)

	// Should handle unicode correctly
	var parsed map[string]string
	err = json.Unmarshal(result, &parsed)
	require.NoError(t, err)
	assert.Equal(t, data, parsed)
}

func TestHashCanonicalJSON_Deterministic(t *testing.T) {
	// Test with a structure that would be non-deterministic with regular json.Marshal
	data := map[string]interface{}{
		"details": map[string]interface{}{
			"z_field": "last",
			"a_field": "first",
			"nested": map[string]string{
				"c": "3",
				"a": "1",
				"b": "2",
			},
		},
	}

	var hashes []string
	for i := 0; i < 100; i++ {
		hash, err := HashCanonicalJSON(data)
		require.NoError(t, err)
		hashes = append(hashes, hash)
	}

	// All hashes should be identical
	for i := 1; i < len(hashes); i++ {
		assert.Equal(t, hashes[0], hashes[i], "Iteration %d produced different hash", i)
	}
}

func TestHashCanonicalJSON_DifferentFromStandardJSON(t *testing.T) {
	// This test documents that canonical JSON may produce different output
	// than standard json.Marshal for maps (due to key sorting)
	data := map[string]string{
		"z": "last",
		"a": "first",
	}

	canonicalResult, err := CanonicalJSON(data)
	require.NoError(t, err)

	// Canonical should always be sorted
	assert.Equal(t, `{"a":"first","z":"last"}`, string(canonicalResult))
}
