package attestation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// CanonicalJSON serializes a value to JSON with deterministic ordering.
// Map keys are sorted alphabetically at all nesting levels.
// This ensures that the same data always produces the same JSON output,
// which is critical for cryptographic hashing.
func CanonicalJSON(v interface{}) ([]byte, error) {
	normalized := normalize(v)
	return json.Marshal(normalized)
}

// HashCanonicalJSON computes the SHA-256 hash of a value using canonical JSON serialization.
// This is the recommended way to hash structures containing maps.
func HashCanonicalJSON(v interface{}) (string, error) {
	data, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return HashData(data), nil
}

// normalize recursively converts a value into a form that will serialize deterministically.
// Maps are converted to sortedMap which serializes keys in sorted order.
// Slices and arrays are processed element by element.
// Structs are converted to sorted maps based on JSON field names.
func normalize(v interface{}) interface{} {
	if v == nil {
		return nil
	}

	val := reflect.ValueOf(v)
	return normalizeValue(val)
}

func normalizeValue(val reflect.Value) interface{} {
	// Handle invalid values
	if !val.IsValid() {
		return nil
	}

	// Dereference pointers
	for val.Kind() == reflect.Ptr || val.Kind() == reflect.Interface {
		if val.IsNil() {
			return nil
		}
		val = val.Elem()
	}

	switch val.Kind() {
	case reflect.Map:
		return normalizeMap(val)
	case reflect.Slice, reflect.Array:
		return normalizeSlice(val)
	case reflect.Struct:
		return normalizeStruct(val)
	default:
		// Primitive types: return as-is
		return val.Interface()
	}
}

// normalizeMap converts a map to a sortedMap with normalized values.
func normalizeMap(val reflect.Value) interface{} {
	if val.IsNil() {
		return nil
	}

	result := make(sortedMap)
	iter := val.MapRange()
	for iter.Next() {
		key := iter.Key()
		value := iter.Value()

		// Convert key to string (JSON map keys must be strings)
		keyStr := ""
		switch key.Kind() {
		case reflect.String:
			keyStr = key.String()
		default:
			// For non-string keys, use JSON representation
			keyBytes, err := json.Marshal(key.Interface())
			if err != nil {
				// Use fmt.Sprintf as fallback for non-JSON-serializable keys
				keyStr = fmt.Sprintf("%v", key.Interface())
			} else {
				keyStr = string(keyBytes)
			}
		}

		result[keyStr] = normalizeValue(value)
	}
	return result
}

// normalizeSlice processes each element of a slice.
func normalizeSlice(val reflect.Value) interface{} {
	if val.IsNil() {
		return []interface{}{}
	}

	result := make([]interface{}, val.Len())
	for i := 0; i < val.Len(); i++ {
		result[i] = normalizeValue(val.Index(i))
	}
	return result
}

// normalizeStruct converts a struct to a sortedMap based on JSON field names.
func normalizeStruct(val reflect.Value) interface{} {
	// First marshal to JSON to get proper field names and handle omitempty
	jsonBytes, err := json.Marshal(val.Interface())
	if err != nil {
		// If marshaling fails, return the original value unchanged
		return val.Interface()
	}

	// Unmarshal into a map to get the actual JSON representation
	var m map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &m); err != nil {
		return val.Interface()
	}

	// Normalize the map (which will recursively normalize nested structures)
	return normalizeMapInterface(m)
}

// normalizeMapInterface normalizes a map[string]interface{} (common from JSON unmarshaling).
func normalizeMapInterface(m map[string]interface{}) sortedMap {
	result := make(sortedMap)
	for k, v := range m {
		result[k] = normalizeInterface(v)
	}
	return result
}

// normalizeInterface normalizes an interface{} value (typically from JSON unmarshaling).
func normalizeInterface(v interface{}) interface{} {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case map[string]interface{}:
		return normalizeMapInterface(val)
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, elem := range val {
			result[i] = normalizeInterface(elem)
		}
		return result
	default:
		return v
	}
}

// sortedMap is a map that serializes with keys in sorted order.
type sortedMap map[string]interface{}

// MarshalJSON implements json.Marshaler with sorted keys.
func (m sortedMap) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("null"), nil
	}

	// Get sorted keys
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build JSON manually with sorted keys
	var buf bytes.Buffer
	buf.WriteByte('{')

	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}

		// Marshal key
		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(keyBytes)
		buf.WriteByte(':')

		// Marshal value
		valBytes, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		buf.Write(valBytes)
	}

	buf.WriteByte('}')
	return buf.Bytes(), nil
}
