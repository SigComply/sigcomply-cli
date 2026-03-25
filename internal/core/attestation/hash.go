package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// HashData computes the SHA-256 hash of arbitrary data.
func HashData(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// HashJSON computes the SHA-256 hash of a JSON-serializable value.
//
// Deprecated: Use HashCanonicalJSON instead for structures containing maps.
// This function uses standard json.Marshal which has non-deterministic
// ordering for map keys. It is kept for backward compatibility with
// simple structures that don't contain maps.
func HashJSON(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return HashData(data), nil
}

// VerifyHash verifies that data matches an expected hash.
func VerifyHash(data []byte, expectedHash string) bool {
	actualHash := HashData(data)
	return actualHash == expectedHash
}
