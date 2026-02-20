package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
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

// ComputeStoredFileHashes builds EvidenceHashes from stored file hashes.
// checkResultHash is the SHA-256 of the stored check_result.json file.
// fileHashes maps relative file paths to their SHA-256 hashes.
func ComputeStoredFileHashes(checkResultHash string, fileHashes map[string]string) *EvidenceHashes {
	hashes := &EvidenceHashes{
		CheckResult: checkResultHash,
		StoredFiles: fileHashes,
	}

	hashes.Combined = computeCombinedHash(hashes)

	return hashes
}

// computeCombinedHash creates a single hash representing all stored files.
func computeCombinedHash(hashes *EvidenceHashes) string {
	// Sort file paths for deterministic ordering
	paths := make([]string, 0, len(hashes.StoredFiles))
	for p := range hashes.StoredFiles {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	// Concatenate all hashes in order: check_result hash first, then sorted file hashes
	var combined []byte
	combined = append(combined, []byte(hashes.CheckResult)...)

	for _, p := range paths {
		combined = append(combined, []byte(hashes.StoredFiles[p])...)
	}

	return HashData(combined)
}

// VerifyHash verifies that data matches an expected hash.
func VerifyHash(data []byte, expectedHash string) bool {
	actualHash := HashData(data)
	return actualHash == expectedHash
}
