package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/tracevault/tracevault-cli/internal/core/evidence"
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

// HashCheckResult computes the SHA-256 hash of a check result.
// Uses canonical JSON serialization to ensure deterministic hashing,
// since CheckResult contains Violations with map[string]interface{} Details.
func HashCheckResult(result *evidence.CheckResult) (string, error) {
	return HashCanonicalJSON(result)
}

// HashEvidence computes the SHA-256 hash of an evidence item.
func HashEvidence(ev *evidence.Evidence) string {
	// Evidence already has a hash computed at creation time
	if ev.Hash != "" {
		return ev.Hash
	}
	// Fallback to computing from data
	return HashData(ev.Data)
}

// ComputeEvidenceHashes computes hashes for all evidence and the check result.
func ComputeEvidenceHashes(result *evidence.CheckResult, evidenceList []evidence.Evidence) (*EvidenceHashes, error) {
	hashes := &EvidenceHashes{
		Evidence: make(map[string]string),
	}

	// Hash each piece of evidence
	for i := range evidenceList {
		ev := &evidenceList[i]
		hashes.Evidence[ev.ID] = HashEvidence(ev)
	}

	// Hash the check result
	checkResultHash, err := HashCheckResult(result)
	if err != nil {
		return nil, err
	}
	hashes.CheckResult = checkResultHash

	// Compute combined hash (deterministic ordering)
	hashes.Combined = computeCombinedHash(hashes)

	return hashes, nil
}

// computeCombinedHash creates a single hash representing all evidence.
func computeCombinedHash(hashes *EvidenceHashes) string {
	// Sort evidence IDs for deterministic ordering
	ids := make([]string, 0, len(hashes.Evidence))
	for id := range hashes.Evidence {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	// Concatenate all hashes in order
	var combined []byte
	combined = append(combined, []byte(hashes.CheckResult)...)

	for _, id := range ids {
		combined = append(combined, []byte(hashes.Evidence[id])...)
	}

	if hashes.Manifest != "" {
		combined = append(combined, []byte(hashes.Manifest)...)
	}

	return HashData(combined)
}

// VerifyHash verifies that data matches an expected hash.
func VerifyHash(data []byte, expectedHash string) bool {
	actualHash := HashData(data)
	return actualHash == expectedHash
}

// VerifyEvidenceHash verifies that evidence data matches its hash.
func VerifyEvidenceHash(ev *evidence.Evidence) bool {
	expectedHash := HashData(ev.Data)
	return ev.Hash == expectedHash
}
