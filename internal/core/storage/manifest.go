package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// StoredPolicyResult wraps PolicyResult with storage-specific fields for the per-policy result.json.
type StoredPolicyResult struct {
	evidence.PolicyResult
	EvidenceFiles []string `json:"evidence_files"`
}

// StoreRun stores all evidence and check results in an auditor-friendly, policy-centric layout:
//
//	<prefix>/runs/<framework>/<date>/<time>/
//	  manifest.json
//	  attestation.json
//	  check_result.json
//	  <policy-slug>/
//	    result.json
//	    evidence/<descriptor>.json
func StoreRun(ctx context.Context, backend Backend, result *evidence.CheckResult,
	evidenceList []evidence.Evidence, att *attestation.Attestation) (*Manifest, error) {
	runPath := NewRunPath(result.Framework, result.Timestamp)

	manifest := &Manifest{
		RunID:     result.RunID,
		Framework: result.Framework,
		Timestamp: result.Timestamp,
		Backend:   backend.Name(),
		Items:     []StoredItem{},
	}

	// Build resource type → evidence index for fast lookup
	typeToEvidence := buildEvidenceIndex(evidenceList)

	evidenceCount := 0

	// For each policy result, store its evidence and result.json
	for i := range result.PolicyResults {
		pr := &result.PolicyResults[i]

		policyDir := runPath.PolicyDir(pr.PolicyID, result.Framework)

		// Find matching evidence for this policy's resource types
		matching := findMatchingEvidence(pr.ResourceTypes, typeToEvidence, evidenceList)

		// Group matching evidence by resource type and store one aggregated file per type
		var evidenceFiles []string
		byType := groupEvidenceByType(matching)

		for resourceType, items := range byType {
			filename := EvidenceTypeFilename(resourceType)
			evPath := policyDir + "/evidence/" + filename

			// Build an array of evidence entries for this resource type
			entries := make([]aggregatedEvidenceEntry, len(items))
			for j := range items {
				entries[j] = aggregatedEvidenceEntry{
					ResourceID:  items[j].ResourceID,
					CollectedAt: items[j].CollectedAt,
					Data:        items[j].Data,
				}
			}

			data, err := json.MarshalIndent(entries, "", "  ")
			if err != nil {
				return nil, fmt.Errorf("failed to marshal evidence for type %s: %w", resourceType, err)
			}

			item, err := backend.StoreRaw(ctx, evPath, data, map[string]string{
				"resource_type": resourceType,
				"count":         fmt.Sprintf("%d", len(items)),
			})
			if err != nil {
				return nil, fmt.Errorf("failed to store evidence for type %s: %w", resourceType, err)
			}

			manifest.Items = append(manifest.Items, *item)
			manifest.TotalSize += item.Size
			evidenceFiles = append(evidenceFiles, "evidence/"+filename)
			evidenceCount += len(items)
		}

		// Build per-policy result.json with evidence file references and violation evidence pointers
		storedResult := buildStoredPolicyResult(pr, evidenceFiles)

		resultData, err := json.MarshalIndent(storedResult, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal policy result %s: %w", pr.PolicyID, err)
		}

		resultPath := policyDir + "/result.json"
		item, err := backend.StoreRaw(ctx, resultPath, resultData, map[string]string{
			"type":      "policy_result",
			"policy_id": pr.PolicyID,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to store policy result %s: %w", pr.PolicyID, err)
		}
		manifest.Items = append(manifest.Items, *item)
		manifest.TotalSize += item.Size
	}

	manifest.EvidenceCount = evidenceCount

	// Store aggregate check_result.json at run level
	checkResultData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal check result: %w", err)
	}
	crItem, err := backend.StoreRaw(ctx, runPath.CheckResultPath(), checkResultData, map[string]string{
		"type":      "check_result",
		"framework": result.Framework,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store check result: %w", err)
	}
	manifest.Items = append(manifest.Items, *crItem)
	manifest.TotalSize += crItem.Size
	manifest.CheckResult = crItem.Path

	// Store attestation.json at run level (if provided)
	if att != nil {
		attData, err := json.MarshalIndent(att, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal attestation: %w", err)
		}
		attItem, err := backend.StoreRaw(ctx, runPath.AttestationPath(), attData, map[string]string{
			"type": "attestation",
		})
		if err != nil {
			return nil, fmt.Errorf("failed to store attestation: %w", err)
		}
		manifest.Items = append(manifest.Items, *attItem)
		manifest.TotalSize += attItem.Size
		manifest.Attestation = attItem.Path
	}

	// Store manifest.json at run level
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal manifest: %w", err)
	}
	mItem, err := backend.StoreRaw(ctx, runPath.ManifestPath(), manifestData, map[string]string{
		"type":      "manifest",
		"run_id":    result.RunID,
		"framework": result.Framework,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to store manifest: %w", err)
	}
	manifest.Items = append(manifest.Items, *mItem)
	manifest.TotalSize += mItem.Size

	return manifest, nil
}

// buildEvidenceIndex creates a map from resource type to indices in the evidence list.
func buildEvidenceIndex(evidenceList []evidence.Evidence) map[string][]int {
	idx := make(map[string][]int)
	for i := range evidenceList {
		rt := evidenceList[i].ResourceType
		idx[rt] = append(idx[rt], i)
	}
	return idx
}

// findMatchingEvidence returns evidence items that match any of the given resource types.
func findMatchingEvidence(resourceTypes []string, typeIndex map[string][]int, evidenceList []evidence.Evidence) []evidence.Evidence {
	var result []evidence.Evidence
	seen := make(map[int]bool)
	for _, rt := range resourceTypes {
		for _, idx := range typeIndex[rt] {
			if !seen[idx] {
				seen[idx] = true
				result = append(result, evidenceList[idx])
			}
		}
	}
	return result
}

// aggregatedEvidenceEntry represents a single resource within an aggregated evidence file.
type aggregatedEvidenceEntry struct {
	ResourceID  string          `json:"resource_id"`
	CollectedAt time.Time       `json:"collected_at"`
	Data        json.RawMessage `json:"data"`
}

// groupEvidenceByType groups evidence items by their resource type.
func groupEvidenceByType(items []evidence.Evidence) map[string][]evidence.Evidence {
	grouped := make(map[string][]evidence.Evidence)
	for i := range items {
		rt := items[i].ResourceType
		grouped[rt] = append(grouped[rt], items[i])
	}
	return grouped
}

// buildStoredPolicyResult creates a StoredPolicyResult with evidence_files and violation evidence pointers.
func buildStoredPolicyResult(pr *evidence.PolicyResult, evidenceFiles []string) *StoredPolicyResult {
	stored := &StoredPolicyResult{
		PolicyResult:  *pr,
		EvidenceFiles: evidenceFiles,
	}

	// Add evidence_file to each violation so auditors can trace violations to the aggregated file
	if len(stored.Violations) > 0 {
		// Build resource type → aggregated filename map
		typeToFile := make(map[string]string)
		for _, rt := range pr.ResourceTypes {
			typeToFile[rt] = "evidence/" + EvidenceTypeFilename(rt)
		}

		updatedViolations := make([]evidence.Violation, len(stored.Violations))
		for i, v := range stored.Violations {
			updatedViolations[i] = v
			if file, ok := typeToFile[v.ResourceType]; ok {
				if updatedViolations[i].Details == nil {
					updatedViolations[i].Details = make(map[string]interface{})
				}
				updatedViolations[i].Details["evidence_file"] = file
			}
		}
		stored.Violations = updatedViolations
	}

	return stored
}

// LoadManifest loads a manifest from storage by scanning for manifest.json under the runs prefix.
func LoadManifest(ctx context.Context, backend Backend, runPath string) (*Manifest, error) {
	// runPath should be the run base path (e.g. "runs/soc2/2026-02-14")
	path := runPath
	if !strings.HasSuffix(path, "/manifest.json") {
		path += "/manifest.json"
	}

	data, err := backend.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to load manifest: %w", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return &manifest, nil
}

// ManifestBuilder helps construct a storage manifest.
type ManifestBuilder struct {
	manifest *Manifest
	backend  Backend
}

// NewManifestBuilder creates a new manifest builder.
func NewManifestBuilder(backend Backend, framework string) *ManifestBuilder {
	return &ManifestBuilder{
		manifest: &Manifest{
			Framework: framework,
			Timestamp: time.Now().UTC(),
			Backend:   backend.Name(),
			Items:     []StoredItem{},
		},
		backend: backend,
	}
}

// WithRunID sets a custom run ID.
func (b *ManifestBuilder) WithRunID(runID string) *ManifestBuilder {
	b.manifest.RunID = runID
	return b
}

// AddItem adds a stored item to the manifest.
func (b *ManifestBuilder) AddItem(item *StoredItem) {
	b.manifest.Items = append(b.manifest.Items, *item)
	b.manifest.TotalSize += item.Size
}

// SetCheckResult sets the check result path.
func (b *ManifestBuilder) SetCheckResult(path string) {
	b.manifest.CheckResult = path
}

// SetEvidenceCount sets the evidence count.
func (b *ManifestBuilder) SetEvidenceCount(count int) {
	b.manifest.EvidenceCount = count
}

// Build finalizes and returns the manifest.
func (b *ManifestBuilder) Build() *Manifest {
	return b.manifest
}
