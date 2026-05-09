package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// manualEvidencePDFFilename is the fixed name we mirror manual evidence under
// inside each policy's run folder. The canonical declaration lives at
// internal/core/manual.EvidencePDFFilename; we duplicate the literal here to
// avoid an import cycle (the manual package depends on storage). Keep the two
// in lockstep — a CI check or grep on rename is sufficient.
const manualEvidencePDFFilename = "evidence.pdf"

// StoredPolicyResult is the on-disk format for result.json in each policy folder.
// It embeds PolicyResult (full violations included) and adds storage-specific metadata.
type StoredPolicyResult struct {
	evidence.PolicyResult
	EvidenceFiles []string `json:"evidence_files"`
	CLIVersion    string   `json:"cli_version,omitempty"`
	CLISHA        string   `json:"cli_sha,omitempty"`
	RepoSHA       string   `json:"repo_sha,omitempty"`
}

// StoreRun stores all evidence and policy results using a policy-first folder layout:
//
//	{framework}/{policy_slug}/{timestamp}_{run_id_short}/
//	  evidence/{resource_type_plural}.json    (EvidenceEnvelope — self-contained, signed)
//	  manual_attachments/{evidence_id}/evidence.pdf  (manual PDF mirrored as sibling, when applicable)
//	  result.json                             (StoredPolicyResult — full violations)
//
// Each evidence file is an independently verifiable EvidenceEnvelope: it contains the
// raw evidence (or, for manual policies, a small {evidence_id, file_hash, file_path,
// period, framework} manifest), a timestamp, and an Ed25519 signature over the signed
// payload. The private key is discarded immediately after signing.
//
// manualSidecars carries the user-supplied PDF for each manual evidence entry
// referenced by this run. Sidecars are mirrored into
// every policy folder whose evidence list includes the matching "manual:<id>" resource
// type, so auditors verify each policy from a single self-contained folder.
func StoreRun(ctx context.Context, backend Backend, result *evidence.CheckResult,
	evidenceList []evidence.Evidence, manualSidecars []ManualSidecar,
	cliVersion, cliSHA, repoSHA string) error {
	typeToEvidence := buildEvidenceIndex(evidenceList)
	sidecarByType := indexSidecarsByResourceType(manualSidecars)

	for i := range result.PolicyResults {
		pr := &result.PolicyResults[i]
		rp := NewRunPath(result.Framework, pr.PolicyID, result.RunID, result.Timestamp)

		// Find and group evidence matching this policy's resource types
		matching := findMatchingEvidence(pr.ResourceTypes, typeToEvidence, evidenceList)
		byType := groupEvidenceByType(matching)

		var evidenceFiles []string

		for resourceType, items := range byType {
			filename := EvidenceTypeFilename(resourceType)
			evPath := rp.EvidencePath(filename)

			// Build the aggregated entries array
			entries := make([]aggregatedEvidenceEntry, len(items))
			for j := range items {
				entries[j] = aggregatedEvidenceEntry{
					ResourceID:  items[j].ResourceID,
					CollectedAt: items[j].CollectedAt,
					Data:        items[j].Data,
				}
			}

			entriesData, err := json.Marshal(entries)
			if err != nil {
				return fmt.Errorf("failed to marshal evidence for type %s: %w", resourceType, err)
			}

			// Wrap in a signed EvidenceEnvelope — fresh ephemeral keypair per file,
			// private key discarded immediately after signing.
			envelope := attestation.NewEvidenceEnvelope(result.Timestamp, entriesData)
			signer, err := attestation.NewEd25519Signer()
			if err != nil {
				return fmt.Errorf("failed to create signer for type %s: %w", resourceType, err)
			}
			if err := signer.Sign(envelope); err != nil {
				return fmt.Errorf("failed to sign evidence for type %s: %w", resourceType, err)
			}

			envelopeData, err := json.MarshalIndent(envelope, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal evidence envelope for type %s: %w", resourceType, err)
			}

			_, err = backend.StoreRaw(ctx, evPath, envelopeData, map[string]string{
				"resource_type": resourceType,
				"count":         fmt.Sprintf("%d", len(items)),
			})
			if err != nil {
				return fmt.Errorf("failed to store evidence for type %s: %w", resourceType, err)
			}

			evidenceFiles = append(evidenceFiles, "evidence/"+filename)
		}

		// Mirror manual evidence sidecars (raw evidence.json + supporting files) into
		// this policy's folder for any "manual:<id>" resource types it references.
		if err := writeManualSidecars(ctx, backend, rp, pr.ResourceTypes, sidecarByType); err != nil {
			return err
		}

		// Build per-policy result.json
		storedResult := buildStoredPolicyResult(pr, evidenceFiles, cliVersion, cliSHA, repoSHA)

		resultData, err := json.MarshalIndent(storedResult, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal policy result %s: %w", pr.PolicyID, err)
		}

		_, err = backend.StoreRaw(ctx, rp.ResultPath(), resultData, map[string]string{
			"type":      "policy_result",
			"policy_id": pr.PolicyID,
		})
		if err != nil {
			return fmt.Errorf("failed to store policy result %s: %w", pr.PolicyID, err)
		}
	}

	return nil
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

// buildStoredPolicyResult creates a StoredPolicyResult with evidence file references,
// violation evidence pointers, and CLI provenance metadata.
func buildStoredPolicyResult(pr *evidence.PolicyResult, evidenceFiles []string, cliVersion, cliSHA, repoSHA string) *StoredPolicyResult {
	stored := &StoredPolicyResult{
		PolicyResult:  *pr,
		EvidenceFiles: evidenceFiles,
		CLIVersion:    cliVersion,
		CLISHA:        cliSHA,
		RepoSHA:       repoSHA,
	}

	// Add evidence_file to each violation so auditors can trace violations to the evidence file
	if len(stored.Violations) > 0 {
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

func indexSidecarsByResourceType(sidecars []ManualSidecar) map[string]ManualSidecar {
	out := make(map[string]ManualSidecar, len(sidecars))
	for _, s := range sidecars {
		out[s.ResourceType] = s
	}
	return out
}

// writeManualSidecars mirrors the user-supplied PDF for each referenced manual
// evidence entry into this policy's run folder under
// manual_attachments/{evidence_id}/evidence.pdf. The same PDF is duplicated
// across every policy folder that references the entry, so each policy folder
// is fully self-contained for auditor review.
func writeManualSidecars(ctx context.Context, backend Backend, rp *RunPath,
	resourceTypes []string, sidecarByType map[string]ManualSidecar) error {
	for _, rt := range resourceTypes {
		sidecar, ok := sidecarByType[rt]
		if !ok {
			continue
		}
		if len(sidecar.PDF) == 0 {
			continue
		}

		path := rp.ManualAttachmentPath(sidecar.EvidenceID, manualEvidencePDFFilename)
		if _, err := backend.StoreRaw(ctx, path, sidecar.PDF, map[string]string{
			"type":        "manual_evidence_pdf",
			"evidence_id": sidecar.EvidenceID,
			"period":      sidecar.Period,
			"sha256":      sidecar.FileHash,
		}); err != nil {
			return fmt.Errorf("failed to store manual %s for %s: %w", manualEvidencePDFFilename, sidecar.EvidenceID, err)
		}
	}
	return nil
}
