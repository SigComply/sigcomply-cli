//go:build e2e

// Package manual provides E2E test functions for the manual evidence pipeline
// using real S3 storage. Tests create folder structure in S3, upload evidence.json
// files (same format the SPA produces), upload sample attachments (PDFs), then
// run OPA policy evaluation, store policy results via StoreRun, and verify
// execution-state attestations — all in S3.
//
// The test mirrors the production dual-backend architecture from check.go:
//   - manualBackend: reads/writes manual evidence + execution state (Storage.Prefix + ManualEvidence.Prefix)
//   - resultsBackend: stores policy results via StoreRun (Storage.Prefix)
//
// Required env vars: E2E_AWS_ACCESS_KEY_ID, E2E_AWS_SECRET_ACCESS_KEY, E2E_AWS_REGION, E2E_S3_BUCKET
package manual

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/engine"
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	manualPkg "github.com/sigcomply/sigcomply-cli/internal/core/manual"
	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
	manualReader "github.com/sigcomply/sigcomply-cli/internal/data_sources/manual"
)

const (
	frameworkName = "soc2"

	// manualSubPrefix mirrors the production ManualEvidence.Prefix (default "manual-evidence/").
	// In production, manual evidence lives at {Storage.Prefix}{ManualEvidence.Prefix}.
	manualSubPrefix = "manual-evidence/"
)

// testBackends holds the two S3 backends mirroring production's dual-backend architecture.
// In production (check.go), buildManualStorageConfig creates a backend at Storage.Prefix + ManualEvidence.Prefix,
// while buildStorageConfig creates a backend at Storage.Prefix for policy result storage.
type testBackends struct {
	// manual reads/writes manual evidence files and execution-state.json.
	// Prefix: {basePrefix}{manualSubPrefix} (e.g., "e2e/a1b2c3d4/manual-evidence/")
	manual storage.Backend

	// results stores policy results via storage.StoreRun (result.json + signed evidence envelopes).
	// Prefix: {basePrefix} (e.g., "e2e/a1b2c3d4/")
	results storage.Backend
}

// s3TestPrefix returns a unique S3 key prefix for this test run to avoid collisions.
// This is analogous to Storage.Prefix in production config.
func s3TestPrefix() string {
	return fmt.Sprintf("e2e/%s/", uuid.New().String()[:8])
}

// samplePDF is a minimal valid PDF file (header + minimal body).
// This is what a compliance officer would upload as an attachment.
var samplePDF = []byte(`%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [] /Count 0 >>
endobj
xref
0 3
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
trailer
<< /Size 3 /Root 1 0 R >>
startxref
109
%%EOF`)

// resolveS3Config reads AWS credentials and bucket from environment variables.
// Skips the test if any are missing (safe for local dev without credentials).
func resolveS3Config(t *testing.T) (bucket, region string) {
	t.Helper()

	// Check required env vars — skip (don't fail) if missing
	required := []string{"E2E_AWS_ACCESS_KEY_ID", "E2E_AWS_SECRET_ACCESS_KEY", "E2E_S3_BUCKET"}
	var missing []string
	for _, env := range required {
		if os.Getenv(env) == "" {
			missing = append(missing, env)
		}
	}
	if len(missing) > 0 {
		t.Skipf("Skipping S3 manual evidence test: missing env vars %v", missing)
	}

	// Set standard AWS SDK env vars so the S3Backend picks them up
	t.Setenv("AWS_ACCESS_KEY_ID", os.Getenv("E2E_AWS_ACCESS_KEY_ID"))
	t.Setenv("AWS_SECRET_ACCESS_KEY", os.Getenv("E2E_AWS_SECRET_ACCESS_KEY"))

	region = os.Getenv("E2E_AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	t.Setenv("AWS_DEFAULT_REGION", region)

	return os.Getenv("E2E_S3_BUCKET"), region
}

// setupTestBackends creates the dual-backend setup mirroring production.
// Cleanup deletes all S3 objects under the base prefix (covers both backends).
func setupTestBackends(t *testing.T, bucket, region, basePrefix string) *testBackends {
	t.Helper()
	ctx := context.Background()

	// Manual evidence backend: {basePrefix}{manualSubPrefix}
	manualCfg := &storage.Config{
		Backend: "s3",
		S3: &storage.S3Config{
			Bucket: bucket,
			Region: region,
			Prefix: basePrefix + manualSubPrefix,
		},
	}
	manualBackend, err := storage.NewBackend(manualCfg)
	require.NoError(t, err, "Failed to create manual S3 backend")
	require.NoError(t, manualBackend.Init(ctx), "Failed to init manual S3 backend")

	// Results backend: {basePrefix} (for StoreRun — policy results + evidence envelopes)
	resultsCfg := &storage.Config{
		Backend: "s3",
		S3: &storage.S3Config{
			Bucket: bucket,
			Region: region,
			Prefix: basePrefix,
		},
	}
	resultsBackend, err := storage.NewBackend(resultsCfg)
	require.NoError(t, err, "Failed to create results S3 backend")
	require.NoError(t, resultsBackend.Init(ctx), "Failed to init results S3 backend")

	// Cleanup: delete everything under the base prefix (covers both backends).
	// Set E2E_SKIP_CLEANUP=true to inspect S3 artifacts after tests.
	t.Cleanup(func() {
		if os.Getenv("E2E_SKIP_CLEANUP") != "true" {
			cleanupS3Prefix(t, region, bucket, basePrefix)
		} else {
			t.Logf("E2E_SKIP_CLEANUP=true — leaving S3 objects under s3://%s/%s", bucket, basePrefix)
		}
		_ = manualBackend.Close()
		_ = resultsBackend.Close()
	})

	return &testBackends{
		manual:  manualBackend,
		results: resultsBackend,
	}
}

// cleanupS3Prefix deletes all objects under a prefix in S3.
func cleanupS3Prefix(t *testing.T, region, bucket, prefix string) {
	t.Helper()
	ctx := context.Background()

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		t.Logf("Warning: cleanup failed to create AWS config: %v", err)
		return
	}

	client := s3.NewFromConfig(awsCfg)
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})

	deleted := 0
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			t.Logf("Warning: cleanup failed to list objects: %v", err)
			return
		}
		for _, obj := range page.Contents {
			_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket),
				Key:    obj.Key,
			})
			if err != nil {
				t.Logf("Warning: failed to delete %s: %v", aws.ToString(obj.Key), err)
			}
			deleted++
		}
	}
	t.Logf("Cleaned up %d S3 objects under s3://%s/%s", deleted, bucket, prefix)
}

// listS3Objects lists all object keys under a prefix for verification.
func listS3Objects(t *testing.T, region, bucket, prefix string) []string {
	t.Helper()
	ctx := context.Background()

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	require.NoError(t, err)

	client := s3.NewFromConfig(awsCfg)
	var keys []string

	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		require.NoError(t, err)
		for _, obj := range page.Contents {
			keys = append(keys, aws.ToString(obj.Key))
		}
	}
	return keys
}

// loadFramework returns the SOC2 framework and its manual evidence catalog.
func loadFramework(t *testing.T) (engine.Framework, *manualPkg.Catalog) {
	t.Helper()
	fw := soc2.New()
	catalog, err := fw.ManualCatalog()
	require.NoError(t, err)
	require.NotEmpty(t, catalog.Entries, "SOC2 manual catalog should have entries")
	return fw, catalog
}

// placeEvidence writes a SubmittedEvidence JSON to S3 at the correct path.
func placeEvidence(t *testing.T, backend storage.Backend, evidenceID, period string, submitted manualPkg.SubmittedEvidence) {
	t.Helper()
	data, err := json.MarshalIndent(submitted, "", "  ")
	require.NoError(t, err)
	path := filepath.Join(frameworkName, evidenceID, period, "evidence.json")
	_, err = backend.StoreRaw(context.Background(), path, data, nil)
	require.NoError(t, err)
	t.Logf("Uploaded evidence.json -> %s", path)
}

// placeAttachment writes a file alongside evidence.json in S3 storage.
func placeAttachment(t *testing.T, backend storage.Backend, evidenceID, period, filename string, content []byte) {
	t.Helper()
	path := filepath.Join(frameworkName, evidenceID, period, filename)
	_, err := backend.StoreRaw(context.Background(), path, content, nil)
	require.NoError(t, err)
	t.Logf("Uploaded attachment -> %s (%d bytes)", path, len(content))
}

// pipelineResult holds everything produced by runPipeline for verification.
type pipelineResult struct {
	manualResults []evidence.PolicyResult
	state         *manualPkg.ExecutionState
	checkResult   *evidence.CheckResult
}

// runPipeline executes the full manual evidence pipeline against S3, mirroring
// the production flow in check.go:
//
//  1. Load execution state from S3
//  2. Read manual evidence from S3
//  3. OPA policy evaluation
//  4. Store policy results + signed evidence envelopes via StoreRun (results backend)
//  5. Update execution state (manual backend)
func runPipeline(t *testing.T, backends *testBackends, fw engine.Framework, catalog *manualPkg.Catalog, now time.Time) *pipelineResult {
	t.Helper()
	ctx := context.Background()

	// 1. Load execution state from S3 (or create empty if not found)
	statePath := filepath.Join(frameworkName, "execution-state.json")
	state, err := manualPkg.LoadState(ctx, backends.manual, statePath)
	require.NoError(t, err)
	state.Framework = frameworkName

	// 2. Read manual evidence from S3
	reader := manualReader.NewReader(backends.manual, catalog, frameworkName)
	result, err := reader.Read(ctx, state, now)
	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("Reader produced %d evidence items, %d errors", len(result.Evidence), len(result.Errors))
	for _, s := range result.Status {
		t.Logf("  entry=%s period=%s temporal=%s hasEvidence=%v attested=%v",
			s.EvidenceID, s.Period, s.TemporalStatus, s.HasEvidence, s.Attested)
	}

	// 3. Load OPA policies and evaluate
	eng := engine.New()
	for _, p := range fw.Policies() {
		require.NoError(t, eng.LoadPolicy(p.Name, p.Source))
	}

	policyResults, err := eng.Evaluate(ctx, result.Evidence)
	require.NoError(t, err)

	// Filter to manual-only policies (resource_types containing "manual:")
	var manualResults []evidence.PolicyResult
	for _, pr := range policyResults {
		for _, rt := range pr.ResourceTypes {
			if len(rt) > 7 && rt[:7] == "manual:" {
				manualResults = append(manualResults, pr)
				break
			}
		}
	}

	// Build CheckResult (mirrors check.go)
	runID := uuid.New().String()
	checkResult := &evidence.CheckResult{
		RunID:         runID,
		Framework:     frameworkName,
		Timestamp:     now,
		PolicyResults: manualResults,
	}
	checkResult.CalculateSummary()

	// 4. Store policy results + signed evidence envelopes via StoreRun (results backend)
	err = storage.StoreRun(ctx, backends.results, checkResult, result.Evidence, "e2e-test", "", "")
	require.NoError(t, err, "StoreRun should persist policy results and evidence envelopes to S3")
	t.Logf("StoreRun complete: stored %d policy results to S3", len(manualResults))

	// 5. Update execution state (mirrors check.go:updateManualExecutionState)
	for i := range manualResults {
		pr := &manualResults[i]
		for _, rt := range pr.ResourceTypes {
			if len(rt) <= 7 || rt[:7] != "manual:" {
				continue
			}
			evidenceID := rt[7:]
			entry := catalog.GetEntry(evidenceID)
			if entry == nil {
				continue
			}
			period, err := manualPkg.CurrentPeriod(entry.Frequency, now, entry.GracePeriod)
			if err != nil {
				continue
			}
			status := "attested"
			if pr.Status == evidence.StatusFail {
				status = "uploaded"
			}
			state.RecordAttestation(evidenceID, period.Key, runID, status, nil)
		}
	}

	// Save execution state back to S3
	require.NoError(t, state.Save(ctx, backends.manual, statePath))
	t.Logf("Saved execution-state.json to S3")

	return &pipelineResult{
		manualResults: manualResults,
		state:         state,
		checkResult:   checkResult,
	}
}

// buildValidEvidence returns valid SubmittedEvidence for each SOC2 catalog entry.
func buildValidEvidence(catalog *manualPkg.Catalog, now time.Time) map[string]manualPkg.SubmittedEvidence {
	accepted := true
	result := make(map[string]manualPkg.SubmittedEvidence)

	for _, entry := range catalog.Entries {
		period, _ := manualPkg.CurrentPeriod(entry.Frequency, now, entry.GracePeriod)

		base := manualPkg.SubmittedEvidence{
			SchemaVersion: "1.0",
			EvidenceID:    entry.ID,
			Type:          entry.Type,
			Framework:     frameworkName,
			Control:       entry.Control,
			Period:        period.Key,
			CompletedBy:   "test@e2e.sigcomply.dev",
			CompletedAt:   now,
		}

		switch entry.Type {
		case manualPkg.EvidenceTypeDocumentUpload:
			base.Attachments = []string{"review.pdf"}
		case manualPkg.EvidenceTypeChecklist:
			for _, item := range entry.Items {
				base.Items = append(base.Items, manualPkg.SubmittedChecklistItem{
					ID:      item.ID,
					Checked: true,
				})
			}
		case manualPkg.EvidenceTypeDeclaration:
			base.DeclarationText = entry.DeclarationText
			base.Accepted = &accepted
		}

		result[entry.ID] = base
	}

	return result
}

// RunPositiveScenario creates the full S3 folder structure with valid evidence
// for all SOC2 manual entries, runs OPA evaluation, stores policy results, and
// verifies all policies pass.
//
// S3 structure created (mirrors production layout):
//
//	{basePrefix}/manual-evidence/soc2/quarterly_access_review/2026-Q2/evidence.json
//	{basePrefix}/manual-evidence/soc2/quarterly_access_review/2026-Q2/review.pdf
//	{basePrefix}/manual-evidence/soc2/security_awareness_training/2026/evidence.json
//	{basePrefix}/manual-evidence/soc2/security_awareness_training/2026/review.pdf
//	{basePrefix}/manual-evidence/soc2/incident_response_test/2026/evidence.json       (checklist)
//	{basePrefix}/manual-evidence/soc2/risk_acceptance_signoff/2026-Q2/evidence.json   (declaration)
//	{basePrefix}/manual-evidence/soc2/execution-state.json                            (after eval)
//	{basePrefix}/soc2/{policy_slug}/{timestamp}_{run_id}/result.json                  (per policy)
//	{basePrefix}/soc2/{policy_slug}/{timestamp}_{run_id}/evidence/manuals.json        (signed envelope)
func RunPositiveScenario(t *testing.T) {
	t.Helper()
	bucket, region := resolveS3Config(t)
	basePrefix := s3TestPrefix()
	backends := setupTestBackends(t, bucket, region, basePrefix)
	fw, catalog := loadFramework(t)
	now := time.Now().UTC()

	t.Logf("=== Phase 1: Create S3 folder structure with valid evidence ===")
	t.Logf("S3 base prefix: s3://%s/%s", bucket, basePrefix)
	t.Logf("Manual evidence: s3://%s/%s%s", bucket, basePrefix, manualSubPrefix)

	// Place valid evidence for all catalog entries
	validEvidence := buildValidEvidence(catalog, now)
	for evidenceID, submitted := range validEvidence {
		entry := catalog.GetEntry(evidenceID)
		period, err := manualPkg.CurrentPeriod(entry.Frequency, now, entry.GracePeriod)
		require.NoError(t, err)

		placeEvidence(t, backends.manual, evidenceID, period.Key, submitted)

		// Upload sample PDF attachments for document_upload types
		if submitted.Type == manualPkg.EvidenceTypeDocumentUpload {
			for _, attachment := range submitted.Attachments {
				placeAttachment(t, backends.manual, evidenceID, period.Key, attachment, samplePDF)
			}
		}
	}

	// Verify S3 objects were created
	keys := listS3Objects(t, region, bucket, basePrefix)
	t.Logf("Phase 1 complete: %d objects in S3", len(keys))
	for _, key := range keys {
		t.Logf("  -> %s", key)
	}

	t.Logf("=== Phase 2: Run OPA policy evaluation + StoreRun ===")
	pr := runPipeline(t, backends, fw, catalog, now)
	require.NotEmpty(t, pr.manualResults, "Should have manual policy results")

	// All manual policies should pass
	for _, result := range pr.manualResults {
		assert.Equal(t, evidence.StatusPass, result.Status,
			"Policy %s (control %s) should pass but got %s: %s",
			result.PolicyID, result.ControlID, result.Status, result.Message)
		assert.Empty(t, result.Violations,
			"Policy %s should have no violations", result.PolicyID)
		t.Logf("PASS: %s (control %s)", result.PolicyID, result.ControlID)
	}

	t.Logf("=== Phase 3: Verify execution-state.json attestations in S3 ===")
	for _, entry := range catalog.Entries {
		period, _ := manualPkg.CurrentPeriod(entry.Frequency, now, entry.GracePeriod)
		assert.True(t, pr.state.IsAttested(entry.ID, period.Key),
			"Entry %s should be attested for period %s", entry.ID, period.Key)
	}

	// Re-read execution state from S3 to confirm it was persisted
	statePath := filepath.Join(frameworkName, "execution-state.json")
	reloadedState, err := manualPkg.LoadState(context.Background(), backends.manual, statePath)
	require.NoError(t, err)
	for _, entry := range catalog.Entries {
		period, _ := manualPkg.CurrentPeriod(entry.Frequency, now, entry.GracePeriod)
		assert.True(t, reloadedState.IsAttested(entry.ID, period.Key),
			"Reloaded state: entry %s should be attested for period %s", entry.ID, period.Key)
	}

	t.Logf("=== Phase 4: Verify policy results stored in S3 ===")
	finalKeys := listS3Objects(t, region, bucket, basePrefix)
	t.Logf("Final S3 state: %d objects total", len(finalKeys))
	for _, key := range finalKeys {
		t.Logf("  -> %s", key)
	}

	// Verify result.json exists for each policy
	for _, result := range pr.manualResults {
		slug := storage.PolicySlug(result.PolicyID, frameworkName)
		found := false
		for _, key := range finalKeys {
			if strings.Contains(key, slug+"/") && strings.HasSuffix(key, "/result.json") {
				found = true

				// Read and validate the stored result
				resultData, err := backends.results.Get(context.Background(), strings.TrimPrefix(key, basePrefix))
				require.NoError(t, err, "Should be able to read result.json for %s", result.PolicyID)

				var stored storage.StoredPolicyResult
				require.NoError(t, json.Unmarshal(resultData, &stored))
				assert.Equal(t, result.PolicyID, stored.PolicyID, "Stored policy ID should match")
				assert.Equal(t, result.Status, stored.Status, "Stored status should match")
				assert.Equal(t, "e2e-test", stored.CLIVersion, "CLI version should be set")
				t.Logf("Verified result.json: %s status=%s", result.PolicyID, stored.Status)
				break
			}
		}
		assert.True(t, found, "result.json should exist for policy %s (slug: %s)", result.PolicyID, slug)
	}

	// Verify signed evidence envelopes: read each from S3, check public key + Ed25519 signature
	verifier := attestation.NewEd25519Verifier()
	envelopeCount := 0
	for _, key := range finalKeys {
		if !strings.Contains(key, "/evidence/") || !strings.HasSuffix(key, ".json") || strings.Contains(key, manualSubPrefix) {
			continue
		}
		envelopeCount++

		envelopeData, err := backends.results.Get(context.Background(), strings.TrimPrefix(key, basePrefix))
		require.NoError(t, err, "Should be able to read evidence envelope: %s", key)

		var envelope attestation.EvidenceEnvelope
		require.NoError(t, json.Unmarshal(envelopeData, &envelope),
			"Evidence envelope should be valid JSON: %s", key)

		// Verify envelope structure
		assert.NotEmpty(t, envelope.PublicKey,
			"Envelope should have public_key: %s", key)
		assert.Equal(t, attestation.AlgorithmEd25519, envelope.Signature.Algorithm,
			"Signature algorithm should be ed25519: %s", key)
		assert.NotEmpty(t, envelope.Signature.Value,
			"Envelope should have signature value: %s", key)
		assert.False(t, envelope.Signed.Timestamp.IsZero(),
			"Signed payload should have non-zero timestamp: %s", key)
		assert.NotEmpty(t, envelope.Signed.Evidence,
			"Signed payload should have evidence data: %s", key)

		// Cryptographically verify the signature
		err = verifier.Verify(&envelope)
		assert.NoError(t, err, "Ed25519 signature verification should pass: %s", key)
		t.Logf("Verified signed envelope: %s (pubkey=%s...)", key, envelope.PublicKey[:16])
	}
	assert.Greater(t, envelopeCount, 0, "Should have evidence envelope files stored by StoreRun")
	t.Logf("Verified %d signed evidence envelopes with valid Ed25519 signatures", envelopeCount)

	t.Logf("Positive scenario: %d policies passed, all entries attested, results + attestations stored in S3", len(pr.manualResults))
}

// RunNegativeScenario uploads invalid evidence to S3 and verifies policies fail.
//
// Invalid evidence:
//   - Checklist with required items NOT checked -> policy violation
//   - Declaration with accepted=false -> policy violation
//   - Document upload entries have no evidence -> "not_uploaded" (within_window = pass)
func RunNegativeScenario(t *testing.T) {
	t.Helper()
	bucket, region := resolveS3Config(t)
	basePrefix := s3TestPrefix()
	backends := setupTestBackends(t, bucket, region, basePrefix)
	fw, catalog := loadFramework(t)
	now := time.Now().UTC()

	t.Logf("=== Phase 1: Upload invalid evidence to S3 ===")
	t.Logf("S3 base prefix: s3://%s/%s", bucket, basePrefix)

	// Place invalid checklist evidence: required items NOT checked
	irEntry := catalog.GetEntry("incident_response_test")
	require.NotNil(t, irEntry)
	irPeriod, err := manualPkg.CurrentPeriod(irEntry.Frequency, now, irEntry.GracePeriod)
	require.NoError(t, err)

	irSubmitted := manualPkg.SubmittedEvidence{
		SchemaVersion: "1.0",
		EvidenceID:    "incident_response_test",
		Type:          manualPkg.EvidenceTypeChecklist,
		Framework:     frameworkName,
		Control:       irEntry.Control,
		Period:        irPeriod.Key,
		CompletedBy:   "test@e2e.sigcomply.dev",
		CompletedAt:   now,
		Items: []manualPkg.SubmittedChecklistItem{
			{ID: "plan_tested", Checked: false},        // required — NOT checked
			{ID: "roles_verified", Checked: false},      // required — NOT checked
			{ID: "communication_tested", Checked: true}, // required — checked
			{ID: "lessons_documented", Checked: true},   // optional — checked
		},
	}
	placeEvidence(t, backends.manual, "incident_response_test", irPeriod.Key, irSubmitted)

	// Place invalid declaration: accepted = false
	raEntry := catalog.GetEntry("risk_acceptance_signoff")
	require.NotNil(t, raEntry)
	raPeriod, err := manualPkg.CurrentPeriod(raEntry.Frequency, now, raEntry.GracePeriod)
	require.NoError(t, err)

	notAccepted := false
	raSubmitted := manualPkg.SubmittedEvidence{
		SchemaVersion:   "1.0",
		EvidenceID:      "risk_acceptance_signoff",
		Type:            manualPkg.EvidenceTypeDeclaration,
		Framework:       frameworkName,
		Control:         raEntry.Control,
		Period:          raPeriod.Key,
		CompletedBy:     "test@e2e.sigcomply.dev",
		CompletedAt:     now,
		DeclarationText: raEntry.DeclarationText,
		Accepted:        &notAccepted,
	}
	placeEvidence(t, backends.manual, "risk_acceptance_signoff", raPeriod.Key, raSubmitted)

	// Place invalid declaration from the new data-protection set: media_sanitization, accepted=false
	msEntry := catalog.GetEntry("media_sanitization")
	require.NotNil(t, msEntry, "media_sanitization entry should exist in catalog")
	msPeriod, err := manualPkg.CurrentPeriod(msEntry.Frequency, now, msEntry.GracePeriod)
	require.NoError(t, err)

	msSubmitted := manualPkg.SubmittedEvidence{
		SchemaVersion:   "1.0",
		EvidenceID:      "media_sanitization",
		Type:            manualPkg.EvidenceTypeDeclaration,
		Framework:       frameworkName,
		Control:         msEntry.Control,
		Period:          msPeriod.Key,
		CompletedBy:     "test@e2e.sigcomply.dev",
		CompletedAt:     now,
		DeclarationText: msEntry.DeclarationText,
		Accepted:        &notAccepted,
	}
	placeEvidence(t, backends.manual, "media_sanitization", msPeriod.Key, msSubmitted)

	// Don't upload anything for document_upload entries — they'll be "not_uploaded"

	keys := listS3Objects(t, region, bucket, basePrefix)
	t.Logf("Phase 1 complete: %d objects in S3", len(keys))

	t.Logf("=== Phase 2: Run OPA evaluation + StoreRun — expect failures ===")
	pr := runPipeline(t, backends, fw, catalog, now)
	require.NotEmpty(t, pr.manualResults)

	resultMap := make(map[string]evidence.PolicyResult)
	for _, result := range pr.manualResults {
		resultMap[result.PolicyID] = result
		t.Logf("Result: %s status=%s violations=%d", result.PolicyID, result.Status, len(result.Violations))
	}

	// Incident response test should FAIL (required items unchecked)
	irResult, ok := resultMap["soc2-cc7.4-incident-response-test"]
	require.True(t, ok, "Incident response test policy result must exist")
	assert.Equal(t, evidence.StatusFail, irResult.Status,
		"Incident response test should fail with unchecked required items")
	assert.GreaterOrEqual(t, len(irResult.Violations), 2,
		"Should have at least 2 violations (plan_tested and roles_verified unchecked)")

	// Risk acceptance should FAIL (not accepted)
	raResult, ok := resultMap["soc2-cc3.1-risk-acceptance"]
	require.True(t, ok, "Risk acceptance policy result must exist")
	assert.Equal(t, evidence.StatusFail, raResult.Status,
		"Risk acceptance should fail when not accepted")
	assert.NotEmpty(t, raResult.Violations)

	// Media sanitization (new data-protection entry) should FAIL (not accepted)
	msResult, ok := resultMap["soc2-cc6.5-media-sanitization"]
	require.True(t, ok, "Media sanitization policy result must exist")
	assert.Equal(t, evidence.StatusFail, msResult.Status,
		"Media sanitization should fail when not accepted")
	assert.NotEmpty(t, msResult.Violations)

	t.Logf("=== Phase 3: Verify execution state — failed entries not attested ===")
	if irPeriods, ok := pr.state.Manual["incident_response_test"]; ok {
		if entry, ok := irPeriods[irPeriod.Key]; ok {
			assert.Equal(t, "uploaded", entry.Status,
				"Failed checklist should have 'uploaded' status, not 'attested'")
		}
	}
	if raPeriods, ok := pr.state.Manual["risk_acceptance_signoff"]; ok {
		if entry, ok := raPeriods[raPeriod.Key]; ok {
			assert.Equal(t, "uploaded", entry.Status,
				"Failed declaration should have 'uploaded' status, not 'attested'")
		}
	}
	if msPeriods, ok := pr.state.Manual["media_sanitization"]; ok {
		if entry, ok := msPeriods[msPeriod.Key]; ok {
			assert.Equal(t, "uploaded", entry.Status,
				"Failed media_sanitization declaration should have 'uploaded' status, not 'attested'")
		}
	}

	t.Logf("=== Phase 4: Verify failed policy results stored in S3 ===")
	finalKeys := listS3Objects(t, region, bucket, basePrefix)
	t.Logf("Final S3 state: %d objects total", len(finalKeys))

	// Verify result.json for failed policies contains violations
	for _, policyID := range []string{"soc2-cc7.4-incident-response-test", "soc2-cc3.1-risk-acceptance", "soc2-cc6.5-media-sanitization"} {
		slug := storage.PolicySlug(policyID, frameworkName)
		for _, key := range finalKeys {
			if strings.Contains(key, slug+"/") && strings.HasSuffix(key, "/result.json") {
				resultData, err := backends.results.Get(context.Background(), strings.TrimPrefix(key, basePrefix))
				require.NoError(t, err)

				var stored storage.StoredPolicyResult
				require.NoError(t, json.Unmarshal(resultData, &stored))
				assert.Equal(t, evidence.StatusFail, stored.Status,
					"Stored result for %s should be fail", policyID)
				assert.NotEmpty(t, stored.Violations,
					"Stored result for %s should have violations", policyID)
				t.Logf("Verified stored failure: %s violations=%d", policyID, len(stored.Violations))
				break
			}
		}
	}

	// Verify signed evidence envelopes have valid attestations even for failed policies
	verifier := attestation.NewEd25519Verifier()
	envelopeCount := 0
	for _, key := range finalKeys {
		if !strings.Contains(key, "/evidence/") || !strings.HasSuffix(key, ".json") || strings.Contains(key, manualSubPrefix) {
			continue
		}
		envelopeCount++

		envelopeData, err := backends.results.Get(context.Background(), strings.TrimPrefix(key, basePrefix))
		require.NoError(t, err)

		var envelope attestation.EvidenceEnvelope
		require.NoError(t, json.Unmarshal(envelopeData, &envelope))
		assert.NotEmpty(t, envelope.PublicKey, "Envelope should have public_key: %s", key)
		assert.Equal(t, attestation.AlgorithmEd25519, envelope.Signature.Algorithm)
		assert.NoError(t, verifier.Verify(&envelope),
			"Ed25519 signature should be valid even for failed policies: %s", key)
		t.Logf("Verified signed envelope: %s", key)
	}
	assert.Greater(t, envelopeCount, 0, "Should have evidence envelope files")
	t.Logf("Verified %d signed evidence envelopes with valid Ed25519 signatures", envelopeCount)

	t.Logf("Negative scenario: verified expected failures + valid attestations")
}

// RunMissingScenario runs with no evidence in S3 — verifies "not_uploaded" handling.
// Within the current period, not_uploaded + within_window = pass (not overdue yet).
func RunMissingScenario(t *testing.T) {
	t.Helper()
	bucket, region := resolveS3Config(t)
	basePrefix := s3TestPrefix()
	backends := setupTestBackends(t, bucket, region, basePrefix)
	fw, catalog := loadFramework(t)
	now := time.Now().UTC()

	t.Logf("=== Running with empty S3 prefix (no evidence files) ===")
	t.Logf("S3 base prefix: s3://%s/%s", bucket, basePrefix)

	pr := runPipeline(t, backends, fw, catalog, now)
	require.NotEmpty(t, pr.manualResults, "Should have manual policy results even with no evidence")

	for _, result := range pr.manualResults {
		t.Logf("Missing: %s status=%s violations=%d eval=%d",
			result.PolicyID, result.Status, len(result.Violations), result.ResourcesEvaluated)

		assert.Equal(t, 1, result.ResourcesEvaluated,
			"Policy %s should evaluate 1 resource (the not_uploaded entry)", result.PolicyID)
		assert.Equal(t, evidence.StatusPass, result.Status,
			"Policy %s should pass for not_uploaded + within_window (current period)", result.PolicyID)
	}

	// Verify StoreRun persisted results even for "missing" evidence
	finalKeys := listS3Objects(t, region, bucket, basePrefix)
	resultCount := 0
	for _, key := range finalKeys {
		if strings.HasSuffix(key, "/result.json") {
			resultCount++
		}
	}
	assert.Equal(t, len(pr.manualResults), resultCount,
		"Should have result.json for each policy even when evidence is missing")

	t.Logf("Missing scenario: %d policies evaluated, %d result.json files stored", len(pr.manualResults), resultCount)
}
