package sigcomply

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteJSONOutputFile(t *testing.T) {
	checkResult := &evidence.CheckResult{
		RunID:     "test-run-id",
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{
				PolicyID:  "cc6_1_mfa",
				ControlID: "CC6.1",
				Status:    evidence.StatusPass,
				Message:   "All users have MFA enabled",
			},
		},
	}
	checkResult.CalculateSummary()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "results.json")

	err := writeJSONOutputFile(path, checkResult)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &result))

	assert.Equal(t, "test-run-id", result["run_id"])
	assert.Equal(t, "soc2", result["framework"])
	assert.NotNil(t, result["summary"])
	assert.NotNil(t, result["policy_results"])
}

func TestWriteJSONOutputFile_CreatesParentDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "nested", "dir", "results.json")

	checkResult := &evidence.CheckResult{
		RunID:     "test-run-id",
		Framework: "soc2",
		Timestamp: time.Now(),
	}
	checkResult.CalculateSummary()

	err := writeJSONOutputFile(path, checkResult)
	require.NoError(t, err)

	_, statErr := os.Stat(path)
	require.NoError(t, statErr)
}

func TestWriteJSONOutputFile_SummaryFields(t *testing.T) {
	checkResult := &evidence.CheckResult{
		RunID:     "test-run-id",
		Framework: "soc2",
		Timestamp: time.Now(),
		PolicyResults: []evidence.PolicyResult{
			{PolicyID: "policy-1", Status: evidence.StatusPass},
			{PolicyID: "policy-2", Status: evidence.StatusFail},
		},
	}
	checkResult.CalculateSummary()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "results.json")

	require.NoError(t, writeJSONOutputFile(path, checkResult))

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &result))

	summary, ok := result["summary"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(2), summary["total_policies"])
	assert.Equal(t, float64(1), summary["passed_policies"])
	assert.Equal(t, float64(1), summary["failed_policies"])
}

func TestWriteJSONOutputFile_ValidJSON(t *testing.T) {
	checkResult := &evidence.CheckResult{
		RunID:         "run-valid",
		Framework:     "iso27001",
		Timestamp:     time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC),
		PolicyResults: []evidence.PolicyResult{},
	}
	checkResult.CalculateSummary()

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "out.json")

	require.NoError(t, writeJSONOutputFile(path, checkResult))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, json.Valid(data), "output file must contain valid JSON")
}

func TestJSONOutputFlagRegistered(t *testing.T) {
	cmd := newCheckCmd()
	flag := cmd.Flags().Lookup("json-output")
	require.NotNil(t, flag, "--json-output flag must be registered on the check command")
	assert.Equal(t, "", flag.DefValue, "default value must be empty string")
}
