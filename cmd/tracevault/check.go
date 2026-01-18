package tracevault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/tracevault/tracevault-cli/internal/compliance_frameworks/engine"
	"github.com/tracevault/tracevault-cli/internal/compliance_frameworks/soc2"
	"github.com/tracevault/tracevault-cli/internal/core/config"
	"github.com/tracevault/tracevault-cli/internal/core/evidence"
	"github.com/tracevault/tracevault-cli/internal/core/output"
	"github.com/tracevault/tracevault-cli/internal/core/storage"
	"github.com/tracevault/tracevault-cli/internal/data_sources/apis/aws"
)

const (
	backendLocal = "local"
	backendS3    = "s3"
)

var (
	flagFramework      string
	flagOutput         string
	flagVerbose        bool
	flagRegion         string
	flagStore          bool
	flagStoragePath    string
	flagStorageBackend string
	flagCloud          bool
	flagNoCloud        bool
)

var checkCmd = newCheckCmd()

func newCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Run compliance checks against your infrastructure",
		Long: `Run compliance checks against your infrastructure.

The check command collects evidence from your cloud providers, evaluates
compliance policies, and reports the results.

By default, it auto-detects available credentials and runs SOC 2 checks.

Examples:
  # Run with auto-detected AWS credentials
  tracevault check

  # Specify framework and region
  tracevault check --framework soc2 --region us-west-2

  # Output as JSON
  tracevault check --output json

  # Output as JUnit XML (for CI/CD)
  tracevault check --output junit`,
		RunE: runCheck,
	}

	cmd.Flags().StringVarP(&flagFramework, "framework", "f", "", "Compliance framework (soc2, hipaa, iso27001)")
	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Output format (text, json, junit)")
	cmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().StringVar(&flagRegion, "region", "", "AWS region")
	cmd.Flags().BoolVar(&flagStore, "store", false, "Store evidence and results to configured storage")
	cmd.Flags().StringVar(&flagStoragePath, "storage-path", "", "Local storage path (default: ./.tracevault/evidence)")
	cmd.Flags().StringVar(&flagStorageBackend, "storage-backend", "", "Storage backend (local, s3)")
	cmd.Flags().BoolVar(&flagCloud, "cloud", false, "Force submission to TraceVault Cloud (requires TRACEVAULT_API_TOKEN)")
	cmd.Flags().BoolVar(&flagNoCloud, "no-cloud", false, "Disable submission to TraceVault Cloud")

	return cmd
}

func runCheck(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	startTime := time.Now()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	// Apply CLI flag overrides
	if flagFramework != "" {
		cfg.Framework = flagFramework
	}
	if flagOutput != "" {
		cfg.OutputFormat = flagOutput
	}
	if flagVerbose {
		cfg.Verbose = true
	}

	// Apply storage flag overrides
	if flagStore {
		cfg.Storage.Enabled = true
	}
	if flagStoragePath != "" {
		cfg.Storage.Path = flagStoragePath
	}
	if flagStorageBackend != "" {
		cfg.Storage.Backend = flagStorageBackend
	}

	// Set storage defaults if enabled but not configured
	if cfg.Storage.Enabled {
		if cfg.Storage.Backend == "" {
			cfg.Storage.Backend = backendLocal
		}
		if cfg.Storage.Backend == backendLocal && cfg.Storage.Path == "" {
			cfg.Storage.Path = "./.tracevault/evidence"
		}
	}

	// Re-validate after overrides
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	// Select output mode based on format
	switch cfg.OutputFormat {
	case "json":
		return runCheckJSON(ctx, cfg)
	case "junit":
		return runCheckJUnit(ctx, cfg)
	default:
		return runCheckText(ctx, cfg, startTime)
	}
}

func runCheckText(ctx context.Context, cfg *config.Config, startTime time.Time) error {
	// Print header
	fmt.Println("TraceVault Compliance Check")
	fmt.Println("===========================")
	fmt.Printf("Framework: %s\n", cfg.Framework)
	if cfg.CI {
		fmt.Printf("CI: %s\n", cfg.CIProvider)
	}
	fmt.Println()

	// Initialize AWS collector
	collector := aws.New()
	if flagRegion != "" {
		collector.WithRegion(flagRegion)
	}

	if err := collector.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize AWS collector: %w", err)
	}

	// Check connectivity
	status := collector.Status(ctx)

	if !status.Connected {
		fmt.Fprintf(os.Stderr, "Warning: AWS connection failed: %s\n", status.Error)
		fmt.Println()
		fmt.Println("No AWS credentials detected. Please configure credentials using:")
		fmt.Println("  - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)")
		fmt.Println("  - AWS CLI (aws configure)")
		fmt.Println("  - IAM role (when running in AWS)")
		fmt.Println()
		return fmt.Errorf("no AWS credentials available")
	}

	fmt.Printf("AWS Account: %s\n", status.AccountID)
	if status.Region != "" {
		fmt.Printf("AWS Region:  %s\n", status.Region)
	}
	fmt.Println()

	// Collect evidence
	result, err := collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect evidence: %w", err)
	}

	printEvidenceCollection(result)

	// Load framework and evaluate policies
	policyResults, err := evaluatePolicies(ctx, cfg.Framework, result.Evidence)
	if err != nil {
		return fmt.Errorf("failed to evaluate policies: %w", err)
	}

	// Build check result
	checkResult := &evidence.CheckResult{
		RunID:         uuid.New().String(),
		Framework:     cfg.Framework,
		Timestamp:     time.Now(),
		PolicyResults: policyResults,
	}
	checkResult.CalculateSummary()

	// Store evidence if enabled
	var manifest *storage.Manifest
	if cfg.Storage.Enabled {
		fmt.Println()
		fmt.Println("Storage")
		fmt.Println("-------")

		var storageErr error
		manifest, storageErr = storeEvidence(ctx, cfg, checkResult, result.Evidence)
		if storageErr != nil {
			fmt.Printf("  [warn] Failed to store evidence: %s\n", storageErr)
		} else {
			fmt.Printf("  [done] Stored %d evidence items\n", manifest.EvidenceCount)
			fmt.Printf("  [done] Manifest: %s\n", manifest.RunID)
		}
	}

	// Submit to TraceVault Cloud if enabled
	if shouldSubmitToCloud(cfg, flagCloud, flagNoCloud) {
		printCloudSubmission(ctx, cfg, checkResult, result.Evidence, manifest)
	}

	// Format and display results
	fmt.Println()
	formatter := output.NewTextFormatter(os.Stdout)
	if err := formatter.FormatCheckResult(checkResult); err != nil {
		return fmt.Errorf("failed to format results: %w", err)
	}

	fmt.Println()
	elapsed := time.Since(startTime)
	fmt.Printf("Completed in %s\n", elapsed.Round(time.Millisecond))

	// Return error if there are failures (for CI/CD exit code)
	if checkResult.HasFailures() {
		return fmt.Errorf("compliance check failed: %d policy violations", checkResult.Summary.FailedPolicies)
	}

	return nil
}

func runCheckJSON(ctx context.Context, cfg *config.Config) error {
	// Initialize AWS collector
	collector := aws.New()
	if flagRegion != "" {
		collector.WithRegion(flagRegion)
	}

	if err := collector.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize AWS collector: %w", err)
	}

	// Check connectivity
	status := collector.Status(ctx)
	if !status.Connected {
		return fmt.Errorf("no AWS credentials available: %s", status.Error)
	}

	// Collect evidence
	result, err := collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect evidence: %w", err)
	}

	// Load framework and evaluate policies
	policyResults, err := evaluatePolicies(ctx, cfg.Framework, result.Evidence)
	if err != nil {
		return fmt.Errorf("failed to evaluate policies: %w", err)
	}

	// Build check result
	checkResult := &evidence.CheckResult{
		RunID:         uuid.New().String(),
		Framework:     cfg.Framework,
		Timestamp:     time.Now(),
		PolicyResults: policyResults,
	}
	checkResult.CalculateSummary()

	// Store evidence if enabled
	var manifest *storage.Manifest
	if cfg.Storage.Enabled {
		var storageErr error
		manifest, storageErr = storeEvidence(ctx, cfg, checkResult, result.Evidence)
		if storageErr != nil {
			// Log storage error but continue
			_ = storageErr
		}
	}

	// Submit to cloud if enabled
	var cloudResponse *cloudSubmitResult
	if shouldSubmitToCloud(cfg, flagCloud, flagNoCloud) {
		cloudResp, cloudErr := submitToCloud(ctx, cfg, checkResult, result.Evidence, manifest, "")
		if cloudErr == nil && cloudResp != nil {
			cloudResponse = &cloudSubmitResult{
				Success: cloudResp.Success(),
				RunID:   cloudResp.RunID(),
			}
			if driftSummary := cloudResp.GetDriftSummary(); driftSummary != nil {
				cloudResponse.DriftSummary = &driftInfo{
					HasDrift:           driftSummary.HasDrift,
					NewViolations:      driftSummary.NewViolations,
					ResolvedViolations: driftSummary.ResolvedViolations,
					ScoreChange:        driftSummary.ScoreChange,
				}
			}
		}
	}

	// Build JSON output
	var manifestID string
	if manifest != nil {
		manifestID = manifest.RunID
	}

	jsonOutput := struct {
		Framework     string                  `json:"framework"`
		RunID         string                  `json:"run_id"`
		AccountID     string                  `json:"account_id"`
		Region        string                  `json:"region"`
		Timestamp     time.Time               `json:"timestamp"`
		PolicyResults []evidence.PolicyResult `json:"policy_results"`
		Summary       evidence.CheckSummary   `json:"summary"`
		Evidence      []evidence.Evidence     `json:"evidence,omitempty"`
		Errors        []aws.CollectionError   `json:"errors,omitempty"`
		ManifestID    string                  `json:"manifest_id,omitempty"`
		Cloud         *cloudSubmitResult      `json:"cloud,omitempty"`
	}{
		Framework:     cfg.Framework,
		RunID:         checkResult.RunID,
		AccountID:     status.AccountID,
		Region:        status.Region,
		Timestamp:     checkResult.Timestamp,
		PolicyResults: checkResult.PolicyResults,
		Summary:       checkResult.Summary,
		Evidence:      result.Evidence,
		Errors:        result.Errors,
		ManifestID:    manifestID,
		Cloud:         cloudResponse,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(jsonOutput); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	// Return error if there are failures (for CI/CD exit code)
	if checkResult.HasFailures() {
		return fmt.Errorf("compliance check failed: %d policy violations", checkResult.Summary.FailedPolicies)
	}

	return nil
}

func runCheckJUnit(ctx context.Context, cfg *config.Config) error {
	// Initialize AWS collector
	collector := aws.New()
	if flagRegion != "" {
		collector.WithRegion(flagRegion)
	}

	if err := collector.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize AWS collector: %w", err)
	}

	// Check connectivity
	status := collector.Status(ctx)
	if !status.Connected {
		return fmt.Errorf("no AWS credentials available: %s", status.Error)
	}

	// Collect evidence
	result, err := collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect evidence: %w", err)
	}

	// Load framework and evaluate policies
	policyResults, err := evaluatePolicies(ctx, cfg.Framework, result.Evidence)
	if err != nil {
		return fmt.Errorf("failed to evaluate policies: %w", err)
	}

	// Build check result
	checkResult := &evidence.CheckResult{
		RunID:         uuid.New().String(),
		Framework:     cfg.Framework,
		Timestamp:     time.Now(),
		PolicyResults: policyResults,
	}
	checkResult.CalculateSummary()

	// Store evidence if enabled (silently, as JUnit output should be pure XML)
	var manifest *storage.Manifest
	if cfg.Storage.Enabled {
		//nolint:errcheck // Intentionally ignoring storage errors in JUnit mode to preserve XML output
		manifest, _ = storeEvidence(ctx, cfg, checkResult, result.Evidence)
	}

	// Submit to cloud if enabled (silently, as JUnit output should be pure XML)
	if shouldSubmitToCloud(cfg, flagCloud, flagNoCloud) {
		//nolint:errcheck // Intentionally ignoring cloud errors in JUnit mode to preserve XML output
		submitToCloud(ctx, cfg, checkResult, result.Evidence, manifest, "")
	}

	// Format as JUnit XML
	formatter := output.NewJUnitFormatter(os.Stdout)
	if err := formatter.FormatCheckResult(checkResult); err != nil {
		return fmt.Errorf("failed to format JUnit XML: %w", err)
	}

	// Return error if there are failures (for CI/CD exit code)
	if checkResult.HasFailures() {
		return fmt.Errorf("compliance check failed: %d policy violations", checkResult.Summary.FailedPolicies)
	}

	return nil
}

// evaluatePolicies loads the framework and evaluates all policies against evidence.
func evaluatePolicies(ctx context.Context, frameworkName string, evidenceList []evidence.Evidence) ([]evidence.PolicyResult, error) {
	// Get framework (currently only SOC2 is implemented)
	var framework engine.Framework
	switch frameworkName {
	case "soc2":
		framework = soc2.New()
	default:
		return nil, fmt.Errorf("unsupported framework: %s (only 'soc2' is currently supported)", frameworkName)
	}

	// Create engine and load policies
	eng := engine.New()
	for _, policy := range framework.Policies() {
		if err := eng.LoadPolicy(policy.Name, policy.Source); err != nil {
			return nil, fmt.Errorf("failed to load policy %s: %w", policy.Name, err)
		}
	}

	// Evaluate all policies
	return eng.Evaluate(ctx, evidenceList)
}

// printEvidenceCollection prints evidence collection results.
func printEvidenceCollection(result *aws.CollectionResult) {
	fmt.Println("Evidence Collection")
	fmt.Println("-------------------")

	typeCounts := countByResourceType(result.Evidence)
	for resourceType, count := range typeCounts {
		fmt.Printf("  [done] %s: %d resources\n", resourceType, count)
	}

	if result.HasErrors() {
		fmt.Println()
		fmt.Println("Collection Warnings:")
		for _, e := range result.Errors {
			fmt.Printf("  [warn] %s: %s\n", e.Service, e.Error)
		}
	}

	fmt.Println()
	fmt.Printf("Total evidence collected: %d resources\n", len(result.Evidence))
	fmt.Println()
}

// printCloudSubmission handles cloud submission and prints the results for text output.
func printCloudSubmission(ctx context.Context, cfg *config.Config, checkResult *evidence.CheckResult, evidenceList []evidence.Evidence, manifest *storage.Manifest) {
	fmt.Println()
	fmt.Println("Cloud Submission")
	fmt.Println("----------------")

	cloudResp, cloudErr := submitToCloud(ctx, cfg, checkResult, evidenceList, manifest, "")
	if cloudErr != nil {
		fmt.Printf("  [warn] Failed to submit to cloud: %s\n", cloudErr)
		return
	}
	if cloudResp == nil {
		return
	}

	fmt.Printf("  [done] Submitted to TraceVault Cloud\n")
	fmt.Printf("  [done] Run ID: %s\n", cloudResp.RunID())
	if driftSummary := cloudResp.GetDriftSummary(); driftSummary != nil && driftSummary.HasDrift {
		fmt.Printf("  [info] Drift detected: %d new violations, %d resolved\n",
			driftSummary.NewViolations, driftSummary.ResolvedViolations)
		if driftSummary.ScoreChange != 0 {
			fmt.Printf("  [info] Compliance score change: %.1f%%\n", driftSummary.ScoreChange)
		}
	}
}

func countByResourceType(evidenceList []evidence.Evidence) map[string]int {
	counts := make(map[string]int)
	for i := range evidenceList {
		counts[evidenceList[i].ResourceType]++
	}
	return counts
}

// storeEvidence stores evidence and check results to the configured storage backend.
func storeEvidence(ctx context.Context, cfg *config.Config, checkResult *evidence.CheckResult, evidenceList []evidence.Evidence) (*storage.Manifest, error) {
	// Build storage configuration
	storageCfg := &storage.Config{
		Backend: cfg.Storage.Backend,
	}

	switch cfg.Storage.Backend {
	case backendLocal:
		storageCfg.Local = &storage.LocalConfig{
			Path: cfg.Storage.Path,
		}
	case backendS3:
		storageCfg.S3 = &storage.S3Config{
			Bucket: cfg.Storage.Bucket,
			Region: cfg.Storage.Region,
			Prefix: cfg.Storage.Prefix,
		}
	}

	// Create backend
	backend, err := storage.NewBackend(storageCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage backend: %w", err)
	}
	defer func() {
		_ = backend.Close() //nolint:errcheck // Close errors are not critical for storage cleanup
	}()

	// Initialize backend
	if err := backend.Init(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Store everything and get manifest
	manifest, err := storage.StoreRun(ctx, backend, checkResult, evidenceList)
	if err != nil {
		return nil, fmt.Errorf("failed to store run: %w", err)
	}

	return manifest, nil
}

// cloudSubmitResult is used for JSON output of cloud submission results.
type cloudSubmitResult struct {
	Success      bool       `json:"success"`
	RunID        string     `json:"run_id"`
	DashboardURL string     `json:"dashboard_url,omitempty"`
	DriftSummary *driftInfo `json:"drift_summary,omitempty"`
}

// driftInfo is used for JSON output of drift information.
type driftInfo struct {
	HasDrift           bool    `json:"has_drift"`
	NewViolations      int     `json:"new_violations"`
	ResolvedViolations int     `json:"resolved_violations"`
	ScoreChange        float64 `json:"score_change,omitempty"`
}
