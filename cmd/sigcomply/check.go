package sigcomply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/engine"
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/iso27001"
	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/core/attestation"
	"github.com/sigcomply/sigcomply-cli/internal/core/cloud"
	"github.com/sigcomply/sigcomply-cli/internal/core/config"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
	"github.com/sigcomply/sigcomply-cli/internal/core/output"
	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
	"github.com/sigcomply/sigcomply-cli/internal/data_sources/apis/aws"
	"github.com/sigcomply/sigcomply-cli/internal/data_sources/apis/github"
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
	flagGitHubOrg      string
	flagConfig         string
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
  sigcomply check

  # Specify framework and region
  sigcomply check --framework soc2 --region us-west-2

  # Output as JSON
  sigcomply check --output json

  # Output as JUnit XML (for CI/CD)
  sigcomply check --output junit

  # Use a specific config file
  sigcomply check --config /path/to/.sigcomply.yaml`,
		RunE: runCheck,
	}

	cmd.Flags().StringVarP(&flagFramework, "framework", "f", "", "Compliance framework (soc2, hipaa, iso27001)")
	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Output format (text, json, junit)")
	cmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().StringVar(&flagRegion, "region", "", "AWS region")
	cmd.Flags().BoolVar(&flagStore, "store", false, "Store evidence and results to configured storage")
	cmd.Flags().StringVar(&flagStoragePath, "storage-path", "", "Local storage path (default: ./.sigcomply/evidence)")
	cmd.Flags().StringVar(&flagStorageBackend, "storage-backend", "", "Storage backend (local, s3)")
	cmd.Flags().BoolVar(&flagCloud, "cloud", false, "Force submission to SigComply Cloud (requires OIDC in CI)")
	cmd.Flags().BoolVar(&flagNoCloud, "no-cloud", false, "Disable submission to SigComply Cloud")
	cmd.Flags().StringVar(&flagGitHubOrg, "github-org", "", "GitHub organization to collect evidence from (requires GITHUB_TOKEN)")
	cmd.Flags().StringVar(&flagConfig, "config", "", "Path to config file (default: .sigcomply.yaml)")

	return cmd
}

func runCheck(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	startTime := time.Now()

	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	applyFlagOverrides(cfg)

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

// loadConfig loads configuration from file and env, using --config flag if set.
func loadConfig() (*config.Config, error) {
	if flagConfig != "" {
		return config.LoadWithConfigPath(flagConfig)
	}
	return config.Load()
}

// applyFlagOverrides applies CLI flag values on top of the loaded config.
func applyFlagOverrides(cfg *config.Config) {
	if flagFramework != "" {
		cfg.Framework = flagFramework
	}
	if flagOutput != "" {
		cfg.OutputFormat = flagOutput
	}
	if flagVerbose {
		cfg.Verbose = true
	}

	// Storage flags
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
			cfg.Storage.Path = "./.sigcomply/evidence"
		}
	}

	// --github-org flag overrides config file
	if flagGitHubOrg != "" {
		cfg.GitHub.Org = flagGitHubOrg
	}

	// --region flag overrides config file
	if flagRegion != "" {
		cfg.AWS.Regions = []string{flagRegion}
	}
}

// resolveAWSRegion returns the effective AWS region from config, or empty for auto-detect.
func resolveAWSRegion(cfg *config.Config) string {
	if len(cfg.AWS.Regions) > 0 {
		return cfg.AWS.Regions[0]
	}
	return ""
}

// collectAWSEvidenceText initializes AWS collector, prints status, and collects evidence.
func collectAWSEvidenceText(ctx context.Context, cfg *config.Config) (*aws.CollectionResult, error) {
	collector := aws.New()
	if region := resolveAWSRegion(cfg); region != "" {
		collector.WithRegion(region)
	}

	if err := collector.Init(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize AWS collector: %w", err)
	}

	status := collector.Status(ctx)
	if !status.Connected {
		fmt.Fprintf(os.Stderr, "Warning: AWS connection failed: %s\n", status.Error)
		fmt.Println()
		fmt.Println("No AWS credentials detected. Please configure credentials using:")
		fmt.Println("  - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)")
		fmt.Println("  - AWS CLI (aws configure)")
		fmt.Println("  - IAM role (when running in AWS)")
		fmt.Println()
		return nil, fmt.Errorf("no AWS credentials available")
	}

	fmt.Printf("AWS Account: %s\n", status.AccountID)
	if status.Region != "" {
		fmt.Printf("AWS Region:  %s\n", status.Region)
	}
	fmt.Println()

	result, err := collector.Collect(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect evidence: %w", err)
	}

	printEvidenceCollection(result)
	return result, nil
}

//nolint:gocyclo // Complexity is acceptable for orchestration function with multiple data sources
func runCheckText(ctx context.Context, cfg *config.Config, startTime time.Time) error {
	// Print header
	fmt.Println("SigComply Compliance Check")
	fmt.Println("==========================")
	fmt.Printf("Framework: %s\n", cfg.Framework)
	if cfg.CI {
		fmt.Printf("CI: %s\n", cfg.CIProvider)
	}
	fmt.Println()

	// Collect evidence from AWS
	result, err := collectAWSEvidenceText(ctx, cfg)
	if err != nil {
		return err
	}

	// Collect evidence from GitHub if organization is configured
	if cfg.GitHub.Org != "" {
		ghResult, ghErr := collectGitHubEvidence(ctx, cfg.GitHub.Org)
		if ghErr != nil {
			fmt.Printf("  [warn] GitHub collection failed: %s\n", ghErr)
		} else {
			result.Evidence = append(result.Evidence, ghResult.Evidence...)
			printGitHubEvidenceCollection(ghResult)
		}
	}

	// Load framework and evaluate ALL policies (framework drives what gets checked)
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
		Environment: evidence.RunEnvironment{
			CI:         cfg.CI,
			CIProvider: cfg.CIProvider,
			Repository: cfg.Repository,
			Branch:     cfg.Branch,
			CommitSHA:  cfg.CommitSHA,
			CLIVersion: version,
		},
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

	// Build attestation from stored file hashes (requires storage + cloud submission)
	var att *attestation.Attestation
	if shouldSubmitToCloud(cfg, flagCloud, flagNoCloud) && cfg.Storage.Enabled && manifest != nil {
		att = buildAttestation(cfg, checkResult, manifest)
		if att != nil {
			if storeErr := storeAttestationFile(ctx, cfg, checkResult, att); storeErr != nil {
				fmt.Printf("  [warn] Failed to store attestation: %s\n", storeErr)
			}
		}
	}

	// Submit to SigComply Cloud if enabled
	if shouldSubmitToCloud(cfg, flagCloud, flagNoCloud) {
		printCloudSubmission(ctx, cfg, checkResult, result.Evidence, manifest, att)
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

//nolint:gocyclo // Complexity is acceptable for orchestration function with multiple data sources
func runCheckJSON(ctx context.Context, cfg *config.Config) error {
	// Initialize AWS collector
	collector := aws.New()
	if region := resolveAWSRegion(cfg); region != "" {
		collector.WithRegion(region)
	}

	if err := collector.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize AWS collector: %w", err)
	}

	// Check connectivity
	status := collector.Status(ctx)
	if !status.Connected {
		return fmt.Errorf("no AWS credentials available: %s", status.Error)
	}

	// Collect evidence from AWS
	result, err := collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect evidence: %w", err)
	}

	// Collect evidence from GitHub if organization is configured
	if cfg.GitHub.Org != "" {
		ghResult, ghErr := collectGitHubEvidence(ctx, cfg.GitHub.Org)
		if ghErr == nil {
			result.Evidence = append(result.Evidence, ghResult.Evidence...)
		}
	}

	// Load framework and evaluate ALL policies
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
		Environment: evidence.RunEnvironment{
			CI:         cfg.CI,
			CIProvider: cfg.CIProvider,
			Repository: cfg.Repository,
			Branch:     cfg.Branch,
			CommitSHA:  cfg.CommitSHA,
			CLIVersion: version,
		},
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

	// Build attestation from stored file hashes (requires storage + cloud submission)
	var att *attestation.Attestation
	if shouldSubmitToCloud(cfg, flagCloud, flagNoCloud) && cfg.Storage.Enabled && manifest != nil {
		att = buildAttestation(cfg, checkResult, manifest)
		if att != nil {
			storeAttestationFile(ctx, cfg, checkResult, att) //nolint:errcheck // Attestation storage errors are non-critical
		}
	}

	// Submit to cloud if enabled
	var cloudResponse *cloudSubmitResult
	if shouldSubmitToCloud(cfg, flagCloud, flagNoCloud) {
		cloudResp, cloudErr := submitToCloudWithAttestation(ctx, cfg, checkResult, manifest, att, "")
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

//nolint:gocyclo // Complexity is acceptable for orchestration function with multiple data sources
func runCheckJUnit(ctx context.Context, cfg *config.Config) error {
	// Initialize AWS collector
	collector := aws.New()
	if region := resolveAWSRegion(cfg); region != "" {
		collector.WithRegion(region)
	}

	if err := collector.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize AWS collector: %w", err)
	}

	// Check connectivity
	status := collector.Status(ctx)
	if !status.Connected {
		return fmt.Errorf("no AWS credentials available: %s", status.Error)
	}

	// Collect evidence from AWS
	result, err := collector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect evidence: %w", err)
	}

	// Collect evidence from GitHub if organization is configured
	if cfg.GitHub.Org != "" {
		ghResult, ghErr := collectGitHubEvidence(ctx, cfg.GitHub.Org)
		if ghErr == nil {
			result.Evidence = append(result.Evidence, ghResult.Evidence...)
		}
	}

	// Load framework and evaluate ALL policies
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
		Environment: evidence.RunEnvironment{
			CI:         cfg.CI,
			CIProvider: cfg.CIProvider,
			Repository: cfg.Repository,
			Branch:     cfg.Branch,
			CommitSHA:  cfg.CommitSHA,
			CLIVersion: version,
		},
	}
	checkResult.CalculateSummary()

	// Store evidence if enabled (silently, as JUnit output should be pure XML)
	var manifest *storage.Manifest
	if cfg.Storage.Enabled {
		//nolint:errcheck // Intentionally ignoring storage errors in JUnit mode to preserve XML output
		manifest, _ = storeEvidence(ctx, cfg, checkResult, result.Evidence)
	}

	// Build attestation from stored file hashes (requires storage + cloud submission)
	var att *attestation.Attestation
	if shouldSubmitToCloud(cfg, flagCloud, flagNoCloud) && cfg.Storage.Enabled && manifest != nil {
		att = buildAttestation(cfg, checkResult, manifest)
		if att != nil {
			storeAttestationFile(ctx, cfg, checkResult, att) //nolint:errcheck // Silently ignore in JUnit mode
		}
	}

	// Submit to cloud if enabled (silently, as JUnit output should be pure XML)
	if shouldSubmitToCloud(cfg, flagCloud, flagNoCloud) {
		//nolint:errcheck // Intentionally ignoring cloud errors in JUnit mode to preserve XML output
		submitToCloudWithAttestation(ctx, cfg, checkResult, manifest, att, "")
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

// evaluatePolicies loads the framework and evaluates ALL policies against evidence.
// The framework determines what gets checked — no policy filtering.
func evaluatePolicies(ctx context.Context, frameworkName string, evidenceList []evidence.Evidence) ([]evidence.PolicyResult, error) {
	// Get framework
	var framework engine.Framework
	switch frameworkName {
	case "soc2":
		framework = soc2.New()
	case "iso27001":
		framework = iso27001.New()
	default:
		return nil, fmt.Errorf("unsupported framework: %s (supported: 'soc2', 'iso27001')", frameworkName)
	}

	// Create engine and load ALL policies
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
func printCloudSubmission(ctx context.Context, cfg *config.Config, checkResult *evidence.CheckResult, _ []evidence.Evidence, manifest *storage.Manifest, att *attestation.Attestation) {
	fmt.Println()
	fmt.Println("Cloud Submission")
	fmt.Println("----------------")

	cloudResp, cloudErr := submitToCloudWithAttestation(ctx, cfg, checkResult, manifest, att, "")
	if cloudErr != nil {
		var apiErr *cloud.APIError
		if errors.As(cloudErr, &apiErr) && apiErr.IsSubscriptionRequired() {
			fmt.Printf("  [error] %s\n", apiErr.Message)
			if url := apiErr.UpgradeURL(); url != "" {
				fmt.Printf("  [info]  Upgrade at: %s\n", url)
			}
		} else {
			fmt.Printf("  [warn] Failed to submit to cloud: %s\n", cloudErr)
		}
		return
	}
	if cloudResp == nil {
		return
	}

	fmt.Printf("  [done] Submitted to SigComply Cloud\n")
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

// storeAttestationFile stores the attestation.json separately after evidence+hashes are computed.
func storeAttestationFile(ctx context.Context, cfg *config.Config, checkResult *evidence.CheckResult, att *attestation.Attestation) error {
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

	backend, err := storage.NewBackend(storageCfg)
	if err != nil {
		return fmt.Errorf("failed to create storage backend: %w", err)
	}
	defer backend.Close() //nolint:errcheck // Best-effort cleanup

	if err := backend.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}

	runPath := storage.NewRunPath(checkResult.Framework, checkResult.Timestamp)
	_, err = storage.StoreAttestation(ctx, backend, *runPath, att)
	return err
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

// collectGitHubEvidence collects evidence from a GitHub organization.
func collectGitHubEvidence(ctx context.Context, org string) (*github.CollectionResult, error) {
	collector := github.New().WithOrganization(org)

	if err := collector.Init(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize GitHub collector: %w", err)
	}

	// Check connectivity
	status := collector.Status(ctx)
	if !status.Connected {
		return nil, fmt.Errorf("GitHub connection failed: %s", status.Error)
	}

	return collector.Collect(ctx)
}

// printGitHubEvidenceCollection prints GitHub evidence collection results.
func printGitHubEvidenceCollection(result *github.CollectionResult) {
	fmt.Println()
	fmt.Println("GitHub Evidence Collection")
	fmt.Println("--------------------------")

	typeCounts := make(map[string]int)
	for i := range result.Evidence {
		typeCounts[result.Evidence[i].ResourceType]++
	}

	for resourceType, count := range typeCounts {
		fmt.Printf("  [done] %s: %d resources\n", resourceType, count)
	}

	if result.HasErrors() {
		fmt.Println()
		fmt.Println("GitHub Collection Warnings:")
		for _, e := range result.Errors {
			fmt.Printf("  [warn] %s: %s\n", e.Resource, e.Error)
		}
	}
}
