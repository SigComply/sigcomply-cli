package tracevault

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/tracevault/tracevault-cli/internal/core/config"
	"github.com/tracevault/tracevault-cli/internal/data_sources/apis/aws"
)

var (
	flagFramework string
	flagOutput    string
	flagVerbose   bool
	flagRegion    string
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
  tracevault check --output json`,
		RunE: runCheck,
	}

	cmd.Flags().StringVarP(&flagFramework, "framework", "f", "", "Compliance framework (soc2, hipaa, iso27001)")
	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Output format (text, json)")
	cmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().StringVar(&flagRegion, "region", "", "AWS region")

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

	// Re-validate after overrides
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

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

	// TODO: Week 2 - Collect evidence from IAM, S3, CloudTrail
	// TODO: Week 3 - Evaluate policies with OPA engine
	// For now, just report successful connection

	fmt.Println("Evidence Collection")
	fmt.Println("-------------------")
	fmt.Println("  [pending] AWS IAM users")
	fmt.Println("  [pending] AWS S3 buckets")
	fmt.Println("  [pending] AWS CloudTrail trails")
	fmt.Println()

	fmt.Println("Policy Evaluation")
	fmt.Println("-----------------")
	fmt.Println("  [pending] CC6.1 - MFA for all users")
	fmt.Println("  [pending] CC6.2 - S3 encryption")
	fmt.Println("  [pending] CC7.1 - CloudTrail enabled")
	fmt.Println()

	elapsed := time.Since(startTime)
	fmt.Printf("Completed in %s\n", elapsed.Round(time.Millisecond))

	return nil
}
