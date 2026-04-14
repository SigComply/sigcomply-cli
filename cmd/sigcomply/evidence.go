package sigcomply

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/compliance_frameworks/engine"
	"github.com/sigcomply/sigcomply-cli/internal/core/config"
	"github.com/sigcomply/sigcomply-cli/internal/core/manual"
	"github.com/sigcomply/sigcomply-cli/internal/core/storage"
	"github.com/spf13/cobra"
)

var flagEvidenceConfig string
var flagEvidenceOutput string

var evidenceCmd = &cobra.Command{
	Use:   "evidence",
	Short: "Manage manual evidence",
	Long:  "Commands for managing manual evidence collection, including folder scaffolding and viewing the catalog.",
}

var evidenceInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create evidence folder structure in storage",
	Long: `Creates the folder structure for manual evidence in the configured storage backend.
For each manual evidence requirement, creates a folder with a README explaining what to upload.`,
	RunE: runEvidenceInit,
}

var evidenceCatalogCmd = &cobra.Command{
	Use:   "catalog",
	Short: "Show manual evidence requirements",
	Long:  "Displays the manual evidence catalog for the configured framework.",
	RunE:  runEvidenceCatalog,
}

var evidenceSchemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "Output the submitted evidence JSON schema",
	Long: `Outputs the JSON Schema that defines the structure of submitted evidence files.

Use this during SPA build to keep frontend types in sync with what the CLI expects:
  sigcomply evidence schema > src/schemas/submitted-evidence.schema.json`,
	RunE: runEvidenceSchema,
}

func runEvidenceInit(cmd *cobra.Command, args []string) (err error) {
	ctx := cmd.Context()

	cfg, err := loadEvidenceConfig()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	framework, err := getFramework(cfg)
	if err != nil {
		return err
	}

	mep, ok := framework.(engine.ManualEvidenceProvider)
	if !ok {
		return fmt.Errorf("framework %q does not support manual evidence", cfg.Framework)
	}

	catalog, err := mep.ManualCatalog()
	if err != nil {
		return fmt.Errorf("failed to load manual catalog: %w", err)
	}

	storageCfg := buildManualStorageConfig(cfg)
	backend, err := storage.NewBackend(storageCfg)
	if err != nil {
		return fmt.Errorf("failed to create storage backend: %w", err)
	}
	defer func() {
		if closeErr := backend.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	if err := backend.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}

	now := time.Now()
	created := 0

	for i := range catalog.Entries {
		entry := &catalog.Entries[i]
		period, periodErr := manual.CurrentPeriod(entry.Frequency, now, entry.GracePeriod)
		if periodErr != nil {
			fmt.Printf("  [warn] %s: %s\n", entry.ID, periodErr)
			continue
		}

		folderPath := filepath.Join(cfg.Framework, entry.ID, period.Key)
		readme := fmt.Sprintf("# %s\n\n%s\n\nEvidence ID: %s\nControl: %s\nType: %s\nFrequency: %s\nPeriod: %s\n\n"+
			"Upload your evidence.json file (and any attachments) to this folder.\n",
			entry.Name, entry.Description, entry.ID, entry.Control, entry.Type, entry.Frequency, period.Key)

		readmePath := filepath.Join(folderPath, "README.md")
		if _, storeErr := backend.StoreRaw(ctx, readmePath, []byte(readme), nil); storeErr != nil {
			fmt.Printf("  [warn] Failed to create %s: %s\n", readmePath, storeErr)
			continue
		}

		fmt.Printf("  [done] %s (%s)\n", folderPath, entry.Name)
		created++
	}

	// Create execution state if it doesn't exist
	statePath := filepath.Join(cfg.Framework, "execution-state.json")
	if _, getErr := backend.Get(ctx, statePath); getErr != nil {
		state := manual.NewExecutionState(cfg.Framework)
		if saveErr := state.Save(ctx, backend, statePath); saveErr != nil {
			fmt.Printf("  [warn] Failed to create execution state: %s\n", saveErr)
		} else {
			fmt.Printf("  [done] Created execution-state.json\n")
		}
	}

	fmt.Printf("\nCreated %d evidence folders for %s\n", created, cfg.Framework)
	return nil
}

func runEvidenceCatalog(cmd *cobra.Command, args []string) error {
	cfg, err := loadEvidenceConfig()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	framework, err := getFramework(cfg)
	if err != nil {
		return err
	}

	mep, ok := framework.(engine.ManualEvidenceProvider)
	if !ok {
		return fmt.Errorf("framework %q does not support manual evidence", cfg.Framework)
	}

	catalog, err := mep.ManualCatalog()
	if err != nil {
		return fmt.Errorf("failed to load manual catalog: %w", err)
	}

	if flagEvidenceOutput == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(catalog)
	}

	// Text output
	fmt.Printf("Manual Evidence Catalog: %s (v%s)\n", catalog.Framework, catalog.Version)
	fmt.Println("=" + repeatChar('=', 50))
	fmt.Println()

	for i := range catalog.Entries {
		entry := &catalog.Entries[i]
		fmt.Printf("%-35s %s\n", entry.ID, entry.Name)
		fmt.Printf("  Control:    %s\n", entry.Control)
		fmt.Printf("  Type:       %s\n", entry.Type)
		fmt.Printf("  Frequency:  %s\n", entry.Frequency)
		fmt.Printf("  Severity:   %s\n", entry.Severity)
		if entry.GracePeriod != "" {
			fmt.Printf("  Grace:      %s\n", entry.GracePeriod)
		}
		if len(entry.AcceptedFormats) > 0 {
			fmt.Printf("  Formats:    %v\n", entry.AcceptedFormats)
		}
		if len(entry.Items) > 0 {
			fmt.Printf("  Items:      %d checklist items\n", len(entry.Items))
		}
		fmt.Println()
	}

	fmt.Printf("Total: %d evidence requirements\n", len(catalog.Entries))
	return nil
}

func runEvidenceSchema(cmd *cobra.Command, args []string) error {
	schema := manual.SubmittedEvidenceSchema()

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(schema)
}

func loadEvidenceConfig() (*config.Config, error) {
	if flagEvidenceConfig != "" {
		cfg, err := config.LoadWithConfigPath(flagEvidenceConfig)
		if err != nil {
			return nil, err
		}
		return cfg, nil
	}
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func repeatChar(ch byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = ch
	}
	return string(b)
}
