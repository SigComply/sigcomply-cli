package sigcomply

import (
	"context"
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

const outputFormatJSON = "json"

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

var evidencePathCmd = &cobra.Command{
	Use:   "path <evidence_id>",
	Short: "Print the upload URI for a manual evidence entry",
	Long: `Resolves the fully-qualified storage URI where a manual evidence PDF is
expected for the active framework's current period.

This is the same URI surfaced in violation messages when a PDF is missing,
exposed as a standalone command for "where do I upload this?" workflows.`,
	Args: cobra.ExactArgs(1),
	RunE: runEvidencePath,
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

	storageCfg, err := buildManualStorageConfig(cfg)
	if err != nil {
		return err
	}
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
		if scaffoldEvidenceFolder(ctx, backend, cfg.Framework, &catalog.Entries[i], now) {
			created++
		}
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

// scaffoldEvidenceFolder creates the README placeholder for one catalog
// entry's current period. Returns true on success. Logs warnings on
// recoverable failures so init keeps going for the rest of the catalog.
func scaffoldEvidenceFolder(ctx context.Context, backend storage.Backend, framework string, entry *manual.CatalogEntry, now time.Time) bool {
	period, err := manual.CurrentPeriod(entry.Frequency, now, entry.GracePeriod)
	if err != nil {
		fmt.Printf("  [warn] %s: %s\n", entry.ID, err)
		return false
	}

	pdfPath, err := manual.ResolvePath(entry, framework, &period)
	if err != nil {
		fmt.Printf("  [warn] %s: %s\n", entry.ID, err)
		return false
	}
	folderPath := filepath.Dir(pdfPath)
	filename := filepath.Base(pdfPath)
	expectedURI := backend.URIFor(pdfPath)

	readme := fmt.Sprintf(
		"# %s\n\n%s\n\n"+
			"Evidence ID: %s\nControl: %s\nFrequency: %s\nPeriod: %s\n\n"+
			"Upload a single PDF as `%s` to this folder.\n\n"+
			"Full upload location:\n  %s\n",
		entry.Name, entry.Description,
		entry.ID, entry.Control, entry.Frequency, period.Key,
		filename,
		expectedURI,
	)

	readmePath := filepath.Join(folderPath, "README.md")
	if _, err := backend.StoreRaw(ctx, readmePath, []byte(readme), nil); err != nil {
		fmt.Printf("  [warn] Failed to create %s: %s\n", readmePath, err)
		return false
	}

	fmt.Printf("  [done] %s (%s)\n", folderPath, entry.Name)
	return true
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

	if flagEvidenceOutput == outputFormatJSON {
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

func runEvidencePath(cmd *cobra.Command, args []string) error {
	evidenceID := args[0]

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

	entry := catalog.GetEntry(evidenceID)
	if entry == nil {
		return fmt.Errorf("evidence ID %q not found in %s catalog", evidenceID, cfg.Framework)
	}

	period, err := manual.CurrentPeriod(entry.Frequency, time.Now(), entry.GracePeriod)
	if err != nil {
		return fmt.Errorf("period computation: %w", err)
	}

	pdfPath, err := manual.ResolvePath(entry, cfg.Framework, &period)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	storageCfg, err := buildManualStorageConfig(cfg)
	if err != nil {
		return err
	}
	backend, err := storage.NewBackend(storageCfg)
	if err != nil {
		return fmt.Errorf("failed to create storage backend: %w", err)
	}
	defer func() {
		_ = backend.Close() //nolint:errcheck // close is best-effort here
	}()

	if flagEvidenceOutput == outputFormatJSON {
		out := map[string]string{
			"evidence_id":   entry.ID,
			"framework":     cfg.Framework,
			"period":        period.Key,
			"expected_path": pdfPath,
			"expected_uri":  backend.URIFor(pdfPath),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	fmt.Println(backend.URIFor(pdfPath))
	return nil
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
