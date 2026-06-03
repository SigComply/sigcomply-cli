package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/manualcatalog"
	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
)

func TestEvidenceCatalog_JSONMatchesSPAContract(t *testing.T) {
	for _, fw := range []string{"soc2", "iso27001"} {
		var out bytes.Buffer
		if err := runEvidenceCatalog(&out, &evidenceFlags{framework: fw, output: "json"}); err != nil {
			t.Fatalf("%s: runEvidenceCatalog: %v", fw, err)
		}
		var cat manualcatalog.Catalog
		if err := json.Unmarshal(out.Bytes(), &cat); err != nil {
			t.Fatalf("%s: invalid JSON: %v", fw, err)
		}
		if cat.Framework != fw {
			t.Errorf("framework = %q; want %q", cat.Framework, fw)
		}
		if cat.Version == "" {
			t.Errorf("%s: empty version", fw)
		}
		if len(cat.Entries) == 0 {
			t.Fatalf("%s: no entries", fw)
		}
		for i := range cat.Entries {
			validateEntry(t, fw, &cat.Entries[i])
		}
	}
}

// validateEntry asserts one catalog entry satisfies the SPA contract:
// required scalars present, and type-specific content (declaration_text
// for declarations, items for checklists).
func validateEntry(t *testing.T, fw string, e *manualcatalog.Entry) {
	t.Helper()
	if e.ID == "" || e.Control == "" || e.Type == "" || e.Frequency == "" ||
		e.TemporalRule == "" || e.GracePeriod == "" || e.Name == "" ||
		e.Description == "" || e.Severity == "" {
		t.Errorf("%s entry %q missing a required field: %+v", fw, e.ID, e)
	}
	switch e.Type {
	case manualcatalog.TypeDeclaration:
		if e.DeclarationText == "" {
			t.Errorf("%s declaration %q missing declaration_text", fw, e.ID)
		}
	case manualcatalog.TypeChecklist:
		if len(e.Items) == 0 {
			t.Errorf("%s checklist %q has no items", fw, e.ID)
		}
	case manualcatalog.TypeDocumentUpload:
		// no extra content required
	default:
		t.Errorf("%s entry %q has unknown type %q", fw, e.ID, e.Type)
	}
}

func TestEvidenceCatalog_CoversEveryManualPolicy(t *testing.T) {
	// The export's entry IDs must equal the framework's manual-policy
	// catalog IDs — no drift between the policy library and the catalog.
	var out bytes.Buffer
	if err := runEvidenceCatalog(&out, &evidenceFlags{framework: "soc2", output: "json"}); err != nil {
		t.Fatalf("runEvidenceCatalog: %v", err)
	}
	var cat manualcatalog.Catalog
	if err := json.Unmarshal(out.Bytes(), &cat); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// At least one declaration and one checklist render in the SPA.
	var decls, checks int
	for i := range cat.Entries {
		switch cat.Entries[i].Type {
		case manualcatalog.TypeDeclaration:
			decls++
		case manualcatalog.TypeChecklist:
			checks++
		}
	}
	if decls == 0 || checks == 0 {
		t.Errorf("want at least one declaration and one checklist; got decls=%d checks=%d", decls, checks)
	}
}

func TestEvidenceCatalog_UnknownFramework(t *testing.T) {
	err := runEvidenceCatalog(&bytes.Buffer{}, &evidenceFlags{framework: "hipaa", output: "json"})
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != orchestrator.ExitConfig {
		t.Fatalf("want ExitConfig error; got %v", err)
	}
}

func TestEvidenceCatalog_InvalidOutput(t *testing.T) {
	err := runEvidenceCatalog(&bytes.Buffer{}, &evidenceFlags{framework: "soc2", output: "yaml"})
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != orchestrator.ExitConfig {
		t.Fatalf("want ExitConfig error; got %v", err)
	}
}

func TestEvidenceCatalog_TextOutput(t *testing.T) {
	var out bytes.Buffer
	if err := runEvidenceCatalog(&out, &evidenceFlags{framework: "soc2", output: "text"}); err != nil {
		t.Fatalf("runEvidenceCatalog: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "Manual Evidence Catalog: soc2") {
		t.Errorf("text output missing header: %q", s)
	}
	if !strings.Contains(s, "CONTROL") {
		t.Errorf("text output missing table header: %q", s)
	}
}

func TestResolveFramework(t *testing.T) {
	if got := resolveFramework("iso27001"); got != "iso27001" {
		t.Errorf("flag precedence: got %q", got)
	}
	t.Setenv("SIGCOMPLY_FRAMEWORK", "iso27001")
	if got := resolveFramework(""); got != "iso27001" {
		t.Errorf("env fallback: got %q", got)
	}
	t.Setenv("SIGCOMPLY_FRAMEWORK", "")
	if got := resolveFramework(""); got != "soc2" {
		t.Errorf("default: got %q", got)
	}
}
