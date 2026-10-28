package planner

import (
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

func TestExperimentalKeyWarnings(t *testing.T) {
	cfg := &spec.ProjectConfig{Experimental: map[string]any{
		"scopee": map[string]any{}, spec.VendorsKey: map[string]any{}, "vendor": map[string]any{},
	}}
	got := ExperimentalKeyWarnings(cfg)
	if len(got) != 2 {
		t.Fatalf("want warnings for scopee and vendor only; got %v", got)
	}
	if !strings.Contains(got[0], `"scopee"`) || !strings.Contains(got[1], `"vendor"`) {
		t.Errorf("warnings should name the keys in order: %v", got)
	}
	if ExperimentalKeyWarnings(&spec.ProjectConfig{}) != nil {
		t.Error("no experimental block must give no warnings")
	}
}
