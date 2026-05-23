package spec

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

func TestLoadFramework_ValidSOC2(t *testing.T) {
	data := readTestdata(t, "framework/valid_soc2.yaml")

	f, err := LoadFramework(data)
	if err != nil {
		t.Fatalf("LoadFramework: %v", err)
	}
	if f.ID() != "soc2" {
		t.Errorf("ID = %q; want soc2", f.ID())
	}
	if f.Version() != "2017" {
		t.Errorf("Version = %q; want 2017", f.Version())
	}
	controls := f.Controls()
	if len(controls) != 3 {
		t.Fatalf("Controls length = %d; want 3", len(controls))
	}
	if controls[1].ID != "SOC2.CC6.1" {
		t.Errorf("Controls[1].ID = %q; want SOC2.CC6.1", controls[1].ID)
	}
	if controls[1].BaselineSeverity != core.SeverityHigh {
		t.Errorf("Controls[1].BaselineSeverity = %q; want high", controls[1].BaselineSeverity)
	}
	policies := f.Policies()
	if len(policies) != 4 {
		t.Errorf("Policies length = %d; want 4", len(policies))
	}
}

func TestFrameworkSpec_SatisfiesInterface(t *testing.T) {
	// Compile-time assertion lives in test code so a refactor that
	// breaks the interface fails the test build immediately.
	var _ core.Framework = (*FrameworkSpec)(nil)
}

func TestLoadFramework_RoundTrip(t *testing.T) {
	data := readTestdata(t, "framework/valid_soc2.yaml")
	first, err := LoadFramework(data)
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	remarshaled, err := yaml.Marshal(first)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	second, err := LoadFramework(remarshaled)
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if first.ID() != second.ID() {
		t.Errorf("round-trip changed ID: %q vs %q", first.ID(), second.ID())
	}
	if len(first.Controls()) != len(second.Controls()) {
		t.Errorf("round-trip changed control count: %d vs %d", len(first.Controls()), len(second.Controls()))
	}
	if len(first.Policies()) != len(second.Policies()) {
		t.Errorf("round-trip changed policy count: %d vs %d", len(first.Policies()), len(second.Policies()))
	}
}

func TestLoadFramework_RejectsInvalid(t *testing.T) {
	cases := []struct {
		file    string
		wantSub string
	}{
		{"framework/invalid_missing_id.yaml", "id"},
		{"framework/invalid_empty_controls.yaml", "controls"},
		{"framework/invalid_duplicate_control.yaml", "duplicate control"},
		{"framework/invalid_bad_severity.yaml", "baseline_severity"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			data := readTestdata(t, tc.file)
			_, err := LoadFramework(data)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q; want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestLoadFramework_EmptyInput(t *testing.T) {
	if _, err := LoadFramework(nil); err == nil {
		t.Error("expected error on nil input")
	}
}
