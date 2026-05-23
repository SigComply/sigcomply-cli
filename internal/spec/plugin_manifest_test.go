package spec

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadPluginManifest_ValidAWSIAM(t *testing.T) {
	data := readTestdata(t, "plugin_manifest/valid_aws_iam.yaml")

	m, err := LoadPluginManifest(data)
	if err != nil {
		t.Fatalf("LoadPluginManifest: %v", err)
	}
	if m.ID != "aws.iam" {
		t.Errorf("ID = %q; want aws.iam", m.ID)
	}
	if m.DisplayName != "AWS IAM" {
		t.Errorf("DisplayName = %q; want %q", m.DisplayName, "AWS IAM")
	}
	wantEmits := []string{"user_record", "iam_role", "iam_policy", "access_key"}
	if len(m.Emits) != len(wantEmits) {
		t.Fatalf("Emits length = %d; want %d", len(m.Emits), len(wantEmits))
	}
	for i, want := range wantEmits {
		if m.Emits[i] != want {
			t.Errorf("Emits[%d] = %q; want %q", i, m.Emits[i], want)
		}
	}
	if m.Singleton {
		t.Error("Singleton = true; want false for aws.iam")
	}
	region, ok := m.ConfigSchema["region"]
	if !ok {
		t.Fatal("ConfigSchema missing \"region\"")
	}
	if region.Type != "string" || !region.Required {
		t.Errorf("region = %+v; want {Type: string, Required: true, ...}", region)
	}
}

func TestLoadPluginManifest_ValidManualPDF(t *testing.T) {
	data := readTestdata(t, "plugin_manifest/valid_manual_pdf.yaml")

	m, err := LoadPluginManifest(data)
	if err != nil {
		t.Fatalf("LoadPluginManifest: %v", err)
	}
	if m.ID != "manual.pdf" {
		t.Errorf("ID = %q; want manual.pdf", m.ID)
	}
	if !m.Singleton {
		t.Error("Singleton = false; want true for manual.pdf")
	}
	backend, ok := m.ConfigSchema["backend"]
	if !ok {
		t.Fatal("ConfigSchema missing \"backend\"")
	}
	if len(backend.Enum) != 4 {
		t.Errorf("backend.Enum length = %d; want 4", len(backend.Enum))
	}
}

func TestLoadPluginManifest_RoundTrip(t *testing.T) {
	data := readTestdata(t, "plugin_manifest/valid_aws_iam.yaml")
	first, err := LoadPluginManifest(data)
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	remarshaled, err := yaml.Marshal(&first)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	second, err := LoadPluginManifest(remarshaled)
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if first.ID != second.ID || first.DisplayName != second.DisplayName {
		t.Errorf("round-trip changed identity fields: %+v vs %+v", first, second)
	}
	if len(first.Emits) != len(second.Emits) {
		t.Errorf("round-trip changed emits length: %d vs %d", len(first.Emits), len(second.Emits))
	}
	if len(first.ConfigSchema) != len(second.ConfigSchema) {
		t.Errorf("round-trip changed config_schema size: %d vs %d", len(first.ConfigSchema), len(second.ConfigSchema))
	}
}

func TestLoadPluginManifest_RejectsInvalid(t *testing.T) {
	cases := []struct {
		file    string
		wantSub string
	}{
		{"plugin_manifest/invalid_missing_id.yaml", "id"},
		{"plugin_manifest/invalid_empty_emits.yaml", "emits"},
		{"plugin_manifest/invalid_unknown_field.yaml", "random_unknown_top_level_field"},
		{"plugin_manifest/invalid_wrong_schema_version.yaml", "schema_version"},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			data := readTestdata(t, tc.file)
			_, err := LoadPluginManifest(data)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q; want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestLoadPluginManifest_EmptyInput(t *testing.T) {
	if _, err := LoadPluginManifest(nil); err == nil {
		t.Error("expected error on nil input")
	}
}
