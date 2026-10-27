package s3

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// A quoted "true" used to be read as false with no warning, so an on-prem
// S3 store silently fell back to virtual-host addressing.
func TestForcePathStyle_AcceptsBoolOrBoolString(t *testing.T) {
	cases := []struct {
		name    string
		raw     any
		want    bool
		wantErr bool
	}{
		{"absent", nil, false, false},
		{"bool true", true, true, false},
		{"bool false", false, false, false},
		{"quoted true", "true", true, false},
		{"quoted false", "false", false, false},
		{"other string", "yes", false, true},
		{"number", 1, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &spec.VaultConfig{Config: map[string]any{}}
			if tc.raw != nil {
				cfg.Config["force_path_style"] = tc.raw
			}
			got, err := forcePathStyle(cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
