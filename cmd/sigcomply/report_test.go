package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
	"github.com/sigcomply/sigcomply-cli/internal/vault/local"
)

// seedFixtureVault writes a tiny vault containing one signed run with
// one passing policy. Returns the vault root path so callers can pass
// it to --vault. The framework / period_id are SOC 2 / 2026-Q1 to
// keep the test surface small.
func seedFixtureVault(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	v := local.New(tmp)
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	ctx := context.Background()

	const runRoot = "soc2/2026-Q1/run_20260215T140000Z_aaaaaaaa"
	result := core.PolicyResult{
		PolicyID: "soc2.cc6.1.mfa", ControlID: "SOC2.CC6.1",
		Status: core.StatusPass, Severity: core.SeverityHigh, Category: "access",
	}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := v.PutBinary(ctx, runRoot+"/policies/soc2.cc6.1.mfa/result.json", body, nil); err != nil {
		t.Fatalf("write result: %v", err)
	}

	when := time.Date(2026, 2, 15, 14, 0, 0, 0, time.UTC)
	h := sha256.Sum256(body)
	manifest := &core.Manifest{
		SchemaVersion: "run.v1", RunID: "aaaaaaaa-1111", Framework: "soc2", PeriodID: "2026-Q1",
		StartedAt: when, CompletedAt: when,
		FileHashes: map[string]string{
			"policies/soc2.cc6.1.mfa/result.json": "sha256:" + hex.EncodeToString(h[:]),
		},
	}
	if err := sign.Manifest(manifest); err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	if err := v.PutJSON(ctx, runRoot+"/manifest.json", manifest); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return tmp
}

// writeReportConfig writes a minimal .sigcomply.yaml pointing at the
// given vault path. The CLI command parses this to discover the
// vault's backend + path when --vault isn't passed.
func writeReportConfig(t *testing.T, vaultPath string) string {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	body := `schema_version: project.v1
framework: soc2
vault:
  backend: local
  path: ` + vaultPath + `
`
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return configPath
}

func TestRunReport_RequiresPeriod(t *testing.T) {
	err := runReport(context.Background(), &bytes.Buffer{}, &reportFlags{})
	if err == nil {
		t.Fatal("want error on missing --period")
	}
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != 3 {
		t.Errorf("want exitCodeError{code:3}; got %v", err)
	}
	if !strings.Contains(err.Error(), "--period") {
		t.Errorf("error should mention --period: %v", err)
	}
}

func TestRunReport_PDFFormatDeferred(t *testing.T) {
	err := runReport(context.Background(), &bytes.Buffer{}, &reportFlags{
		period: "2026-Q1", format: "pdf",
	})
	if err == nil {
		t.Fatal("want PDF-deferred error")
	}
	if !strings.Contains(err.Error(), "PDF format deferred") {
		t.Errorf("error should mention deferred PDF; got %v", err)
	}
}

func TestRunReport_InvalidView(t *testing.T) {
	vaultPath := seedFixtureVault(t)
	configPath := writeReportConfig(t, vaultPath)
	err := runReport(context.Background(), &bytes.Buffer{}, &reportFlags{
		config: configPath, period: "2026-Q1", view: "drift", format: "text",
	})
	if err == nil {
		t.Fatal("want error on bad --view")
	}
	if !strings.Contains(err.Error(), "drift") {
		t.Errorf("err should name the bad view; got %v", err)
	}
}

func TestRunReport_InvalidFormat(t *testing.T) {
	vaultPath := seedFixtureVault(t)
	configPath := writeReportConfig(t, vaultPath)
	err := runReport(context.Background(), &bytes.Buffer{}, &reportFlags{
		config: configPath, period: "2026-Q1", format: "yaml",
		out: filepath.Join(t.TempDir(), "out.yaml"),
	})
	if err == nil {
		t.Fatal("want error on bad --format")
	}
	if !strings.Contains(err.Error(), "yaml") {
		t.Errorf("err should name the bad format; got %v", err)
	}
}

func TestRunReport_NonTextRequiresOut(t *testing.T) {
	vaultPath := seedFixtureVault(t)
	configPath := writeReportConfig(t, vaultPath)
	err := runReport(context.Background(), &bytes.Buffer{}, &reportFlags{
		config: configPath, period: "2026-Q1", format: "json",
	})
	if err == nil {
		t.Fatal("want --out required error for json format")
	}
	if !strings.Contains(err.Error(), "--out is required") {
		t.Errorf("err should mention --out; got %v", err)
	}
}

func TestRunReport_LatestTextE2E(t *testing.T) {
	vaultPath := seedFixtureVault(t)
	configPath := writeReportConfig(t, vaultPath)
	var stdout bytes.Buffer
	err := runReport(context.Background(), &stdout, &reportFlags{
		config: configPath, period: "2026-Q1", view: "latest", format: "text",
	})
	if err != nil {
		t.Fatalf("runReport: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "soc2.cc6.1.mfa") {
		t.Errorf("text output missing policy_id: %q", out)
	}
	if !strings.Contains(out, "pass") {
		t.Errorf("text output missing status: %q", out)
	}
}

func TestRunReport_JSONToFile(t *testing.T) {
	vaultPath := seedFixtureVault(t)
	configPath := writeReportConfig(t, vaultPath)
	outPath := filepath.Join(t.TempDir(), "out.json")
	err := runReport(context.Background(), &bytes.Buffer{}, &reportFlags{
		config: configPath, period: "2026-Q1", view: "latest", format: "json", out: outPath,
	})
	if err != nil {
		t.Fatalf("runReport: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if !json.Valid(data) {
		t.Errorf("out file is not valid JSON: %q", data)
	}
	if !strings.Contains(string(data), "soc2.cc6.1.mfa") {
		t.Errorf("JSON missing policy_id: %q", data)
	}
}

func TestRunReport_CSVToFile(t *testing.T) {
	vaultPath := seedFixtureVault(t)
	configPath := writeReportConfig(t, vaultPath)
	outPath := filepath.Join(t.TempDir(), "out.csv")
	err := runReport(context.Background(), &bytes.Buffer{}, &reportFlags{
		config: configPath, period: "2026-Q1", view: "latest", format: "csv", out: outPath,
	})
	if err != nil {
		t.Fatalf("runReport: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if !strings.HasPrefix(string(data), "policy_id,") {
		t.Errorf("CSV missing header: %q", data)
	}
}

func TestRunReport_VaultOverrideFromCLI(t *testing.T) {
	// Provide vault + framework via CLI flags only — no config file.
	vaultPath := seedFixtureVault(t)
	var stdout bytes.Buffer
	err := runReport(context.Background(), &stdout, &reportFlags{
		config:    filepath.Join(t.TempDir(), "does-not-exist.yaml"), // explicitly unused
		vaultURI:  vaultPath,
		framework: "soc2",
		period:    "2026-Q1",
		view:      "integrity",
		format:    "text",
	})
	if err != nil {
		t.Fatalf("runReport: %v", err)
	}
	if !strings.Contains(stdout.String(), "pass") {
		t.Errorf("integrity output missing pass row: %q", stdout.String())
	}
}

func TestRunReport_MissingConfig(t *testing.T) {
	err := runReport(context.Background(), &bytes.Buffer{}, &reportFlags{
		config: filepath.Join(t.TempDir(), "missing.yaml"),
		period: "2026-Q1",
	})
	if err == nil {
		t.Fatal("want error on missing config")
	}
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != 3 {
		t.Errorf("want exitCodeError code=3; got %v", err)
	}
}

func TestVaultConfigFromURI(t *testing.T) {
	cases := []struct {
		in      string
		backend string
		bucket  string
		prefix  string
		path    string
		account string
		cont    string
		wantErr bool
	}{
		{in: "/var/sigcomply/vault", backend: "local", path: "/var/sigcomply/vault"},
		{in: "file:///tmp/v", backend: "local", path: "/tmp/v"},
		{in: "s3://acme-evidence/sigcomply", backend: "s3", bucket: "acme-evidence", prefix: "sigcomply"},
		{in: "s3://only-bucket", backend: "s3", bucket: "only-bucket"},
		{in: "gs://acme/p1/p2", backend: "gcs", bucket: "acme", prefix: "p1/p2"},
		{in: "az://account/container/prefix", backend: "azure_blob", account: "account", cont: "container", prefix: "prefix"},
		{in: "az://account/container", backend: "azure_blob", account: "account", cont: "container"},
		{in: "az://incomplete", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := vaultConfigFromURI(c.in)
			if c.wantErr {
				if err == nil {
					t.Error("want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Backend != c.backend {
				t.Errorf("Backend = %q; want %q", got.Backend, c.backend)
			}
			if got.Bucket != c.bucket {
				t.Errorf("Bucket = %q; want %q", got.Bucket, c.bucket)
			}
			if got.Prefix != c.prefix {
				t.Errorf("Prefix = %q; want %q", got.Prefix, c.prefix)
			}
			if got.Path != c.path {
				t.Errorf("Path = %q; want %q", got.Path, c.path)
			}
			if got.Account != c.account {
				t.Errorf("Account = %q; want %q", got.Account, c.account)
			}
			if got.Container != c.cont {
				t.Errorf("Container = %q; want %q", got.Container, c.cont)
			}
		})
	}
}

func TestParseView(t *testing.T) {
	if v, err := parseView(""); err != nil || v != "latest" {
		t.Errorf("empty → %q err=%v; want latest", v, err)
	}
	if v, err := parseView("latest"); err != nil || v != "latest" {
		t.Errorf("latest → %q err=%v", v, err)
	}
	if v, err := parseView("exceptions"); err != nil || v != "exceptions" {
		t.Errorf("exceptions → %q err=%v", v, err)
	}
	if v, err := parseView("integrity"); err != nil || v != "integrity" {
		t.Errorf("integrity → %q err=%v", v, err)
	}
	if _, err := parseView("drift"); err == nil {
		t.Error("drift → nil err; want error")
	}
}

func TestNewReportCmd_FlagsRegistered(t *testing.T) {
	cmd := newReportCmd()
	for _, want := range []string{"config", "vault", "framework", "period", "view", "format", "out"} {
		if cmd.Flags().Lookup(want) == nil {
			t.Errorf("flag --%s not registered", want)
		}
	}
}
