package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	s3Backend        = "s3"
	azureBlobBackend = "azure_blob"
	pathKey          = "path"
	bucketKey        = "bucket"
	accountKey       = "account"
	containerKey     = "container"
	uxBucketName     = "audit-bucket"
	uxRegionEU       = "eu-central-1"
)

// An invalid --format is refused before the out file is opened, so an
// existing report is never truncated by a typo.
func TestRunReport_InvalidFormatLeavesOutFileUntouched(t *testing.T) {
	vaultPath := seedFixtureVault(t)
	configPath := writeReportConfig(t, vaultPath)
	out := filepath.Join(t.TempDir(), "keep.txt")
	if err := os.WriteFile(out, []byte("previous report"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runReport(context.Background(), &bytes.Buffer{}, &reportFlags{
		config: configPath, period: testPeriodID, format: formatYAML, out: out,
	})
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != 3 {
		t.Fatalf("want exit 3; got %v", err)
	}
	got, readErr := os.ReadFile(out)
	if readErr != nil || string(got) != "previous report" {
		t.Errorf("out file was modified to %q (err %v)", got, readErr)
	}
}

// `check` prints "<framework>/<period>"; pasting that into --period
// must work, not silently match nothing.
func TestRunReport_AcceptsFrameworkQualifiedPeriod(t *testing.T) {
	vaultPath := seedFixtureVault(t)
	var stdout bytes.Buffer
	err := runReport(context.Background(), &stdout, &reportFlags{
		vaultURI: vaultPath, framework: defaultFW, period: defaultFW + "/" + testPeriodID,
		view: viewLatest, format: outputText,
	})
	if err != nil {
		t.Fatalf("runReport: %v", err)
	}
	if !strings.Contains(stdout.String(), "soc2.cc6.1.mfa") {
		t.Errorf("framework-qualified period found nothing: %q", stdout.String())
	}
}

func TestRunReport_RejectsOtherFrameworkQualifiedPeriod(t *testing.T) {
	vaultPath := seedFixtureVault(t)
	err := runReport(context.Background(), &bytes.Buffer{}, &reportFlags{
		vaultURI: vaultPath, framework: defaultFW, period: "iso27001/" + testPeriodID,
		view: viewLatest, format: outputText,
	})
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != 3 {
		t.Fatalf("want exit 3; got %v", err)
	}
}

// A period with no runs must not pass vacuously: an integrity gate
// scripted against a typo'd period would otherwise exit 0.
func TestRunReport_EmptyPeriodIsAnError(t *testing.T) {
	vaultPath := seedFixtureVault(t)
	for _, view := range []string{viewIntegrity, viewLatest} {
		var stdout bytes.Buffer
		err := runReport(context.Background(), &stdout, &reportFlags{
			vaultURI: vaultPath, framework: defaultFW, period: "2026-Q9",
			view: view, format: outputText,
		})
		var ec *exitCodeError
		if !errors.As(err, &ec) || ec.code != 3 {
			t.Fatalf("%s: want exit 3 for a period with no runs; got %v", view, err)
		}
		if !strings.Contains(err.Error(), testPeriodID) {
			t.Errorf("%s: error should list the periods that exist: %v", view, err)
		}
	}
}

// A local vault path that does not exist is a typo, not an empty vault;
// report is read-only and must not create it.
func TestRunReport_MissingLocalVaultIsAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does", "not", "exist")
	err := runReport(context.Background(), &bytes.Buffer{}, &reportFlags{
		vaultURI: missing, framework: defaultFW, period: testPeriodID,
		view: viewIntegrity, format: outputText,
	})
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != 3 {
		t.Fatalf("want exit 3; got %v", err)
	}
	if _, statErr := os.Stat(missing); !os.IsNotExist(statErr) {
		t.Errorf("report created the vault directory (stat err %v)", statErr)
	}
}

// The S3 vault needs a region, and the URI form must be able to carry
// one.
func TestReportVaultS3Region(t *testing.T) {
	got, err := vaultConfigFromURI("s3://" + uxBucketName + "/pre/fix?region=" + uxRegionEU)
	if err != nil {
		t.Fatal(err)
	}
	if got.Backend != s3Backend || got.Str(bucketKey) != uxBucketName || got.Str("prefix") != "pre/fix" || got.Str("region") != uxRegionEU {
		t.Errorf("query region not parsed: %+v", got)
	}
}

// Without ?region=, the region comes from the AWS environment, then the
// project config's S3 vault; with none of them the error says how to
// give one.
func TestReportVaultS3RegionFallback(t *testing.T) {
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	cfgPath := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(cfgPath, []byte("schema_version: project.v1\nframework: soc2\nvault:\n  backend: s3\n  bucket: other\n  region: ap-south-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := &reportFlags{config: cfgPath, configSet: true, vaultURI: "s3://bucket", framework: defaultFW}
	cfg, err := loadReportConfig(flags)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Vault.Str("region") != "ap-south-1" {
		t.Errorf("config region not used as fallback: %+v", cfg.Vault)
	}

	t.Setenv("AWS_REGION", "us-east-2")
	cfg, err = loadReportConfig(flags)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Vault.Str("region") != "us-east-2" {
		t.Errorf("AWS_REGION should win over the config: %+v", cfg.Vault)
	}

	cfg, err = loadReportConfig(&reportFlags{vaultURI: "s3://bucket?region=eu-north-1", framework: defaultFW})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Vault.Str("region") != "eu-north-1" {
		t.Errorf("URI region should win: %+v", cfg.Vault)
	}

	t.Setenv("AWS_REGION", "")
	if _, err := loadReportConfig(&reportFlags{vaultURI: "s3://" + uxBucketName, framework: defaultFW}); err == nil || !strings.Contains(err.Error(), "?region=") {
		t.Errorf("a region-less s3:// URI should say how to give one; got %v", err)
	}
}

func TestReportVaultS3UnknownParameter(t *testing.T) {
	if _, err := vaultConfigFromURI("s3://bucket?colour=red"); err == nil {
		t.Error("unknown query parameter should be rejected")
	}
}
