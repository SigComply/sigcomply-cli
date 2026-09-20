package planner

import (
	"context"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// The planner package does not import sources/builtin, so no real
// factory is registered here. These stand in for one, with the same
// shape: a declared key list, registered from init().
const (
	testSrcAWSish   = "test.awsish"
	testSrcAzureish = "test.azureish"
	testSrcGCPish   = "test.gcpish"
	testSrcSilent   = "test.silent"

	testKeyRoleARN   = "role_arn"
	testKeyProjectID = "project_id"
)

// stand in for the real factories the planner package does not import.
//
//nolint:gochecknoinits // registration is init-time by contract; these
func init() {
	noopBuild := func(context.Context, sources.Env) (core.SourcePlugin, error) { return nil, nil }
	sources.RegisterFactory(testSrcAWSish, noopBuild, paramRegion, testKeyRoleARN, "external_id", "role_session_name")
	sources.RegisterFactory(testSrcAzureish, noopBuild, "subscription_id", "tenant_id")
	sources.RegisterFactory(testSrcGCPish, noopBuild, testKeyProjectID)
	// Declares nothing: the fail-open case.
	sources.RegisterFactory(testSrcSilent, noopBuild)
}

func sourcesCfg(bags map[string]map[string]any) *spec.ProjectConfig {
	return &spec.ProjectConfig{Framework: "soc2", Sources: bags}
}

func TestSourceConfigWarnings_SilentOnACleanConfig(t *testing.T) {
	cfg := sourcesCfg(map[string]map[string]any{
		testSrcAWSish: {paramRegion: regionUSEast1},
	})
	if got := SourceConfigWarnings(cfg); got != nil {
		t.Errorf("warnings = %v; want none", got)
	}
}

// The case the loader cannot catch: KnownFields(true) stops at the
// source key because the inner bag is map[string]any.
func TestSourceConfigWarnings_NamesAnUnrecognizedKey(t *testing.T) {
	cfg := sourcesCfg(map[string]map[string]any{
		testSrcAWSish: {paramRegion: regionUSEast1, "role_am": "arn:aws:iam::1:role/x"},
	})
	got := strings.Join(SourceConfigWarnings(cfg), "\n")

	if !strings.Contains(got, `unrecognized key "role_am"`) {
		t.Errorf("warnings = %q; want the typo named", got)
	}
	// The correct keys are listed, so the operator can see the near-miss.
	if !strings.Contains(got, testKeyRoleARN) {
		t.Errorf("warnings = %q; want the accepted keys listed", got)
	}
	if strings.Contains(got, `"region"`) {
		t.Errorf("warnings = %q; must not warn about a key the source reads", got)
	}
}

// A key on the wrong source: role_arn is real, but azure.* never reads it.
func TestSourceConfigWarnings_NamesAKeyFromAnotherVendor(t *testing.T) {
	cfg := sourcesCfg(map[string]map[string]any{
		testSrcAzureish: {"subscription_id": "sub-1", testKeyRoleARN: "arn:aws:iam::1:role/x"},
	})
	if got := strings.Join(SourceConfigWarnings(cfg), "\n"); !strings.Contains(got, `unrecognized key "role_arn"`) {
		t.Errorf("warnings = %q; want role_arn flagged on an Azure source", got)
	}
}

// The second half, and the one a key list alone would miss: StringOpt
// returns "" for a wrong-typed value exactly as it does for a missing
// one, so an unquoted YAML integer reads as unset.
func TestSourceConfigWarnings_NamesAWrongTypedValue(t *testing.T) {
	cfg := sourcesCfg(map[string]map[string]any{
		testSrcGCPish: {testKeyProjectID: 12345},
	})
	got := strings.Join(SourceConfigWarnings(cfg), "\n")

	if !strings.Contains(got, "not a string") || !strings.Contains(got, "reads as unset") {
		t.Errorf("warnings = %q; want the type mismatch explained", got)
	}
	if !strings.Contains(got, testKeyProjectID+`: "12345"`) {
		t.Errorf("warnings = %q; want the quoted form suggested", got)
	}
}

// An instance key carries a suffix; the factory, and so the key list, is
// registered under the base ID.
func TestSourceConfigWarnings_ResolvesInstanceKeysToTheirBase(t *testing.T) {
	cfg := sourcesCfg(map[string]map[string]any{
		testSrcAWSish + "[prod]": {"region": regionUSEast1, "nonsense": "x"},
	})
	if got := strings.Join(SourceConfigWarnings(cfg), "\n"); !strings.Contains(got, `unrecognized key "nonsense"`) {
		t.Errorf("warnings = %q; want an instance key resolved to its base", got)
	}
}

// Fail-open: a source that declared no keys is never warned about, so a
// project-local plugin keeps working without knowing this exists.
func TestSourceConfigWarnings_SilentForAnUndeclaredSource(t *testing.T) {
	cfg := sourcesCfg(map[string]map[string]any{
		testSrcSilent: {"anything": "goes"},
	})
	if got := SourceConfigWarnings(cfg); got != nil {
		t.Errorf("warnings = %v; want none for a source that declared no keys", got)
	}
}
