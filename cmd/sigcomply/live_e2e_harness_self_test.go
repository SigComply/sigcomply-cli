package cmd

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
)

// Self-tests of the live E2E harness (live_e2e_harness_test.go). The live
// tests only run against real accounts, so without these the harness's
// parsing and read-back would first run inside a release.

const harnessTokenEnv = "LIVE_E2E_HARNESS_GITHUB_TOKEN"

// harnessProvider is a live provider made hermetic: the GitHub source
// replays its committed cassette from a local server, and the vault is a
// local folder under a per-run prefix, as a cloud bucket would be.
func harnessProvider(t *testing.T) liveProvider {
	t.Helper()
	fg := newFakeGitHub(t)
	root := t.TempDir()
	return liveProvider{
		sources: func(map[string]string) []liveSource {
			return sameConfig([]string{"github"}, map[string]string{
				"org": githubCassetteOrg, "base_url": fg.srv.URL, "token_env": harnessTokenEnv,
			})
		},
		vault: func(_ map[string]string, prefix string) spec.VaultConfig {
			return spec.VaultConfig{Backend: backendLocal, Config: map[string]any{pathKey: filepath.Join(root, filepath.FromSlash(prefix))}}
		},
	}
}

// TestLiveE2EHarness_PassesARealRun runs the whole harness, both
// frameworks, against the built binary: the counts line parses, the run
// folder is found by listing the vault, the integrity report and every
// envelope verify.
func TestLiveE2EHarness_PassesARealRun(t *testing.T) {
	t.Setenv(harnessTokenEnv, "dummy-token")
	t.Setenv(liveRequiredEnv, "")
	t.Setenv(liveBinaryEnv, "")
	runLiveE2E(t, harnessProvider(t))
}

// One run, checked again after each kind of damage: the harness must
// report it, by path and policy ID only.
func TestLiveE2EHarness_ReportsDamage(t *testing.T) {
	t.Setenv(harnessTokenEnv, "dummy-token")
	p := harnessProvider(t)
	bin := sigcomplyBinary(t)
	dir := t.TempDir()
	vcfg := p.vault(nil, liveRunPrefix(t))
	manual := filepath.Join(dir, "evidence")
	if err := os.MkdirAll(manual, 0o750); err != nil {
		t.Fatal(err)
	}
	srcs := append(p.sources(nil), liveSource{manualSourceID, map[string]string{liveKeyBackend: backendLocal, pathKey: manual}})
	config := filepath.Join(dir, defaultFW+".sigcomply.yaml")
	writeLiveConfig(t, config, defaultFW, srcs, vcfg)
	res := runLiveBinary(t, bin, dir, "check-soc2", "check", "--config", config, "--no-cloud")

	if got := verifyLiveRun(t, bin, dir, defaultFW, config, &vcfg, res); len(got) != 0 {
		t.Fatalf("an undamaged run reported problems: %q", got)
	}

	ctx := context.Background()
	v, err := vault.FromConfig(ctx, &vcfg)
	if err != nil {
		t.Fatal(err)
	}
	_, run, keys, _ := liveRunFolder(ctx, v, defaultFW)
	var envelope string
	for _, k := range keys {
		if strings.Contains(k, "/envelopes/") {
			envelope = k
			break
		}
	}
	if envelope == "" {
		t.Fatal("the run wrote no envelope to tamper with")
	}
	file := filepath.Join(vcfg.Str(pathKey), filepath.FromSlash(envelope))
	body, err := os.ReadFile(file) //nolint:gosec // #nosec G304 -- the test's own vault
	if err != nil {
		t.Fatal(err)
	}
	// Still valid JSON, but a signed field changed.
	tampered := strings.Replace(string(body), `"source_id":"`, `"source_id":"x`, 1)
	if tampered == string(body) {
		t.Fatal("envelope has no source_id to tamper with")
	}
	if err := os.WriteFile(file, []byte(tampered), 0o600); err != nil { //nolint:gosec // #nosec G703 -- a path inside the test's own vault
		t.Fatal(err)
	}

	got := verifyLiveRun(t, bin, dir, defaultFW, config, &vcfg, res)
	rel := strings.TrimPrefix(envelope, run+"/")
	if !slices.Contains(got, "envelope "+rel+" does not verify") {
		t.Errorf("tampered envelope: problems %q; want one naming %s", got, rel)
	}
	if !slices.ContainsFunc(got, func(p string) bool { return strings.HasPrefix(p, "integrity: ") }) {
		t.Errorf("tampered envelope: problems %q; want the integrity report to flag the hash", got)
	}
}

func TestLiveE2EHarness_CheckOutcomeProblems(t *testing.T) {
	const clean = "SigComply check soc2/2026-Q4 — 3 policies\n  pass=1 fail=1 carried=0 skip=1 error=0 na=0 waived=0\n"
	const errored = "  pass=1 fail=0 carried=0 skip=0 error=2 na=0 waived=0\n"
	for _, tc := range []struct {
		name    string
		code    int
		stdout  string
		failing []string
		want    []string
	}{
		{name: "pass", code: 0, stdout: clean},
		{name: "violations", code: 1, stdout: clean},
		{name: "execution error", code: 2, stdout: errored, failing: []string{"soc2.a", "soc2.b"}, want: []string{
			`check exit code = 2; want 0 or 1. counts: "pass=1 fail=0 carried=0 skip=0 error=2 na=0 waived=0"; policies in error: soc2.a, soc2.b`,
			`check reported policies in error: "pass=1 fail=0 carried=0 skip=0 error=2 na=0 waived=0"; policies in error: soc2.a, soc2.b`,
		}},
		{name: "config error prints no counts", code: 3, stdout: "", want: []string{
			`check exit code = 3; want 0 or 1. counts: ""; no policy result in error`,
			`check printed no counts line (exit 3)`,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkOutcomeProblems(tc.code, tc.stdout, tc.failing); !slices.Equal(got, tc.want) {
				t.Errorf("problems = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestLiveE2EHarness_NeverConsulted(t *testing.T) {
	stderr := "WARN unbound-source: aws.inspector is configured but no policy slot accepts what it emits, so it was never consulted\n" +
		"WARN unbound-source: gcp.scc is configured but no policy slot accepts what it emits, so it was never consulted\n"
	byRun := map[string][]string{
		defaultFW: unboundSources(stderr),
		isoFW:     unboundSources("WARN unbound-source: gcp.scc is configured but no policy slot accepts what it emits\n"),
	}
	if got := neverConsulted(byRun, 2); !slices.Equal(got, []string{"gcp.scc"}) {
		t.Errorf("neverConsulted = %q; want only the source unbound in both frameworks", got)
	}
}

func TestLiveE2EHarness_UnsetVariableSkips(t *testing.T) {
	const name = "LIVE_E2E_HARNESS_UNSET_VARIABLE"
	t.Setenv(name, "")
	t.Setenv(liveRequiredEnv, "")
	skipped := false
	t.Run("optional", func(t *testing.T) {
		defer func() { skipped = t.Skipped() }()
		liveRequireEnv(t, name)
	})
	if !skipped {
		t.Error("an unset variable without LIVE_E2E_REQUIRED did not skip")
	}
}
