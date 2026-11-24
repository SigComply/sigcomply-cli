package cmd

// Harness for the live E2E tier (live_e2e_test.go, //go:build live). It
// lives in an untagged file so its own tests (live_e2e_harness_self_test.go)
// run on every push: a harness that only ever runs against real clouds
// would otherwise be first exercised by a release.
//
// Output hygiene: this repo and its Actions logs are public, and the
// CLI's own output names resources (ARNs, account and project IDs,
// e-mails). The child's stdout and stderr go to files in the test's temp
// directory and are never printed. Every problem the harness reports is
// built only from values parsed out of that output or the vault: policy
// IDs, statuses, source IDs, exit codes, file paths inside the run folder
// and the counts line.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/report"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
	_ "github.com/sigcomply/sigcomply-cli/internal/vault/builtin" // every vault backend, for the read-back
)

const (
	liveRequiredEnv = "LIVE_E2E_REQUIRED"
	liveBinaryEnv   = "SIGCOMPLY_E2E_BINARY"
	liveCheckLimit  = 30 * time.Minute
	liveKeyBackend  = "backend"
)

// liveFrameworks are run once each against the same sources and vault.
var liveFrameworks = []string{defaultFW, isoFW}

// liveSource is one configured source: its ID and its config keys.
type liveSource struct {
	id  string
	cfg map[string]string
}

// liveProvider is what one TestLiveE2E_* runs.
type liveProvider struct {
	// required are the variables without which the test skips (or fails
	// under LIVE_E2E_REQUIRED=1).
	required []string
	// sources builds the committed sources from the required variables.
	sources func(env map[string]string) []liveSource
	// extras adds env-gated sources when their variables are set.
	extras func() []liveSource
	// vault builds the vault backend config for a run prefix; nil means
	// a local vault in the test's temp directory.
	vault func(env map[string]string, prefix string) spec.VaultConfig
}

func sameConfig(ids []string, cfg map[string]string) []liveSource {
	out := make([]liveSource, 0, len(ids))
	for _, id := range ids {
		out = append(out, liveSource{id, cfg})
	}
	return out
}

// liveRequireEnv returns the named variables, or skips the test when one
// is unset; under LIVE_E2E_REQUIRED=1 it fails instead, so a release is
// never promoted on a silent skip.
func liveRequireEnv(t *testing.T, keys ...string) map[string]string {
	t.Helper()
	vals := map[string]string{}
	var missing []string
	for _, k := range keys {
		v := os.Getenv(k)
		if v == "" {
			missing = append(missing, k)
			continue
		}
		vals[k] = v
	}
	if len(missing) > 0 {
		if os.Getenv(liveRequiredEnv) == "1" {
			t.Fatalf("live E2E: %s=1 but %s unset", liveRequiredEnv, strings.Join(missing, ", "))
		}
		t.Skipf("live E2E: requires env %s; skipping", strings.Join(missing, ", "))
	}
	return vals
}

// liveBinary returns the binary under test: SIGCOMPLY_E2E_BINARY when set,
// otherwise one built from this checkout. LIVE_E2E_REQUIRED=1 refuses the
// fallback: a release run must test the published asset, not the source.
func liveBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv(liveBinaryEnv); p != "" {
		info, err := os.Stat(p) //nolint:gosec // #nosec G703 -- the operator names the binary to test
		if err != nil || info.IsDir() {
			t.Fatalf("live E2E: %s does not name a file", liveBinaryEnv)
		}
		return p
	}
	if os.Getenv(liveRequiredEnv) == "1" {
		t.Fatalf("live E2E: %s=1 but %s is unset", liveRequiredEnv, liveBinaryEnv)
	}
	return sigcomplyBinary(t)
}

// liveRun is one `sigcomply` invocation: its exit code and the files its
// output went to.
type liveRun struct {
	code           int
	stdout, stderr string
}

func readLiveFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name) //nolint:gosec // #nosec G304 -- the test's own output file
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// runLiveBinary runs bin in dir with the test's own environment (the
// job's cloud credentials), its output in <name>.stdout and .stderr.
func runLiveBinary(t *testing.T, bin, dir, name string, args ...string) liveRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), liveCheckLimit)
	defer cancel()
	r := liveRun{stdout: filepath.Join(dir, name+".stdout"), stderr: filepath.Join(dir, name+".stderr")}
	stdout, err := os.Create(r.stdout)
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close() //nolint:errcheck // test output file
	stderr, err := os.Create(r.stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()                          //nolint:errcheck // test output file
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // #nosec G204 -- the binary under test
	cmd.Dir = dir
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("live E2E: %s did not run (context: %v)", name, ctx.Err())
		}
		r.code = exitErr.ExitCode()
	}
	return r
}

func runLiveE2E(t *testing.T, p liveProvider) {
	t.Helper()
	env := liveRequireEnv(t, p.required...)
	bin := liveBinary(t)
	srcs := p.sources(env)
	if p.extras != nil {
		srcs = append(srcs, p.extras()...)
	}

	dir := t.TempDir()
	// check refuses to plan the manual policies without a manual source.
	// An empty local folder makes each of them fail on missing evidence
	// (exit 1), which this tier accepts: manual evidence is covered by the
	// binary E2E tests and the E2E repos.
	manual := filepath.Join(dir, "evidence")
	if err := os.MkdirAll(manual, 0o750); err != nil {
		t.Fatal(err)
	}
	srcs = append(srcs, liveSource{manualSourceID, map[string]string{liveKeyBackend: backendLocal, pathKey: manual}})
	var vcfg spec.VaultConfig
	if p.vault != nil {
		vcfg = p.vault(env, liveRunPrefix(t))
	} else {
		vcfg = spec.VaultConfig{Backend: backendLocal, Config: map[string]any{pathKey: filepath.Join(dir, "vault")}}
	}

	unbound := map[string][]string{}
	for _, fw := range liveFrameworks {
		t.Run(fw, func(t *testing.T) {
			config := filepath.Join(dir, fw+".sigcomply.yaml")
			writeLiveConfig(t, config, fw, srcs, vcfg)
			res := runLiveBinary(t, bin, dir, "check-"+fw, "check", "--config", config, "--no-cloud")
			unbound[fw] = unboundSources(readLiveFile(t, res.stderr))
			for _, problem := range verifyLiveRun(t, bin, dir, fw, config, &vcfg, res) {
				t.Error(problem)
			}
		})
	}
	if never := neverConsulted(unbound, len(liveFrameworks)); len(never) > 0 {
		t.Errorf("configured sources no policy of %v consulted (unbound-source): %v", liveFrameworks, never)
	}
}

// liveRunPrefix is a vault prefix unique to this run, so the read-back sees
// only this run's files. The bucket's lifecycle rule deletes it later.
func liveRunPrefix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "live-e2e/" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}

func writeLiveConfig(t *testing.T, file, framework string, srcs []liveSource, v spec.VaultConfig) {
	t.Helper()
	var b strings.Builder
	b.WriteString("schema_version: project.v1\nframework: " + framework + "\n")
	b.WriteString("vault:\n  backend: " + v.Backend + "\n")
	vc := make(map[string]string, len(v.Config))
	for k, val := range v.Config {
		vc[k] = fmt.Sprint(val)
	}
	writeLiveMap(&b, "  ", vc)
	b.WriteString("sources:\n")
	for _, s := range srcs {
		b.WriteString("  " + s.id + ":\n")
		writeLiveMap(&b, "    ", s.cfg)
	}
	if err := os.WriteFile(file, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeLiveMap writes m as YAML, keys sorted, every value quoted (a JSON
// string is a valid YAML scalar).
func writeLiveMap(b *strings.Builder, indent string, m map[string]string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		q, _ := json.Marshal(m[k]) //nolint:errcheck // a string always marshals
		b.WriteString(indent + k + ": " + string(q) + "\n")
	}
}

var (
	liveCountsLine     = regexp.MustCompile(`(?m)^\s+pass=\d+ fail=\d+ carried=\d+ skip=\d+ error=(\d+) na=\d+ waived=\d+$`)
	liveUnboundWarning = regexp.MustCompile(`unbound-source: ([A-Za-z0-9_.\[\]-]+) is configured`)
)

// unboundSources returns the source IDs check warned no policy consulted.
func unboundSources(stderr string) []string {
	matches := liveUnboundWarning.FindAllStringSubmatch(stderr, -1)
	ids := make([]string, 0, len(matches))
	for _, m := range matches {
		ids = append(ids, m[1])
	}
	return ids
}

// neverConsulted returns the sources every one of the runs reported
// unbound: a source no policy of any framework reads is configured for
// nothing (a renamed source or a lost evidence type).
func neverConsulted(unboundByRun map[string][]string, runs int) []string {
	n := map[string]int{}
	for _, ids := range unboundByRun {
		for _, id := range ids {
			n[id]++
		}
	}
	var out []string
	for id, c := range n {
		if c == runs {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// checkOutcomeProblems judges check's exit code and counts line. errored
// lists the policies the vault holds in error, for the message.
func checkOutcomeProblems(code int, stdout string, errored []string) []string {
	var problems []string
	detail := "no policy result in error"
	if len(errored) > 0 {
		detail = "policies in error: " + strings.Join(errored, ", ")
	}
	m := liveCountsLine.FindStringSubmatch(stdout)
	counts := ""
	if m != nil {
		counts = strings.TrimSpace(m[0])
	}
	if code != 0 && code != 1 {
		problems = append(problems, fmt.Sprintf("check exit code = %d; want 0 or 1. counts: %q; %s", code, counts, detail))
	}
	switch {
	case m == nil:
		problems = append(problems, fmt.Sprintf("check printed no counts line (exit %d)", code))
	case m[1] != "0":
		problems = append(problems, fmt.Sprintf("check reported policies in error: %q; %s", counts, detail))
	}
	return problems
}

// verifyLiveRun asserts one check run: its exit code and counts, then
// reads its run folder back from the vault and verifies it twice, with
// `sigcomply report --view integrity` and with the signing package.
func verifyLiveRun(t *testing.T, bin, dir, framework, config string, vcfg *spec.VaultConfig, res liveRun) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	v, err := vault.FromConfig(ctx, vcfg)
	if err != nil {
		// The error names the bucket or account; say only which backend.
		t.Fatalf("open the %s vault for read-back: failed", vcfg.Backend)
	}
	period, run, keys, problems := liveRunFolder(ctx, v, framework)
	problems = append(problems, checkOutcomeProblems(res.code, readLiveFile(t, res.stdout), erroredPolicies(ctx, v, keys))...)
	if run == "" {
		return problems
	}
	problems = append(problems, integrityReportProblems(t, bin, dir, framework, config, period)...)
	return append(problems, envelopeProblems(ctx, v, run, keys)...)
}

// liveRunFolder lists the framework's folder and returns the run's period,
// its run folder ({framework}/{period}/run_...) and every key under it.
// The prefix is unique to this test run, so there must be exactly one.
func liveRunFolder(ctx context.Context, v core.Vault, framework string) (period, run string, keys, problems []string) {
	all, err := v.List(ctx, framework+"/")
	if err != nil {
		return "", "", nil, []string{"list the vault: failed"}
	}
	runs := map[string]string{}
	for _, k := range all {
		parts := strings.SplitN(k, "/", 4)
		if len(parts) == 4 && strings.HasPrefix(parts[2], "run_") {
			runs[path.Join(parts[0], parts[1], parts[2])] = parts[1]
		}
	}
	if len(runs) != 1 {
		return "", "", nil, []string{fmt.Sprintf("found %d run folders under %s/ in the vault; want 1", len(runs), framework)}
	}
	for r, p := range runs {
		run, period = r, p
	}
	for _, k := range all {
		if strings.HasPrefix(k, run+"/") {
			keys = append(keys, k)
		}
	}
	return period, run, keys, nil
}

// erroredPolicies returns the IDs of the policies whose result.json says
// error. The reason text is not returned: it names resources.
func erroredPolicies(ctx context.Context, v core.Vault, keys []string) []string {
	var out []string
	for _, k := range keys {
		if !strings.HasSuffix(k, "/result.json") {
			continue
		}
		data, err := v.GetBinary(ctx, k)
		if err != nil {
			out = append(out, path.Base(path.Dir(k))+" (result unreadable)")
			continue
		}
		var pr core.PolicyResult
		if json.Unmarshal(data, &pr) == nil && pr.Status == core.StatusError {
			out = append(out, pr.PolicyID)
		}
	}
	sort.Strings(out)
	return out
}

// integrityReportProblems runs the auditor's integrity view against the
// vault: it downloads the manifest and checks its signature and every
// file hash.
func integrityReportProblems(t *testing.T, bin, dir, framework, config, period string) []string {
	t.Helper()
	out := filepath.Join(dir, "integrity-"+framework+".json")
	res := runLiveBinary(t, bin, dir, "report-"+framework, "report", "--config", config,
		"--period", period, "--view", "integrity", "--format", "json", "--out", out)
	// Exit 1 means a run failed verification; the snapshot says which file.
	if res.code != 0 && res.code != 1 {
		return []string{fmt.Sprintf("report --view integrity exit code = %d; want 0", res.code)}
	}
	var snap report.Snapshot
	if err := json.Unmarshal([]byte(readLiveFile(t, out)), &snap); err != nil {
		return []string{"the integrity report is not a JSON snapshot"}
	}
	if snap.Integrity == nil || len(snap.Integrity.Runs) != 1 {
		n := 0
		if snap.Integrity != nil {
			n = len(snap.Integrity.Runs)
		}
		return []string{fmt.Sprintf("the integrity report lists %d runs; want 1", n)}
	}
	row := snap.Integrity.Runs[0]
	if res.code != 0 || !row.SignatureValid || row.FilesTotal == 0 || row.FilesVerified != row.FilesTotal {
		return []string{fmt.Sprintf("integrity: report exit %d, manifest signature valid=%v, files verified %d of %d, first mismatch %q",
			res.code, row.SignatureValid, row.FilesVerified, row.FilesTotal, row.FirstMismatchPath)}
	}
	return nil
}

// envelopeProblems downloads every envelope in the run folder and
// verifies its signature: the report checks the manifest's file hashes,
// this checks each file's own signature, as an auditor's verifier does.
func envelopeProblems(ctx context.Context, v core.Vault, run string, keys []string) []string {
	var problems []string
	envelopes := 0
	for _, k := range keys {
		if !strings.Contains(k, "/envelopes/") {
			continue
		}
		envelopes++
		rel := strings.TrimPrefix(k, run+"/")
		data, err := v.GetBinary(ctx, k)
		if err != nil {
			problems = append(problems, "download envelope "+rel+": failed")
			continue
		}
		var env core.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			problems = append(problems, "envelope "+rel+" is not JSON")
			continue
		}
		if err := sign.VerifyEnvelope(&env); err != nil {
			problems = append(problems, "envelope "+rel+" does not verify")
		}
	}
	if envelopes == 0 {
		problems = append(problems, "the run folder holds no envelopes")
	}
	return problems
}
