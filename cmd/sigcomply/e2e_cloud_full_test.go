package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// Full-run payload goldens: the exact counts-only payload an unfiltered
// run of each shipped framework captures, with most manual evidence on
// file and a few entries left empty. The dashboard repo POSTs a
// byte-identical copy of each (cloudFullRailsFixture) and renders every
// page and report from it, so these files are a cross-repo contract like
// internal/aggregator/testdata/cloud_golden.json. Regenerate with
//
//	go test ./cmd/sigcomply/ -run TestBinaryE2E_CloudFullPayloadGoldens -update
//
// then copy both files to the dashboard repo in the same task.

// cloudFullEmpty names the catalog entries each run leaves empty, so the
// payload carries fail rows next to the passes and the skips of
// automated policies with no source configured.
var cloudFullEmpty = map[string][]string{
	defaultFW: {"code_of_conduct_acknowledgment", "security_awareness_training", "incident_response_tested"},
	isoFW:     {"return_of_assets", "access_control_policy", "incident_response_tested"},
}

// Fixed values for the fields that change from run to run. The times are
// valid RFC 3339 instants after the pinned commit time, so the receiver
// can parse and order them as it would a real run's.
var (
	cloudFullStarted   = e2eCommitTime.Add(5 * time.Minute)
	cloudFullCompleted = cloudFullStarted.Add(time.Minute)
	cloudFullNextDue   = cloudFullStarted.Add(24 * time.Hour)
)

const (
	cloudFullRunID      = "20260215T120500Z-e2efull0"
	cloudFullCLIVersion = "1.0.0-e2e"
)

// cloudFullRailsFixture is the dashboard repo's copy of a golden, from
// this package's directory.
func cloudFullRailsFixture(framework string) string {
	return filepath.Join("..", "..", "..", "sigcomply", "spec", "fixtures", "files", "contract", "cloud_full_"+framework+".json")
}

func cloudFullGoldenPath(framework string) string {
	return filepath.Join("testdata", "cloud-full", framework+".json")
}

// githubActionsRunEnv is a GitHub Actions push run with no OIDC token,
// so repository and environment carry what a real run sends while the
// run cannot submit.
func githubActionsRunEnv() []string {
	return []string{
		"CI=true",
		"GITHUB_ACTIONS=true",
		"GITHUB_SERVER_URL=https://github.com",
		"GITHUB_REPOSITORY=acme/infra",
		"GITHUB_WORKFLOW=compliance",
		"GITHUB_RUN_ID=42",
		"GITHUB_REF_NAME=main",
		"GITHUB_EVENT_NAME=push",
	}
}

func TestBinaryE2E_CloudFullPayloadGoldens(t *testing.T) {
	for _, fw := range []string{defaultFW, isoFW} {
		t.Run(fw, func(t *testing.T) {
			got := captureFullRunPayload(t, fw)
			path := cloudFullGoldenPath(fw)
			if *updateE2EGoldens {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path) //nolint:gosec // #nosec G304 -- fixed testdata path
			if err != nil {
				t.Fatalf("%v (generate with -update)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s drifted from the captured payload at %s.\nIf the change is intended, regenerate with -update, read the diff and copy the file to the dashboard repo (%s).",
					path, firstLineDiff(got, want), cloudFullRailsFixture(fw))
			}

			// Cross-repo drift guard, as in TestCloud_GoldenWireContract:
			// skipped when the dashboard repo is not checked out next to
			// this one (CI).
			if rails, err := os.ReadFile(cloudFullRailsFixture(fw)); err == nil && !bytes.Equal(rails, want) {
				t.Errorf("dashboard fixture %s has drifted from %s; copy the CLI golden over it", cloudFullRailsFixture(fw), path)
			}
		})
	}
}

// captureFullRunPayload seeds the framework's manual evidence except the
// entries in cloudFullEmpty, runs an unfiltered check that captures the
// payload, and returns it normalised and pretty-printed.
func captureFullRunPayload(t *testing.T, framework string) []byte {
	t.Helper()
	p := newE2EProjectFor(t, framework, "")
	seedManualEvidenceExcept(t, p, cloudFullEmpty[framework]...)
	capture := filepath.Join(p.dir, "payload.json")
	res := runSigcomply(t, p.dir, githubActionsRunEnv(), checkCmd, "--capture-cloud-payload", capture)
	res.wantCode(t, 1) // the empty entries fail

	var payload core.SubmissionPayload
	readJSON(t, capture, &payload)
	if payload.Framework != framework || payload.PeriodID != e2ePeriod {
		t.Fatalf("captured %s/%s; want %s/%s", payload.Framework, payload.PeriodID, framework, e2ePeriod)
	}
	assertFullRunRows(t, &payload)

	payload.RunID = cloudFullRunID
	payload.StartedAt = cloudFullStarted
	payload.CompletedAt = cloudFullCompleted
	payload.CLIVersion = cloudFullCLIVersion
	for i := range payload.Policies {
		pol := &payload.Policies[i]
		if pol.LastEvaluatedAt != nil {
			at := cloudFullStarted
			pol.LastEvaluatedAt = &at
		}
		if pol.NextDueAt != nil {
			at := cloudFullNextDue
			pol.NextDueAt = &at
		}
	}
	out, err := json.MarshalIndent(&payload, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// assertFullRunRows checks the run is the one the golden means to pin:
// every policy of the framework, with passes, fails and skips.
func assertFullRunRows(t *testing.T, payload *core.SubmissionPayload) {
	t.Helper()
	s := payload.Summary
	if s.PoliciesTotal != len(payload.Policies) {
		t.Errorf("summary total %d; payload has %d policies", s.PoliciesTotal, len(payload.Policies))
	}
	if s.PoliciesPassed == 0 || s.PoliciesSkipped == 0 {
		t.Errorf("want passes and skips in a full run: %+v", s)
	}
	if s.PoliciesFailed != len(cloudFullEmpty[payload.Framework]) {
		t.Errorf("failed policies = %d; want one per empty entry (%d)", s.PoliciesFailed, len(cloudFullEmpty[payload.Framework]))
	}
}

// firstLineDiff names the first line where got and want differ.
func firstLineDiff(got, want []byte) string {
	g, w := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			return "line " + strconv.Itoa(i+1) + ": got " + strings.TrimSpace(gl) + ", want " + strings.TrimSpace(wl)
		}
	}
	return "trailing bytes"
}

// TestCloudFullGoldens_NoIdentityKeys scans the committed full-run
// goldens, which a public repo and the dashboard both hold, for any key
// the privacy boundary forbids and for values that look like an
// identifier or a local path (Sacred Invariant 1).
func TestCloudFullGoldens_NoIdentityKeys(t *testing.T) {
	forbidden := map[string]bool{
		"violations": true, "violation": true, "resources": true, "identifiers": true,
		"arn": true, "email": true, "username": true, "account_id": true, "user_id": true,
		"file_hash": true, "raw": true,
	}
	for _, fw := range []string{defaultFW, isoFW} {
		var generic any
		readJSON(t, cloudFullGoldenPath(fw), &generic)
		scanForIdentity(t, fw, generic, forbidden, "")
	}
}

// emailLike matches an address but not a framework version such as
// "soc2-2017@1.0.0".
var emailLike = regexp.MustCompile(`[^\s@]+@[^\s@]+\.[A-Za-z]{2,}`)

func scanForIdentity(t *testing.T, fw string, v any, forbidden map[string]bool, path string) {
	t.Helper()
	switch node := v.(type) {
	case map[string]any:
		for k, child := range node {
			if forbidden[k] {
				t.Errorf("%s: forbidden key %q at %s", fw, k, path)
			}
			scanForIdentity(t, fw, child, forbidden, path+"."+k)
		}
	case []any:
		for _, child := range node {
			scanForIdentity(t, fw, child, forbidden, path+"[]")
		}
	case string:
		for _, bad := range []string{"arn:", "evidence.pdf", "file://", os.TempDir()} {
			if strings.Contains(node, bad) {
				t.Errorf("%s: value at %s contains %q: %q", fw, path, bad, node)
			}
		}
		if emailLike.MatchString(node) {
			t.Errorf("%s: value at %s looks like an email address: %q", fw, path, node)
		}
	}
}
