package orchestrator

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/submitter"
	"github.com/sigcomply/sigcomply-cli/internal/submitter/oidctest"
)

// stubTokenProvider hands back a canned token so Submit never touches a
// real OIDC endpoint.
type stubTokenProvider struct{}

func (stubTokenProvider) Token(context.Context, string) (token, providerName string, err error) {
	return oidctest.JWT(submitter.DefaultAudience), "test-provider", nil
}

// handleSubmission's DecisionSubmit branch: with Force + an injected
// token provider + an OIDC env hint, the payload is POSTed and the run
// reports Submitted=true.
func TestHandleSubmission_SubmitsSuccessfully(t *testing.T) {
	t.Setenv("SIGCOMPLY_ID_TOKEN", oidctest.JWT(submitter.DefaultAudience)) // makes submitter.HasOIDC() true

	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := readAll(r)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		gotBody = body
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`)) //nolint:errcheck // test server response
	}))
	defer srv.Close()

	var logBuf bytes.Buffer
	opts := &Options{
		Logger: log.New(&logBuf, false),
		SubmitterOpts: submitter.Options{
			BaseURL:       srv.URL,
			Force:         true,
			TokenProvider: stubTokenProvider{},
		},
	}
	payload := &core.SubmissionPayload{Schema: "sigcomply.cloud.v5", RunID: "r1"}
	completedAt := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)

	submitted, at, err := handleSubmission(context.Background(), opts, payload, completedAt, false)
	if err != nil {
		t.Fatalf("handleSubmission: %v", err)
	}
	if !submitted {
		t.Fatalf("submitted = false; want true. log=%s", logBuf.String())
	}
	if !at.Equal(completedAt) {
		t.Errorf("submittedAt = %v; want %v", at, completedAt)
	}
	if len(gotBody) == 0 {
		t.Error("server received empty body")
	}
}

// A 4xx from the cloud is non-fatal: handleSubmission logs and returns
// submitted=false without panicking.
func TestHandleSubmission_ServerErrorIsNonFatal(t *testing.T) {
	t.Setenv("SIGCOMPLY_ID_TOKEN", oidctest.JWT(submitter.DefaultAudience))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	var logBuf bytes.Buffer
	opts := &Options{
		Logger: log.New(&logBuf, false),
		SubmitterOpts: submitter.Options{
			BaseURL:       srv.URL,
			Force:         true,
			TokenProvider: stubTokenProvider{},
		},
	}
	submitted, _, err := handleSubmission(context.Background(), opts,
		&core.SubmissionPayload{Schema: "x"}, time.Now(), false)
	if submitted {
		t.Error("submitted = true; want false on 4xx")
	}
	if err != nil {
		t.Errorf("a refused submission must not change the exit code; got %v", err)
	}
}

// The capture file is what the operator explicitly asked for (the
// auditor's view of what would be sent), so failing to write it is an
// error the run reports, not a warning it exits 0 past.
func TestHandleSubmission_CaptureWriteFailureIsAnError(t *testing.T) {
	var logBuf bytes.Buffer
	opts := &Options{
		Logger:             log.New(&logBuf, false),
		CapturePayloadPath: "/nonexistent-dir-xyz/captured.json",
	}
	submitted, _, err := handleSubmission(context.Background(), opts,
		&core.SubmissionPayload{Schema: "x"}, time.Now(), false)
	if submitted {
		t.Error("submitted = true; want false (capture path takes precedence)")
	}
	if err == nil || !strings.Contains(err.Error(), "captured.json") {
		t.Errorf("want an error naming the capture path; got %v", err)
	}
}

// collectAppliedExceptions snapshots resolved exceptions sorted by
// policy ID for deterministic manifests, and returns nil when none.
func TestCollectAppliedExceptions(t *testing.T) {
	plan := &planner.RunPlan{
		Policies: []planner.PlannedPolicy{
			{Spec: core.Policy{ID: "p.z"}, Exceptions: []*planner.Exception{
				{State: core.StatusWaived, Reason: "z1", ResourceID: "r1"},
				{State: core.StatusWaived, Reason: "z2", ResourceID: "r2"},
			}},
			{Spec: core.Policy{ID: "p.a"}, Exceptions: []*planner.Exception{{State: core.StatusNA, Reason: "a"}}},
			{Spec: core.Policy{ID: "p.none"}}, // no exception
		},
	}
	got := collectAppliedExceptions(plan)
	// Every live exception is recorded, not only a policy's first.
	if len(got) != 3 {
		t.Fatalf("got %d applied exceptions; want 3", len(got))
	}
	// Sorted by policy ID (p.a before p.z); a policy's own entries keep
	// their declared order.
	if got[0].PolicyID != "p.a" || got[1].Reason != "z1" || got[2].Reason != "z2" {
		t.Errorf("order = %v; want p.a, then p.z's z1, z2", got)
	}

	// No exceptions → nil (so the manifest field stays absent).
	empty := collectAppliedExceptions(&planner.RunPlan{
		Policies: []planner.PlannedPolicy{{Spec: core.Policy{ID: "p1"}}},
	})
	if empty != nil {
		t.Errorf("want nil for no exceptions; got %v", empty)
	}
}

// readAll drains the request body; small helper to avoid importing io in
// the test's hot path more than once.
func readAll(r *http.Request) ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r.Body)
	return buf.Bytes(), err
}

// filteredNotice is the stdout line a filtered run prints instead of
// submitting.
const filteredNotice = "cloud submission skipped: this run evaluates a subset of policies"

// setSubmittingCI makes every condition for an automatic submission hold:
// in CI, with an OIDC token.
func setSubmittingCI(t *testing.T) {
	t.Helper()
	t.Setenv("CI", "true")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("SIGCOMPLY_ID_TOKEN", oidctest.JWT(submitter.DefaultAudience))
}

// Every submitted run is a full snapshot: the dashboard reads the latest
// run as the project's state, so a run over a subset of policies would
// replace the score with one over different controls. Only an unfiltered
// run and a --scheduled run (not-due policies carry forward) submit.
func TestRun_OnlyFullSnapshotRunsSubmit(t *testing.T) {
	setSubmittingCI(t)
	cases := []struct {
		name       string
		mode       Mode
		filter     planner.Filter
		wantSubmit bool
	}{
		{"unfiltered check", ModeManual, planner.Filter{}, true},
		{"--scheduled", ModeScheduled, planner.Filter{}, true},
		{"--cadence", ModeManual, planner.Filter{Cadence: cadenceDaily}, false},
		{"--cadences", ModeManual, planner.Filter{Cadences: []string{cadenceDaily}}, false},
		{"--on-push", ModeManual, planner.Filter{OnPush: true}, false},
		{"--pr", ModePR, planner.Filter{}, false},
		{"--scheduled with a filter", ModeScheduled, planner.Filter{Cadence: cadenceDaily}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusCreated)
			}))
			defer srv.Close()

			var stdout bytes.Buffer
			res, err := Run(context.Background(), &Options{
				Config:        schedConfig(),
				Registries:    schedRegistries(t, &schedSource{}),
				Vault:         newListVault(),
				Mode:          tc.mode,
				Filter:        tc.filter,
				Stdout:        &stdout,
				Logger:        log.New(&bytes.Buffer{}, false),
				Now:           func() time.Time { return time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC) },
				SubmitterOpts: submitter.Options{BaseURL: srv.URL},
			})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			wantCalls := int32(0)
			if tc.wantSubmit {
				wantCalls = 1
			}
			if got := calls.Load(); got != wantCalls || res.Submitted != tc.wantSubmit {
				t.Errorf("POSTs = %d, Submitted = %v; want %d, %v", got, res.Submitted, wantCalls, tc.wantSubmit)
			}
			if got := strings.Contains(stdout.String(), filteredNotice); got == tc.wantSubmit {
				t.Errorf("skip notice printed = %v; want %v\n%s", got, !tc.wantSubmit, stdout.String())
			}
		})
	}
}

// --capture-cloud-payload still writes on a filtered run, so an auditor
// can inspect it, and the run still says it would not have been sent.
func TestRun_FilteredRunStillCapturesPayload(t *testing.T) {
	out := filepath.Join(t.TempDir(), "payload.json")
	var stdout bytes.Buffer
	_, err := Run(context.Background(), &Options{
		Config:             schedConfig(),
		Registries:         schedRegistries(t, &schedSource{}),
		Vault:              newListVault(),
		Filter:             planner.Filter{Cadence: cadenceDaily},
		Stdout:             &stdout,
		Logger:             log.New(&bytes.Buffer{}, false),
		Now:                func() time.Time { return time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC) },
		CapturePayloadPath: out,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("payload not captured: %v", err)
	}
	if !strings.Contains(stdout.String(), filteredNotice) {
		t.Errorf("stdout missing the skip notice:\n%s", stdout.String())
	}
}

// A filtered run with no cloud configured says nothing about submission:
// there was none to skip.
func TestRun_FilteredRunWithoutCloudIsQuiet(t *testing.T) {
	var stdout bytes.Buffer
	_, err := Run(context.Background(), &Options{
		Config:     schedConfig(),
		Registries: schedRegistries(t, &schedSource{}),
		Vault:      newListVault(),
		Filter:     planner.Filter{Cadence: cadenceDaily},
		Stdout:     &stdout,
		Logger:     log.New(&bytes.Buffer{}, false),
		Now:        func() time.Time { return time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(stdout.String(), filteredNotice) {
		t.Errorf("skip notice printed with no cloud configured:\n%s", stdout.String())
	}
}

// A --pr run evaluates the pull request's branch and config. It must not
// advance cadence state, or a later --scheduled run on the default branch
// would carry forward a pass the branch earned.
func TestRun_PRModeDoesNotAdvanceState(t *testing.T) {
	p := schedPolicy()
	p.OnPush = true
	src := &schedSource{}
	v := newListVault()
	res, err := Run(context.Background(), &Options{
		Config:        schedConfig(),
		Registries:    schedRegistriesWith(t, src, &p),
		Vault:         v,
		Mode:          ModePR,
		Stdout:        &bytes.Buffer{},
		Logger:        log.New(&bytes.Buffer{}, false),
		Now:           func() time.Time { return time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC) },
		SubmitterOpts: submitter.Options{Disable: true},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Summary.PoliciesPassed != 1 || src.calls != 1 {
		t.Fatalf("PR run passed %d policies with %d collections; want 1 and 1", res.Summary.PoliciesPassed, src.calls)
	}
	st, err := ReadPolicyState(context.Background(), v, testFramework, testPolicyID)
	if err != nil {
		t.Fatal(err)
	}
	if st != nil {
		t.Errorf("--pr wrote a state shard: %+v", st)
	}
}

// A pull-request or merge-request pipeline evaluates the branch, whatever
// flags it passes. A plain `check` or `--scheduled` run in one must not
// advance cadence state either; a push pipeline still does.
func TestRun_PRPipelineDoesNotAdvanceStateWithoutPRFlag(t *testing.T) {
	tests := []struct {
		name      string
		env       map[string]string
		wantState bool
	}{
		{"github pull_request", map[string]string{envGitHubEventName: "pull_request"}, false},
		{"github pull_request_target", map[string]string{envGitHubEventName: "pull_request_target"}, false},
		{"gitlab merge request", map[string]string{envMergeRequestIID: "7"}, false},
		{"github push", map[string]string{envGitHubEventName: "push"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{envGitHubEventName, envMergeRequestIID} {
				t.Setenv(k, tc.env[k])
			}
			p := schedPolicy()
			v := newListVault()
			_, err := Run(context.Background(), &Options{
				Config:        schedConfig(),
				Registries:    schedRegistriesWith(t, &schedSource{}, &p),
				Vault:         v,
				Stdout:        &bytes.Buffer{},
				Logger:        log.New(&bytes.Buffer{}, false),
				Now:           func() time.Time { return time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC) },
				SubmitterOpts: submitter.Options{Disable: true},
			})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			st, err := ReadPolicyState(context.Background(), v, testFramework, testPolicyID)
			if err != nil {
				t.Fatal(err)
			}
			if (st != nil) != tc.wantState {
				t.Errorf("state shard written = %v; want %v", st != nil, tc.wantState)
			}
		})
	}
}
