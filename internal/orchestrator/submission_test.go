package orchestrator

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/submitter"
)

// stubTokenProvider hands back a canned token so Submit never touches a
// real OIDC endpoint.
type stubTokenProvider struct{}

func (stubTokenProvider) Token(context.Context, string) (token, providerName string, err error) {
	return "test-token", "test-provider", nil
}

// handleSubmission's DecisionSubmit branch: with Force + an injected
// token provider + an OIDC env hint, the payload is POSTed and the run
// reports Submitted=true.
func TestHandleSubmission_SubmitsSuccessfully(t *testing.T) {
	t.Setenv("SIGCOMPLY_ID_TOKEN", "present") // makes submitter.HasOIDC() true

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
	payload := &core.SubmissionPayload{Schema: "sigcomply.cloud.v3", RunID: "r1"}
	completedAt := time.Date(2026, 5, 24, 9, 0, 0, 0, time.UTC)

	submitted, at := handleSubmission(context.Background(), opts, payload, completedAt)
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
	t.Setenv("SIGCOMPLY_ID_TOKEN", "present")
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
	submitted, _ := handleSubmission(context.Background(), opts,
		&core.SubmissionPayload{Schema: "x"}, time.Now())
	if submitted {
		t.Error("submitted = true; want false on 4xx")
	}
}

// The capture-payload branch with an unwritable path logs a warning and
// reports submitted=false (the directory does not exist).
func TestHandleSubmission_CaptureWriteFailureIsNonFatal(t *testing.T) {
	var logBuf bytes.Buffer
	opts := &Options{
		Logger:             log.New(&logBuf, false),
		CapturePayloadPath: "/nonexistent-dir-xyz/captured.json",
	}
	submitted, _ := handleSubmission(context.Background(), opts,
		&core.SubmissionPayload{Schema: "x"}, time.Now())
	if submitted {
		t.Error("submitted = true; want false (capture path takes precedence)")
	}
}

// collectAppliedExceptions snapshots resolved exceptions sorted by
// policy ID for deterministic manifests, and returns nil when none.
func TestCollectAppliedExceptions(t *testing.T) {
	plan := &planner.RunPlan{
		Policies: []planner.PlannedPolicy{
			{Spec: core.Policy{ID: "p.z"}, Exception: &planner.Exception{State: core.StatusWaived, Reason: "z"}},
			{Spec: core.Policy{ID: "p.a"}, Exception: &planner.Exception{State: core.StatusNA, Reason: "a"}},
			{Spec: core.Policy{ID: "p.none"}}, // no exception
		},
	}
	got := collectAppliedExceptions(plan)
	if len(got) != 2 {
		t.Fatalf("got %d applied exceptions; want 2", len(got))
	}
	// Sorted by policy ID: p.a before p.z.
	if got[0].PolicyID != "p.a" || got[1].PolicyID != "p.z" {
		t.Errorf("not sorted by policy id: %v", []string{got[0].PolicyID, got[1].PolicyID})
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
