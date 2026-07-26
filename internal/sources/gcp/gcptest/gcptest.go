// Package gcptest is the GCP test seam (WU-2.7): it builds the option.ClientOption
// set that points a GCP SDK client (google.golang.org/api/* or
// cloud.google.com/go/storage) at a go-vcr cassette instead of the live API, so
// GCP source plugins can be exercised offline through the real deserializer.
//
// GCP has no usable test credential in this org (SA-key creation and
// impersonation are blocked org-wide — see CLAUDE.local.md), so cassettes are
// hand-authored: canned Discovery-shaped JSON is served from an httptest server
// at record time (RecordOptions, endpoint = the httptest URL), captured by the
// recorder, then the recorded URL is rewritten to the real googleapis endpoint;
// replay (ReplayOptions, endpoint = the real endpoint) matches on method+URL
// (GCP gives each operation a distinct URL, so no body matcher is needed).
package gcptest

import (
	"context"
	"net/http"
	"os"
	"testing"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// ReplayOptions returns client options that replay the named cassette offline,
// with auth disabled and the (real) endpoint the cassette was rewritten to.
func ReplayOptions(t *testing.T, cassetteName, endpoint string) []option.ClientOption {
	t.Helper()
	return []option.ClientOption{
		option.WithoutAuthentication(),
		option.WithEndpoint(endpoint),
		option.WithHTTPClient(sourcetest.ReplayClient(t, cassetteName)),
	}
}

// RecordOptions returns client options that record into the named cassette,
// pointed at endpoint (an httptest server serving canned JSON). Maintainer path.
func RecordOptions(t *testing.T, cassetteName, endpoint string) []option.ClientOption {
	t.Helper()
	return []option.ClientOption{
		option.WithoutAuthentication(),
		option.WithEndpoint(endpoint),
		option.WithHTTPClient(sourcetest.RecordClient(t, cassetteName, nil)),
	}
}

// RecordLiveOptions returns client options that record REAL GCP API traffic into
// the named cassette, pointed at the live endpoint (e.g.
// "https://storage.googleapis.com"). Unlike RecordOptions (which records a
// hand-authored httptest server), this authenticates via Application Default
// Credentials, so it hits the real API — the maintainer path for capturing a
// genuine cassette against a seeded test project.
//
// Configure impersonation before recording (the recorder SA is read-only):
//
//	gcloud auth application-default login \
//	  --impersonate-service-account=sigcomply-e2e-recorder@<project>.iam.gserviceaccount.com
//
// The recorder wraps the ADC oauth2 transport, so a real bearer token reaches
// googleapis while the request the cassette stores carries none (the token is
// added by the inner transport, below the recording point, and RedactInteraction
// scrubs Authorization as a second guard). Only ever run under //go:build record;
// never in the per-PR suite.
func RecordLiveOptions(t *testing.T, cassetteName, endpoint string, scopes ...string) []option.ClientOption {
	t.Helper()
	if len(scopes) == 0 {
		scopes = []string{"https://www.googleapis.com/auth/cloud-platform.read-only"}
	}
	creds, err := google.FindDefaultCredentials(context.Background(), scopes...)
	if err != nil {
		t.Fatalf("gcptest: no Application Default Credentials — run `gcloud auth "+
			"application-default login --impersonate-service-account=<recorder-sa>`: %v", err)
	}
	var authed http.RoundTripper = &oauth2.Transport{Source: creds.TokenSource, Base: http.DefaultTransport}
	// Some APIs (Cloud Asset, etc.) reject user ADC without a quota project (the
	// X-Goog-User-Project header). Our custom transport bypasses the client
	// library's ADC quota-project handling, so inject it from the record env.
	// Added below the recording point, so it never lands in the cassette.
	if qp := os.Getenv("GCP_TEST_PROJECT"); qp != "" {
		authed = &quotaProjectTransport{base: authed, project: qp}
	}
	return []option.ClientOption{
		// Auth lives in `authed`, so tell the SDK not to add its own credential
		// layer on top of our recording transport.
		option.WithoutAuthentication(),
		option.WithEndpoint(endpoint),
		option.WithHTTPClient(sourcetest.RecordClient(t, cassetteName, authed)),
	}
}

// quotaProjectTransport sets X-Goog-User-Project on each request so a live
// recording against user ADC satisfies APIs that require a quota project.
type quotaProjectTransport struct {
	base    http.RoundTripper
	project string
}

func (q *quotaProjectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("X-Goog-User-Project") == "" {
		r = r.Clone(r.Context())
		r.Header.Set("X-Goog-User-Project", q.project)
	}
	return q.base.RoundTrip(r)
}
