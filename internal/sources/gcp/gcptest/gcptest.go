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
	"testing"

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
