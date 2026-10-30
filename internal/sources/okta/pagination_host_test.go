package okta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The rel="next" Link is requested with the SSWS token. A link to
// another host was appended to the org URL as a path, so a value such as
// ".evil.example/x" or "@evil.example/x" moved the request to another
// host. Such a link must be refused.
func TestHTTPAPI_PaginationLinkMustStayOnOrgHost(t *testing.T) {
	var foreignHits atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignHits.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("the token reached the foreign host")
		}
		_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
	}))
	defer foreign.Close()
	foreignHost := strings.TrimPrefix(foreign.URL, "http://")

	for name, next := range map[string]string{
		"other host": foreign.URL + "/api/v1/apps?after=x",
		"user info":  "@" + foreignHost + "/api/v1/apps?after=x",
	} {
		t.Run(name, func(t *testing.T) {
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if requests.Add(1) == 1 {
					w.Header().Set("Link", "<"+next+`>; rel="next"`)
				}
				_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
			}))
			defer srv.Close()
			api := &httpAPI{base: srv.URL, token: testToken, client: srv.Client()}
			_, err := api.ListApps(context.Background())
			if err == nil || !strings.Contains(err.Error(), "pagination link") {
				t.Errorf("ListApps err = %v; want a pagination-link error", err)
			}
		})
	}
	if n := foreignHits.Load(); n != 0 {
		t.Errorf("foreign host received %d request(s)", n)
	}
}
