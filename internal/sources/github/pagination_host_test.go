package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The cursor-paginated endpoints follow the Link header's rel="next"
// URL, and every request carries the token. A Link pointing at another
// host (a compromised or misconfigured GHES proxy, a hostile mock) would
// send the token there. A next URL must stay on the configured API host
// and under its base path.
func TestHTTPAPI_PaginationLinkMustStayOnAPIHost(t *testing.T) {
	var foreignHits atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignHits.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("the token reached the foreign host")
		}
		_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
	}))
	defer foreign.Close()

	for name, next := range map[string]string{
		"other host":       foreign.URL + "/orgs/acme/dependabot/alerts?after=x",
		"other scheme":     "ftp://" + strings.TrimPrefix(foreign.URL, "http://") + "/x",
		"outside base dir": "", // filled below: same host, path above the base
	} {
		t.Run(name, func(t *testing.T) {
			var api *httpAPI
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				link := next
				if link == "" {
					link = strings.TrimSuffix(api.base, "/api/v3") + "/other/path?after=x"
				}
				w.Header().Set("Link", "<"+link+`>; rel="next"`)
				_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
			}))
			defer srv.Close()
			api = &httpAPI{org: testOrg, token: testToken, base: srv.URL + "/api/v3", client: srv.Client()}
			_, err := api.ListDependabotAlerts(context.Background())
			if err == nil || !strings.Contains(err.Error(), "pagination") {
				t.Errorf("ListDependabotAlerts err = %v; want a pagination-link error", err)
			}
		})
	}
	if n := foreignHits.Load(); n != 0 {
		t.Errorf("foreign host received %d request(s)", n)
	}
}
