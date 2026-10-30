package entra

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Graph's @odata.nextLink is followed with the bearer token. A link to
// another host (a hostile proxy or mock, a tampered response) must be
// refused, not requested.
func TestRealGraph_NextLinkMustStayOnGraphHost(t *testing.T) {
	var foreignHits atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignHits.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("the bearer token reached the foreign host")
		}
		_, _ = w.Write([]byte(`{"value":[]}`)) //nolint:errcheck // test handler
	}))
	defer foreign.Close()

	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) > 1 {
			_, _ = w.Write([]byte(`{"value":[]}`)) //nolint:errcheck // test handler
			return
		}
		_, _ = w.Write([]byte(`{"value":[],"@odata.nextLink":"` + foreign.URL + `/v1.0/users?$skiptoken=x"}`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()

	r := &realGraph{base: srv.URL + "/v1.0", client: srv.Client(), cred: fakeCred{}}
	_, err := r.ListDomains(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pagination link") {
		t.Errorf("ListDomains err = %v; want a pagination-link error", err)
	}
	if n := foreignHits.Load(); n != 0 {
		t.Errorf("foreign host received %d request(s)", n)
	}
}
