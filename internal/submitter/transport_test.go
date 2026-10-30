package submitter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// stubToken is the bearer token the stub provider hands out.
var stubToken = validToken

// A provider that is present but fails (GitHub refusing the audience)
// must not be masked by a later provider that is simply absent.
func TestChainProvider_KeepsRealErrorOverNoToken(t *testing.T) {
	ghErr := errors.New("github actions oidc: 403 audience not allowed")
	c := &chainProvider{providers: []TokenProvider{
		&stubProvider{err: ghErr},
		&stubProvider{err: ErrNoToken},
	}}
	_, _, err := c.Token(context.Background(), "")
	if !errors.Is(err, ghErr) {
		t.Fatalf("want the GitHub error; got %v", err)
	}
}

// A 301/302 turns the POST into a GET and forwards the bearer token to
// wherever the redirect points; the CLI used to log that as accepted.
func TestSubmit_RedirectIsAnError(t *testing.T) {
	var gotGET bool
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			gotGET = true
		}
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+Path, http.StatusMovedPermanently)
	}))
	defer redirector.Close()

	resp, err := Submit(context.Background(), &Options{
		BaseURL:       redirector.URL,
		TokenProvider: &stubProvider{token: stubToken, provider: providerGitLab},
	}, &core.SubmissionPayload{})
	if err == nil || !strings.Contains(err.Error(), "redirect") || !strings.Contains(err.Error(), target.URL) {
		t.Fatalf("want a redirect error naming the target; got resp=%+v err=%v", resp, err)
	}
	if gotGET {
		t.Error("the redirect was followed")
	}
}

func TestValidateBaseURL(t *testing.T) {
	for _, ok := range []string{"https://sigcomply.com", "https://sigcomply.com/", "http://localhost:3000", "http://127.0.0.1:8080", "http://[::1]:9"} {
		if err := ValidateBaseURL(ok); err != nil {
			t.Errorf("%s: unexpected error %v", ok, err)
		}
	}
	for _, bad := range []string{"http://sigcomply.com", "ftp://x", "sigcomply.com", "https://", "http://localhost.evil.com"} {
		if err := ValidateBaseURL(bad); err == nil {
			t.Errorf("%s: want an error", bad)
		}
	}
}

func TestSubmit_RefusesPlainHTTP(t *testing.T) {
	_, err := Submit(context.Background(), &Options{
		BaseURL:       "http://sigcomply.example",
		TokenProvider: &stubProvider{token: stubToken, provider: providerGitLab},
	}, &core.SubmissionPayload{})
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("want an https error; got %v", err)
	}
}
