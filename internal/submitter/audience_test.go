package submitter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/submitter/oidctest"
)

// validToken is a token minted for SigComply Cloud.
var validToken = oidctest.JWT(DefaultAudience)

// A bearer token is sent only to the receiver it was minted for. A token
// minted for AWS (or any other audience) must never reach SigComply
// Cloud, whichever provider produced it.
func TestSubmit_RefusesTokenNotMintedForSigComply(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"aws audience", oidctest.JWT("sts.amazonaws.com")},
		{"no audience", oidctest.JWT()},
		{"not a jwt", "opaque-token"},
		{"bad payload encoding", "a.!!!.c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusCreated)
			}))
			defer srv.Close()
			_, err := Submit(context.Background(), &Options{
				BaseURL:       srv.URL,
				TokenProvider: &stubProvider{token: tc.token, provider: providerGitLab},
			}, &core.SubmissionPayload{})
			if err == nil || !strings.Contains(err.Error(), "audience") {
				t.Fatalf("want an audience error; got %v", err)
			}
			if strings.Contains(err.Error(), tc.token) {
				t.Errorf("the error must not echo the token: %v", err)
			}
			if calls.Load() != 0 {
				t.Error("the token was sent")
			}
		})
	}
}

// GitLab may mint a token for several audiences; one of them being
// SigComply's is enough.
func TestSubmit_AcceptsAudienceList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	_, err := Submit(context.Background(), &Options{
		BaseURL:       srv.URL,
		TokenProvider: &stubProvider{token: oidctest.JWT("other", DefaultAudience), provider: providerGitLab},
	}, &core.SubmissionPayload{})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
}

// ID_TOKEN is a generic name other jobs use for their own tokens (AWS,
// Vault). Reading it would forward someone else's credential.
func TestGitLabCIProvider_IgnoresGenericIDToken(t *testing.T) {
	t.Setenv(GitLabIDTokenEnv, "")
	t.Setenv("ID_TOKEN", validToken)
	_, _, err := (&gitlabCIProvider{}).Token(context.Background(), DefaultAudience)
	if err == nil {
		t.Fatal("ID_TOKEN was read; only SIGCOMPLY_ID_TOKEN may be")
	}
	if HasOIDC() {
		t.Error("HasOIDC true with only ID_TOKEN set")
	}
}

// The AWS token must never carry SigComply's audience: SigComply Cloud
// receives every submitted token, so an AWS role that trusts that
// audience is a role SigComply Cloud could assume.
func TestAWSWebIdentityAudienceWarning(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		name     string
		file     string
		wantWarn bool
	}{
		{"sigcomply audience", write("shared", validToken), true},
		{"sigcomply among several", write("several", oidctest.JWT("sts.amazonaws.com", DefaultAudience)), true},
		{"aws audience", write("aws", oidctest.JWT("sts.amazonaws.com")), false},
		{"unset", "", false},
		{"missing file", filepath.Join(dir, "absent"), false},
		{"not a jwt", write("opaque", "opaque"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tc.file)
			got := AWSWebIdentityAudienceWarning()
			if (got != "") != tc.wantWarn {
				t.Fatalf("warning = %q; want warning: %v", got, tc.wantWarn)
			}
			if tc.wantWarn && !strings.Contains(got, "sts.amazonaws.com") {
				t.Errorf("the warning should name the audience to use: %q", got)
			}
		})
	}
}
