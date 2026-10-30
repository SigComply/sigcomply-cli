package sources

import (
	"strings"
	"testing"
)

// A pagination link the server returns is requested with the source's
// credential, so it must stay on the configured API base: same scheme,
// same host, no user info, under the base path.
func TestFollowableLink(t *testing.T) {
	const base = "https://graph.microsoft.com/v1.0"
	for next, want := range map[string]string{
		"": "",
		"https://graph.microsoft.com/v1.0/users?$skiptoken=x": "https://graph.microsoft.com/v1.0/users?$skiptoken=x",
		"/v1.0/users?$skiptoken=y":                            "https://graph.microsoft.com/v1.0/users?$skiptoken=y",
	} {
		got, err := FollowableLink("azure.entra", base, next)
		if err != nil || got != want {
			t.Errorf("FollowableLink(%q) = %q, %v; want %q", next, got, err, want)
		}
	}
	for _, next := range []string{
		"https://evil.example/v1.0/users",
		"http://graph.microsoft.com/v1.0/users",
		"https://graph.microsoft.com.evil.example/v1.0/users",
		"https://user@graph.microsoft.com/v1.0/users",
		"//evil.example/v1.0/users",
		"https://graph.microsoft.com/beta/users",
		"https://graph.microsoft.com/v1.0evil/users",
		"https://graph.microsoft.com:8443/v1.0/users",
		"@evil.example/v1.0",
	} {
		got, err := FollowableLink("azure.entra", base, next)
		if err == nil {
			t.Errorf("FollowableLink(%q) = %q; want an error", next, got)
			continue
		}
		if !strings.Contains(err.Error(), "azure.entra") || !strings.Contains(err.Error(), "pagination link") {
			t.Errorf("FollowableLink(%q): the error should name the source and the link: %v", next, err)
		}
	}
}
