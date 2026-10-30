// Package endpoint checks the URLs the CLI sends a credential to: the
// SigComply Cloud base URL, a source's API base URL, an S3-compatible
// endpoint. One rule for all of them, so no credentialed HTTP request
// can go out in cleartext.
package endpoint

import (
	"fmt"
	neturl "net/url"
)

// ValidateHTTPS accepts an https URL with a host, or plain http to a
// loopback host for local testing. Anything else would send the
// credential (an OIDC bearer token, an API token, an AWS session token)
// unencrypted. name labels the setting in the error, for example
// `cloud base URL` or `github: "base_url"`.
func ValidateHTTPS(name, raw string) error {
	u, err := neturl.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s %q: %w", name, raw, err)
	}
	if u.Host == "" {
		return fmt.Errorf("%s %q: want https://<host>", name, raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
		return fmt.Errorf("%s %q: must use https; plain http would send the credential unencrypted (http is accepted only for localhost)", name, raw)
	default:
		return fmt.Errorf("%s %q: want https://<host>", name, raw)
	}
}
