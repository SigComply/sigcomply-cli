// Package endpoint checks the URLs the CLI sends a credential to: the
// SigComply Cloud base URL, a source's API base URL, an S3-compatible
// endpoint. One rule for all of them, so no credentialed HTTP request
// can go out in cleartext.
package endpoint

import (
	"fmt"
	neturl "net/url"
	"regexp"
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
		return fmt.Errorf("%s %q: must use https; plain http would send the credential unencrypted (http is accepted only for a loopback host: localhost, 127.0.0.1, ::1)", name, raw)
	default:
		return fmt.Errorf("%s %q: want https://<host>", name, raw)
	}
}

// azureStorageAccountRE is Azure's rule for a storage account name.
var azureStorageAccountRE = regexp.MustCompile(`^[a-z0-9]{3,24}$`)

// ValidateAzureStorageAccount accepts an Azure storage account name: 3
// to 24 lowercase letters and digits. The name becomes the host
// <account>.blob.core.windows.net of a request that carries the job's
// Azure Storage token, so a value such as "evil.example/#" would send
// that token to another host. name labels the setting in the error.
func ValidateAzureStorageAccount(name, account string) error {
	if !azureStorageAccountRE.MatchString(account) {
		return fmt.Errorf("%s %q: an Azure storage account name is 3 to 24 lowercase letters and digits", name, account)
	}
	return nil
}
