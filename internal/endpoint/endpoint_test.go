package endpoint

import (
	"strings"
	"testing"
)

func TestValidateHTTPS(t *testing.T) {
	for _, ok := range []string{
		"https://sigcomply.com", "https://sigcomply.com/", "https://ghe.example.com/api/v3",
		"http://localhost:3000", "http://127.0.0.1:8080", "http://[::1]:9",
	} {
		if err := ValidateHTTPS("base URL", ok); err != nil {
			t.Errorf("%s: unexpected error %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://sigcomply.com", "ftp://x", "sigcomply.com", "https://", "http://localhost.evil.com", "HTTP://example.com",
	} {
		err := ValidateHTTPS("base URL", bad)
		if err == nil {
			t.Errorf("%s: want an error", bad)
			continue
		}
		if !strings.Contains(err.Error(), "base URL") {
			t.Errorf("%s: the error should name the setting: %v", bad, err)
		}
	}
}

// The refusal of plain http names every loopback host it accepts, not
// just localhost.
func TestValidateHTTPS_ErrorNamesLoopbackHosts(t *testing.T) {
	err := ValidateHTTPS("base URL", "http://sigcomply.com")
	for _, host := range []string{"localhost", "127.0.0.1", "::1"} {
		if err == nil || !strings.Contains(err.Error(), host) {
			t.Errorf("error should name %s: %v", host, err)
		}
	}
}

// An Azure storage account name becomes the host of the request that
// carries the job's Azure Storage token, so anything but the 3-24
// lowercase letters and digits Azure allows is refused.
func TestValidateAzureStorageAccount(t *testing.T) {
	for _, ok := range []string{"abc", "evidence01", strings.Repeat("a", 24)} {
		if err := ValidateAzureStorageAccount("account", ok); err != nil {
			t.Errorf("%q: unexpected error %v", ok, err)
		}
	}
	for _, bad := range []string{"", "ab", strings.Repeat("a", 25), "Evidence", "evil.example/#", "evil.example?", "a-b-c", "acct@evil.example", "acct:443"} {
		err := ValidateAzureStorageAccount("account", bad)
		if err == nil {
			t.Errorf("%q: accepted", bad)
			continue
		}
		if !strings.Contains(err.Error(), "account") {
			t.Errorf("%q: the error should name the setting: %v", bad, err)
		}
	}
}
