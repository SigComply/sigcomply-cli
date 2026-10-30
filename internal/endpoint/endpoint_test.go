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
