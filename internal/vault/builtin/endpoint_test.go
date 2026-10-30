package builtin_test

import (
	"context"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
	_ "github.com/sigcomply/sigcomply-cli/internal/vault/builtin"
)

// Every vault backend that declares an endpoint key refuses a plaintext
// one: the request carries the backend's credentials (an AWS session
// token, a bearer token). Derived from the registry, so a new backend is
// covered without editing this test.
func TestEveryVaultBackendRefusesPlaintextEndpoints(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	const bad = "http://minio.example.com:9000"
	checked := 0
	for _, id := range vault.IDs() {
		for _, key := range vault.BackendKeys(id) {
			lower := strings.ToLower(key)
			if !strings.Contains(lower, "endpoint") && !strings.Contains(lower, "url") && !strings.Contains(lower, "host") {
				continue
			}
			checked++
			t.Run(id+"/"+key, func(t *testing.T) {
				f, _ := vault.Lookup(id)
				_, err := f(context.Background(), &spec.VaultConfig{Backend: id, Config: map[string]any{
					"bucket": "evidence", "region": "us-east-1", "account": "acct", "container": "c", key: bad,
				}})
				if err == nil || !strings.Contains(err.Error(), bad) {
					t.Fatalf("%s accepted %s %s; got %v", id, key, bad, err)
				}
			})
		}
	}
	if checked == 0 {
		t.Fatal("no vault backend declares an endpoint key; the registry was not populated")
	}
}
