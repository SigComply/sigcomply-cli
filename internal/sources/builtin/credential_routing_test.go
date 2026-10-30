package builtin_test

import (
	"context"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

const (
	keyOrgURL   = "org_url"
	keyToken    = "token"
	keyAPIToken = "api_token"
	dummyCred   = "dummy"
)

// endpointKeys maps every config key that names where a source sends
// its credential to a value that must be refused. HTTP endpoints must be
// https (loopback http is allowed for tests); Active Directory's url keeps
// its own rule (ldaps://, or ldap:// with start_tls).
var endpointKeys = map[string]string{
	"base_url": "http://ghe.example.com",
	keyOrgURL:  "http://example.okta.com",
	"endpoint": "http://minio.example.com:9000",
	"url":      "ldap://dc.example.com",
}

// hostKeys maps every config key whose value becomes part of a request
// host to a value that would move the request, and its credential, to
// another host. Keys a cloud SDK validates or escapes are not here: the
// AWS SDK refuses a region that is not a host label and puts an unusual
// bucket in the path, azidentity validates tenant_id, and project,
// subscription and bucket names elsewhere go into escaped URL paths.
var hostKeys = map[string]string{
	"account": "evil.example/#",
}

// notHostKeys are keys that contain "account" but never form a host.
var notHostKeys = map[string]bool{
	"service_account_ous":    true,
	"target_service_account": true,
}

// hostKeyBackend is the extra config that makes a source use a host key
// (manual.pdf reads "account" only on the azure_blob backend).
var hostKeyBackend = map[string]map[string]any{
	"account": {"backend": "azure_blob", "container": "evidence"},
}

// Every registered source that builds a request host from a config value
// refuses a value that is not a bare host label. Like the endpoint test
// above, a key that looks host-forming and is not listed fails it.
func TestEverySourceRefusesHostInjection(t *testing.T) {
	setDummyAWSCredentials(t)
	checked := 0
	for _, id := range sources.IDs() {
		for _, key := range sources.ConfigKeys(id) {
			bad, isHost := hostKeys[key]
			if !isHost {
				if lower := strings.ToLower(key); (strings.Contains(lower, "account") || strings.Contains(lower, "domain")) && !notHostKeys[key] {
					t.Errorf("%s declares %q, which may form a host: add it to hostKeys or notHostKeys", id, key)
				}
				continue
			}
			checked++
			t.Run(id+"/"+key, func(t *testing.T) {
				cfg := routingBaseConfig()
				for k, v := range hostKeyBackend[key] {
					cfg[k] = v
				}
				cfg[key] = bad
				_, err := sources.Build(context.Background(), id, sources.Env{Config: cfg})
				if err == nil || !strings.Contains(err.Error(), key) {
					t.Fatalf("%s did not refuse %s %q by name; got %v", id, key, bad, err)
				}
			})
		}
	}
	if checked == 0 {
		t.Fatal("no source declares a host key; the registry was not populated")
	}
}

// routingBaseConfig is enough config for every factory that declares an
// endpoint or token_env key to get as far as resolving them, with no
// network call.
func routingBaseConfig() map[string]any {
	return map[string]any{
		"org":       "acme",
		"group":     "acme",
		keyToken:    dummyCred,
		keyAPIToken: dummyCred,
		keyOrgURL:   "https://example.okta.com",
		"url":       "ldaps://dc.example.com",
		"bind_dn":   "CN=svc,DC=example,DC=com",
		"base_dn":   "DC=example,DC=com",
		"backend":   "s3",
		"bucket":    "evidence",
		"region":    "us-east-1",
	}
}

// Every registered source that declares an endpoint key refuses a
// plaintext value for it. Deriving the cases from the registry means a
// new source, or a new endpoint key on an old one, is covered without
// editing this test; a URL-like key this test does not know fails it.
func TestEverySourceRefusesPlaintextEndpoints(t *testing.T) {
	setDummyAWSCredentials(t)
	checked := 0
	for _, id := range sources.IDs() {
		for _, key := range sources.ConfigKeys(id) {
			bad, isEndpoint := endpointKeys[key]
			if !isEndpoint {
				if lower := strings.ToLower(key); strings.Contains(lower, "url") || strings.Contains(lower, "endpoint") || strings.Contains(lower, "host") {
					t.Errorf("%s declares %q, which looks like an endpoint: add it to endpointKeys with a value it must refuse", id, key)
				}
				continue
			}
			checked++
			t.Run(id+"/"+key, func(t *testing.T) {
				cfg := routingBaseConfig()
				cfg[key] = bad
				_, err := sources.Build(context.Background(), id, sources.Env{Config: cfg})
				if err == nil {
					t.Fatalf("%s accepted %s: %s", id, key, bad)
				}
				scheme := bad[:strings.Index(bad, "://")+3]
				if !strings.Contains(err.Error(), bad) && !strings.Contains(err.Error(), key) && !strings.Contains(err.Error(), scheme) {
					t.Errorf("the error should name the key or value, so it is the endpoint that was refused: %v", err)
				}
			})
		}
	}
	if checked == 0 {
		t.Fatal("no source declares an endpoint key; the registry was not populated")
	}
}

// Every registered source that reads token_env refuses a name that holds
// a CI or cloud credential: the source would send it to its API host.
func TestEverySourceRefusesCredentialTokenEnv(t *testing.T) {
	setDummyAWSCredentials(t)
	const denied = "AWS_SECRET_ACCESS_KEY"
	checked := 0
	for _, id := range sources.IDs() {
		if !declares(id, "token_env") {
			continue
		}
		checked++
		t.Run(id, func(t *testing.T) {
			cfg := routingBaseConfig()
			// Remove literal credentials so token_env is what resolves.
			for _, k := range []string{keyToken, keyAPIToken, "bind_password"} {
				delete(cfg, k)
			}
			cfg["token_env"] = denied
			_, err := sources.Build(context.Background(), id, sources.Env{Config: cfg})
			if err == nil || !strings.Contains(err.Error(), denied) {
				t.Fatalf("%s accepted token_env %s; got %v", id, denied, err)
			}
		})
	}
	if checked == 0 {
		t.Fatal("no source declares token_env; the registry was not populated")
	}
}

func declares(id, key string) bool {
	for _, k := range sources.ConfigKeys(id) {
		if k == key {
			return true
		}
	}
	return false
}

// setDummyAWSCredentials lets AWS-backed factories (manual.pdf on s3)
// resolve credentials in-process, so a refusal comes from the endpoint
// or token check rather than from a missing credential.
func setDummyAWSCredentials(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}
