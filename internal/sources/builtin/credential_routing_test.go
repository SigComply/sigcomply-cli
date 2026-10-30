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
