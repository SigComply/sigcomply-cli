package activedirectory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

func baseConfig() map[string]any {
	return map[string]any{
		"url":           "ldaps://dc01.corp.example.com",
		"bind_dn":       "CN=svc-sigcomply,OU=Service Accounts,DC=corp,DC=example,DC=com",
		"bind_password": "test-password",
	}
}

func withKeys(kv map[string]any) map[string]any {
	m := baseConfig()
	for k, v := range kv {
		if v == nil {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	return m
}

func TestParseConfigDefaults(t *testing.T) {
	t.Setenv(BindPasswordEnv, "")
	cfg, err := parseConfig(baseConfig())
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case cfg.Scheme != schemeLDAPS || cfg.Addr != "dc01.corp.example.com:636" || cfg.StartTLS:
		t.Errorf("transport = %s %s start_tls=%v", cfg.Scheme, cfg.Addr, cfg.StartTLS)
	case cfg.BaseDN != "":
		t.Errorf("base_dn = %q, want empty (RootDSE fallback)", cfg.BaseDN)
	case cfg.UserFilter != DefaultUserFilter:
		t.Errorf("user_filter = %q", cfg.UserFilter)
	case cfg.PageSize != DefaultPageSize:
		t.Errorf("page_size = %d", cfg.PageSize)
	case cfg.Timeout != DefaultTimeout:
		t.Errorf("timeout = %v", cfg.Timeout)
	}
	if cfg.TLS.MinVersion != tls.VersionTLS12 || cfg.TLS.ServerName != "dc01.corp.example.com" ||
		cfg.TLS.RootCAs != nil || cfg.TLS.InsecureSkipVerify {
		t.Errorf("tls = min %x server %q roots %v insecure %v",
			cfg.TLS.MinVersion, cfg.TLS.ServerName, cfg.TLS.RootCAs, cfg.TLS.InsecureSkipVerify)
	}
}

func TestParseConfigOverrides(t *testing.T) {
	t.Setenv(BindPasswordEnv, "")
	caPath := writeTestCA(t)
	cfg, err := parseConfig(withKeys(map[string]any{
		"url":                 "ldap://10.0.0.5:3268",
		"start_tls":           true,
		"base_dn":             "OU=Staff,DC=corp,DC=example,DC=com",
		"user_filter":         "(objectClass=user)",
		"page_size":           250,
		"timeout":             "5s",
		"ca_cert":             caPath,
		"tls_server_name":     "dc01.corp.example.com",
		"service_account_ous": []any{"OU=Service Accounts,DC=corp,DC=example,DC=com"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scheme != schemeLDAP || !cfg.StartTLS || cfg.Addr != "10.0.0.5:3268" {
		t.Errorf("transport = %s %s start_tls=%v", cfg.Scheme, cfg.Addr, cfg.StartTLS)
	}
	if cfg.BaseDN != "OU=Staff,DC=corp,DC=example,DC=com" || cfg.UserFilter != "(objectClass=user)" ||
		cfg.PageSize != 250 || cfg.Timeout != 5*time.Second {
		t.Errorf("search = %q %q %d %v", cfg.BaseDN, cfg.UserFilter, cfg.PageSize, cfg.Timeout)
	}
	if cfg.TLS.ServerName != "dc01.corp.example.com" || cfg.TLS.RootCAs == nil {
		t.Errorf("tls server %q roots %v", cfg.TLS.ServerName, cfg.TLS.RootCAs)
	}
	if len(cfg.ServiceAccountOUs) != 1 {
		t.Errorf("service_account_ous = %v", cfg.ServiceAccountOUs)
	}
	if cfg2, err := parseConfig(withKeys(map[string]any{"url": "ldap://dc01", "start_tls": true})); err != nil || cfg2.Addr != "dc01:389" {
		t.Errorf("ldap default port: cfg=%+v err=%v", cfg2, err)
	}
}

func TestParseConfigPasswordFromEnv(t *testing.T) {
	t.Setenv(BindPasswordEnv, "from-env")
	cfg, err := parseConfig(withKeys(map[string]any{"bind_password": nil}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BindPassword != "from-env" {
		t.Errorf("password = %q, want env value", cfg.BindPassword)
	}
	cfg, err = parseConfig(baseConfig())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BindPassword != "test-password" {
		t.Errorf("config key must win over env, got %q", cfg.BindPassword)
	}
}

func TestPageSizeClamp(t *testing.T) {
	t.Setenv(BindPasswordEnv, "")
	cases := []struct {
		in   any
		want uint32
	}{
		{0, 1}, {-7, 1}, {1, 1}, {1000, 1000}, {5000, 1000},
		{int64(1) << 40, 1000}, {uint64(1) << 63, 1000}, {float64(20), 20},
	}
	for _, tc := range cases {
		cfg, err := parseConfig(withKeys(map[string]any{"page_size": tc.in}))
		if err != nil {
			t.Errorf("page_size %v: %v", tc.in, err)
			continue
		}
		if cfg.PageSize != tc.want {
			t.Errorf("page_size %v → %d, want %d", tc.in, cfg.PageSize, tc.want)
		}
	}
}

func TestTimeoutForms(t *testing.T) {
	t.Setenv(BindPasswordEnv, "")
	for in, want := range map[any]time.Duration{"2m": 2 * time.Minute, 45: 45 * time.Second} {
		cfg, err := parseConfig(withKeys(map[string]any{"timeout": in}))
		if err != nil || cfg.Timeout != want {
			t.Errorf("timeout %v → %v (err %v), want %v", in, cfg, err, want)
		}
	}
}

func TestParseConfigErrors(t *testing.T) {
	t.Setenv(BindPasswordEnv, "")
	missingCA := filepath.Join(t.TempDir(), "nope.pem")
	notPEM := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		cfg  map[string]any
		want string
	}{
		{"missing url", withKeys(map[string]any{"url": nil}), `"url" required`},
		{"url wrong type", withKeys(map[string]any{"url": 5}), "must be a string"},
		{"no host", withKeys(map[string]any{"url": "ldaps://"}), "no host"},
		{"plaintext ldap", withKeys(map[string]any{"url": "ldap://dc01.corp.example.com"}), "plaintext ldap:// refused"},
		{"plaintext ldap start_tls false", withKeys(map[string]any{"url": "ldap://dc01", "start_tls": false}), "plaintext"},
		{"ldaps plus start_tls", withKeys(map[string]any{"start_tls": true}), "cannot be combined"},
		{"unsupported scheme", withKeys(map[string]any{"url": "https://dc01"}), "unsupported"},
		{"start_tls wrong type", withKeys(map[string]any{"url": "ldap://dc01", "start_tls": "yes"}), "must be a boolean"},
		{"missing bind_dn", withKeys(map[string]any{"bind_dn": nil}), `"bind_dn" required`},
		{"missing password", withKeys(map[string]any{"bind_password": nil}), "bind password required"},
		{"empty password", withKeys(map[string]any{"bind_password": ""}), "bind password required"},
		{"bad base_dn", withKeys(map[string]any{"base_dn": "not a dn"}), `"base_dn"`},
		{"bad filter", withKeys(map[string]any{"user_filter": "(objectClass=user"}), `"user_filter"`},
		{"page_size wrong type", withKeys(map[string]any{"page_size": "big"}), "must be an integer"},
		{"page_size fractional", withKeys(map[string]any{"page_size": 1.5}), "must be an integer"},
		{"timeout garbage", withKeys(map[string]any{"timeout": "soon"}), `"timeout"`},
		{"timeout zero", withKeys(map[string]any{"timeout": "0s"}), "must be positive"},
		{"timeout wrong type", withKeys(map[string]any{"timeout": true}), "duration string"},
		{"ca_cert missing file", withKeys(map[string]any{"ca_cert": missingCA}), `"ca_cert"`},
		{"ca_cert not PEM", withKeys(map[string]any{"ca_cert": notPEM}), "no PEM certificates"},
		{"service OUs wrong type", withKeys(map[string]any{"service_account_ous": "OU=x"}), "list of strings"},
		{"service OU item wrong type", withKeys(map[string]any{"service_account_ous": []any{1}}), "must be a string"},
		{"service OU invalid", withKeys(map[string]any{"service_account_ous": []any{"garbage"}}), "not a valid DN"},
	}
	for _, tc := range cases {
		_, err := parseConfig(tc.cfg)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want containing %q", tc.name, err, tc.want)
			continue
		}
		if !strings.HasPrefix(err.Error(), "active_directory: ") {
			t.Errorf("%s: err %q lacks source prefix", tc.name, err)
		}
		if strings.Contains(err.Error(), "test-password") {
			t.Errorf("%s: error leaks the bind password: %v", tc.name, err)
		}
	}
}

// TestFactoryNeverDials builds the plugin through the registry against an
// unroutable address: construction must succeed without any network I/O.
func TestFactoryNeverDials(t *testing.T) {
	t.Setenv(BindPasswordEnv, "")
	p, err := sources.Build(context.Background(), SourceID, sources.Env{Config: withKeys(map[string]any{
		"url": "ldaps://192.0.2.1:636", // TEST-NET-1: never answers
	})})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID() != SourceID || len(p.Emits()) != 1 || p.Emits()[0] != EvidenceTypeRosterEntry {
		t.Errorf("plugin id=%q emits=%v", p.ID(), p.Emits())
	}
	if _, err := sources.Build(context.Background(), SourceID, sources.Env{Config: map[string]any{}}); err == nil {
		t.Error("empty config must fail at build time")
	}
}

// writeTestCA writes a throwaway self-signed CA certificate to a temp file
// and returns its path.
func writeTestCA(t *testing.T) string {
	t.Helper()
	certPEM, _ := newTestCert(t, "Test CA", nil)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// newTestCert creates a self-signed certificate valid for dnsNames and
// returns its PEM plus a tls.Certificate for serving.
func newTestCert(t *testing.T, cn string, dnsNames []string) ([]byte, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, pair
}
