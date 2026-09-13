package activedirectory

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/sigcomply/sigcomply-cli/internal/sources"
)

// Config defaults and bounds.
const (
	// DefaultUserFilter selects human user objects. objectCategory=person
	// excludes computer accounts (which are also objectClass=user); managed
	// service accounts (msDS-GroupManagedServiceAccount) are not matched.
	DefaultUserFilter = "(&(objectCategory=person)(objectClass=user))"
	// DefaultPageSize is the paged-search page size. AD's MaxPageSize
	// default is 1000, so the configured value is clamped to 1..1000.
	DefaultPageSize = 500
	maxPageSize     = 1000
	// DefaultTimeout bounds the TCP dial and every LDAP request.
	DefaultTimeout = 30 * time.Second
	// BindPasswordEnv is the environment variable read when the
	// bind_password config key is absent.
	BindPasswordEnv = "SIGCOMPLY_AD_BIND_PASSWORD" //nolint:gosec // G101: env var name, not a credential
)

const (
	schemeLDAPS = "ldaps"
	schemeLDAP  = "ldap"
)

// Config is the validated plugin configuration. It is produced by
// parseConfig from the raw sources.active_directory map; every field is
// already checked, so the adapter never re-validates.
type Config struct {
	// Scheme is "ldaps" or "ldap" (the latter only with StartTLS).
	Scheme string
	// Addr is host:port (default port 636 for ldaps, 389 for ldap).
	Addr string
	// StartTLS upgrades an ldap:// connection before binding.
	StartTLS bool
	BindDN   string
	// BindPassword comes from the bind_password key or BindPasswordEnv.
	BindPassword string
	// BaseDN is the search base; empty means "read RootDSE
	// defaultNamingContext at collect time".
	BaseDN     string
	UserFilter string
	PageSize   uint32
	Timeout    time.Duration
	// TLS is the client TLS config: TLS 1.2+, RootCAs from ca_cert (nil =
	// system roots), ServerName from tls_server_name or the URL host.
	TLS *tls.Config
	// ServiceAccountOUs are parsed DNs; entries at or under any of them are
	// flagged is_service_account.
	ServiceAccountOUs []*ldap.DN
}

// parseConfig validates the raw source config map. It performs no network
// I/O (the factory never dials); the only side effects are reading the
// bind-password environment variable and the ca_cert file.
func parseConfig(m map[string]any) (*Config, error) {
	cfg := &Config{}
	steps := []func(map[string]any, *Config) error{
		parseURL,
		parseBind,
		parseSearch,
		parseTLS,
		parseServiceOUs,
	}
	for _, step := range steps {
		if err := step(m, cfg); err != nil {
			return nil, fmt.Errorf("active_directory: %w", err)
		}
	}
	return cfg, nil
}

func parseURL(m map[string]any, cfg *Config) error {
	raw, err := stringOpt(m, "url")
	if err != nil {
		return err
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("\"url\" required (ldaps://dc.example.com or ldap://… with start_tls: true)")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("\"url\": %w", err)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("\"url\" %q has no host", raw)
	}
	startTLS, err := boolOpt(m, "start_tls")
	if err != nil {
		return err
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	switch {
	case scheme == schemeLDAPS && startTLS:
		return fmt.Errorf("\"start_tls\" cannot be combined with an ldaps:// url (already TLS)")
	case scheme == schemeLDAPS:
		if port == "" {
			port = "636"
		}
	case scheme == schemeLDAP && !startTLS:
		return fmt.Errorf("plaintext ldap:// refused: use ldaps:// or set start_tls: true (the bind password would cross the network in clear text)")
	case scheme == schemeLDAP:
		if port == "" {
			port = "389"
		}
	default:
		return fmt.Errorf("\"url\" scheme %q unsupported (want ldaps or ldap)", u.Scheme)
	}
	cfg.Scheme = scheme
	cfg.StartTLS = startTLS
	cfg.Addr = net.JoinHostPort(u.Hostname(), port)
	return nil
}

func parseBind(m map[string]any, cfg *Config) error {
	bindDN, err := stringOpt(m, "bind_dn")
	if err != nil {
		return err
	}
	if bindDN == "" {
		return fmt.Errorf("\"bind_dn\" required")
	}
	password, err := stringOpt(m, "bind_password")
	if err != nil {
		return err
	}
	if password == "" {
		// ResolveToken honours token_env, so each [instance] of this
		// source can bind with its own password instead of sharing the
		// process-global SIGCOMPLY_AD_BIND_PASSWORD.
		password, err = sources.ResolveToken(m, SourceID, "bind_password", BindPasswordEnv)
		if err != nil {
			return fmt.Errorf("bind password required; anonymous/unauthenticated binds are refused: %w", err)
		}
	}
	cfg.BindDN = bindDN
	cfg.BindPassword = password
	return nil
}

func parseSearch(m map[string]any, cfg *Config) error {
	baseDN, err := stringOpt(m, "base_dn")
	if err != nil {
		return err
	}
	if baseDN != "" {
		if _, perr := ldap.ParseDN(baseDN); perr != nil {
			return fmt.Errorf("\"base_dn\" %q: %w", baseDN, perr)
		}
	}
	filter, err := stringOpt(m, "user_filter")
	if err != nil {
		return err
	}
	if filter == "" {
		filter = DefaultUserFilter
	}
	if _, ferr := ldap.CompileFilter(filter); ferr != nil {
		return fmt.Errorf("\"user_filter\" %q: %w", filter, ferr)
	}
	pageSize, err := intOpt(m, "page_size", DefaultPageSize)
	if err != nil {
		return err
	}
	timeout, err := durationOpt(m, "timeout", DefaultTimeout)
	if err != nil {
		return err
	}
	cfg.BaseDN = baseDN
	cfg.UserFilter = filter
	cfg.PageSize = clampPageSize(pageSize)
	cfg.Timeout = timeout
	return nil
}

// clampPageSize bounds n to 1..1000 before the uint32 conversion, so the
// conversion can never overflow (gosec G115).
func clampPageSize(n int) uint32 {
	switch {
	case n < 1:
		n = 1
	case n > maxPageSize:
		n = maxPageSize
	}
	return uint32(n) //nolint:gosec // G115: n is clamped to 1..1000 above
}

func parseTLS(m map[string]any, cfg *Config) error {
	serverName, err := stringOpt(m, "tls_server_name")
	if err != nil {
		return err
	}
	if serverName == "" {
		host, _, splitErr := net.SplitHostPort(cfg.Addr)
		if splitErr != nil {
			return fmt.Errorf("\"url\": %w", splitErr)
		}
		serverName = host
	}
	caPath, err := stringOpt(m, "ca_cert")
	if err != nil {
		return err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if caPath != "" {
		pool, perr := loadCAPool(caPath)
		if perr != nil {
			return perr
		}
		tc.RootCAs = pool
	}
	cfg.TLS = tc
	return nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("\"ca_cert\": %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("\"ca_cert\" %q: no PEM certificates found", path)
	}
	return pool, nil
}

func parseServiceOUs(m map[string]any, cfg *Config) error {
	ous, err := stringListOpt(m, "service_account_ous")
	if err != nil {
		return err
	}
	for _, ou := range ous {
		dn, perr := ldap.ParseDN(ou)
		if perr != nil || len(dn.RDNs) == 0 {
			return fmt.Errorf("\"service_account_ous\" entry %q is not a valid DN", ou)
		}
		cfg.ServiceAccountOUs = append(cfg.ServiceAccountOUs, dn)
	}
	return nil
}

// --- typed option readers ---------------------------------------------------
//
// Unlike sources.StringOpt these reject a wrongly-typed value instead of
// treating it as absent (e.g. start_tls: "yes" or page_size: "big"), so a
// mistyped setting is a config error (exit 3) rather than a silent default.

func stringOpt(m map[string]any, key string) (string, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%q must be a string, got %T", key, v)
	}
	// Not trimmed: a bind password may legitimately carry edge whitespace.
	return s, nil
}

func boolOpt(m map[string]any, key string) (bool, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%q must be a boolean, got %T", key, v)
	}
	return b, nil
}

func intOpt(m map[string]any, key string, def int) (int, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return def, nil
	}
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return clampInt64(n), nil
	case uint64:
		if n > math.MaxInt32 {
			return math.MaxInt32, nil
		}
		return int(n), nil
	case float64:
		if n != math.Trunc(n) {
			return 0, fmt.Errorf("%q must be an integer, got %v", key, n)
		}
		return clampInt64(int64(n)), nil
	default:
		return 0, fmt.Errorf("%q must be an integer, got %T", key, v)
	}
}

func clampInt64(n int64) int {
	switch {
	case n > math.MaxInt32:
		return math.MaxInt32
	case n < math.MinInt32:
		return math.MinInt32
	default:
		return int(n)
	}
}

// durationOpt accepts a Go duration string ("30s", "2m") or a whole number
// of seconds. The result must be positive.
func durationOpt(m map[string]any, key string, def time.Duration) (time.Duration, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return def, nil
	}
	var d time.Duration
	if s, isString := v.(string); isString {
		parsed, err := time.ParseDuration(strings.TrimSpace(s))
		if err != nil {
			return 0, fmt.Errorf("%q: %w", key, err)
		}
		d = parsed
	} else {
		secs, err := intOpt(m, key, 0)
		if err != nil {
			return 0, fmt.Errorf("%q must be a duration string (e.g. \"30s\") or whole seconds, got %T", key, v)
		}
		d = time.Duration(secs) * time.Second
	}
	if d <= 0 {
		return 0, fmt.Errorf("%q must be positive, got %v", key, d)
	}
	return d, nil
}

func stringListOpt(m map[string]any, key string) ([]string, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return nil, nil
	}
	switch list := v.(type) {
	case []string:
		return list, nil
	case []any:
		out := make([]string, 0, len(list))
		for i, item := range list {
			s, isString := item.(string)
			if !isString {
				return nil, fmt.Errorf("%q[%d] must be a string, got %T", key, i, item)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%q must be a list of strings, got %T", key, v)
	}
}
