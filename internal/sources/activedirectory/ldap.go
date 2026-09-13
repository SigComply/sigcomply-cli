package activedirectory

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/go-ldap/ldap/v3"
)

// ldapDirectory is the production Directory: one connection per
// ListUsers call — dial (TLS), simple bind, optional RootDSE read for the
// base DN, then a manual paged search.
type ldapDirectory struct {
	cfg *Config
	// dial opens an established (TLS, started) connection. It is a seam so
	// the L2 stand-in test can substitute an in-memory pipe while the bind,
	// RootDSE and paging code below stays real.
	dial func(ctx context.Context, cfg *Config) (*ldap.Conn, error)
}

func newLDAPDirectory(cfg *Config) *ldapDirectory {
	return &ldapDirectory{cfg: cfg, dial: dialLDAP}
}

// ListUsers implements Directory.
func (d *ldapDirectory) ListUsers(ctx context.Context) ([]*ldap.Entry, error) {
	conn, err := d.dial(ctx, d.cfg)
	if err != nil {
		return nil, err
	}
	// Close the connection as soon as ctx is canceled so a blocked request
	// returns promptly; the deferred Close is idempotent.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() }) //nolint:errcheck // best-effort close on cancel
	defer stop()
	defer func() { _ = conn.Close() }() //nolint:errcheck // best-effort close
	conn.SetTimeout(d.cfg.Timeout)

	if err := conn.Bind(d.cfg.BindDN, d.cfg.BindPassword); err != nil {
		return nil, ctxOr(ctx, fmt.Errorf("bind as %q: %w", d.cfg.BindDN, err))
	}
	baseDN := d.cfg.BaseDN
	if baseDN == "" {
		baseDN, err = defaultNamingContext(conn)
		if err != nil {
			return nil, ctxOr(ctx, err)
		}
	}
	return pagedSearch(ctx, conn, d.searchRequest(baseDN))
}

func (d *ldapDirectory) searchRequest(baseDN string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		d.cfg.UserFilter, userAttributes,
		[]ldap.Control{ldap.NewControlPaging(d.cfg.PageSize)},
	)
}

// defaultNamingContext reads the RootDSE's defaultNamingContext — the
// domain's root DN — used when base_dn is not configured.
func defaultNamingContext(conn *ldap.Conn) (string, error) {
	req := ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"defaultNamingContext"}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("read RootDSE: %w", err)
	}
	for _, e := range res.Entries {
		if v := attr(e, "defaultNamingContext"); v != "" {
			return v, nil
		}
	}
	return "", errors.New("RootDSE has no defaultNamingContext; set base_dn")
}

// pagedSearch runs the search with the simple paged results control
// (1.2.840.113556.1.4.319), re-issuing it with the server's cookie until
// the cookie comes back empty. ctx is checked after every page.
func pagedSearch(ctx context.Context, conn *ldap.Conn, req *ldap.SearchRequest) ([]*ldap.Entry, error) {
	paging, ok := ldap.FindControl(req.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
	if !ok {
		return nil, errors.New("search request carries no paging control")
	}
	var entries []*ldap.Entry
	for page := 1; ; page++ {
		res, err := conn.Search(req)
		if err != nil {
			return nil, ctxOr(ctx, fmt.Errorf("search %q page %d: %w", req.BaseDN, page, err))
		}
		entries = append(entries, res.Entries...)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cookie := responseCookie(res)
		if len(cookie) == 0 {
			return entries, nil
		}
		paging.SetCookie(cookie)
	}
}

// responseCookie extracts the paging cookie from a search result; nil when
// the server returned no paging control (a server that ignores paging
// returns everything in one response).
func responseCookie(res *ldap.SearchResult) []byte {
	if pc, ok := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging); ok {
		return pc.Cookie
	}
	return nil
}

// ctxOr prefers the context's error when ctx is done: a cancellation closes
// the connection, and the resulting network error would hide the cause.
func ctxOr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}

// dialLDAP opens a TCP connection bounded by cfg.Timeout, then either wraps
// it in TLS (ldaps://) or issues StartTLS (ldap:// + start_tls). Plaintext
// never reaches this point: parseConfig refuses it.
func dialLDAP(ctx context.Context, cfg *Config) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	raw, err := dialer.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.Addr, err)
	}
	if cfg.Scheme == schemeLDAPS {
		return startLDAPS(ctx, raw, cfg)
	}
	conn := ldap.NewConn(raw, false)
	conn.Start()
	conn.SetTimeout(cfg.Timeout)
	if err := conn.StartTLS(cfg.TLS); err != nil {
		_ = conn.Close() //nolint:errcheck // best-effort close after failed StartTLS
		return nil, ctxOr(ctx, fmt.Errorf("start_tls with %s: %w", cfg.Addr, err))
	}
	return conn, nil
}

func startLDAPS(ctx context.Context, raw net.Conn, cfg *Config) (*ldap.Conn, error) {
	tlsConn := tls.Client(raw, cfg.TLS)
	hsCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		_ = raw.Close() //nolint:errcheck // best-effort close after failed handshake
		return nil, ctxOr(ctx, fmt.Errorf("tls handshake with %s: %w", cfg.Addr, err))
	}
	conn := ldap.NewConn(tlsConn, true)
	conn.Start()
	return conn, nil
}
