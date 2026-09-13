package activedirectory

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// fakedc_test.go is the L2 stand-in for the active_directory plugin. AD
// speaks LDAP (BER over TCP), not HTTP, so there is no go-vcr cassette and
// no vendor OpenAPI contract. Instead this scripted responder decodes the
// client's real BER requests and answers them the way a domain controller
// does — simple bind, RootDSE read, and a simple-paged-results search —
// so the production adapter (ldapDirectory: bind, RootDSE fallback, paging
// cookie loop, go-ldap's decoder of binary objectGUID values) runs
// unmodified. Only the transport is swapped: net.Pipe via the dial seam, or
// a loopback TLS listener for the ldaps:// / StartTLS paths.

// LDAP protocolOp application tags (RFC 4511).
const (
	opBindRequest     = 0
	opBindResponse    = 1
	opUnbindRequest   = 2
	opSearchRequest   = 3
	opSearchEntry     = 4
	opSearchDone      = 5
	opAbandonRequest  = 16
	opExtendedRequest = 23
	opExtendedResp    = 24
)

const (
	resultSuccess            = 0
	resultOperationsError    = 1
	resultInvalidCredentials = 49
	startTLSOID              = "1.3.6.1.4.1.1466.20037"
	fakeNamingContext        = "DC=corp,DC=example,DC=com"
	fakeBindDN               = "CN=svc-sigcomply,OU=Service Accounts,DC=corp,DC=example,DC=com"
	fakeBindPassword         = "Passw0rd!Test"
	fakeCookiePrefix         = "page-"
	fakeServerName           = "dc01.corp.example.com"
	fakeServiceAccountsOU    = "OU=Service Accounts,DC=corp,DC=example,DC=com"
)

// fakeAttr is one attribute with its raw values, kept ordered so the wire
// bytes are deterministic.
type fakeAttr struct {
	name string
	vals []string
}

type fakeUser struct {
	dn    string
	attrs []fakeAttr
}

// fakeDC is a scripted domain controller. pages[i] is served for the i-th
// paged search request; the cookie handed out after page i is "page-<i+1>"
// and must come back verbatim on the next request.
type fakeDC struct {
	pages [][]fakeUser
	// stallOnPage, when > 0, makes the server swallow that page's request
	// without answering (to exercise ctx cancellation).
	stallOnPage int
	// startTLS, when set, is the server TLS config used after a StartTLS
	// extended request.
	startTLS *tls.Config
	// stalled is closed when the stalled page request arrives.
	stalled chan struct{}

	mu       sync.Mutex
	errs     []error
	binds    int
	rootDSE  int
	searches []fakeSearch
}

type fakeSearch struct {
	base, filter string
	cookie       string
	pageSize     uint32
	attrs        []string
}

func (s *fakeDC) failf(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errs = append(s.errs, fmt.Errorf(format, args...))
}

// check reports protocol violations the responder observed.
func (s *fakeDC) check(t *testing.T) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, err := range s.errs {
		t.Error(err)
	}
}

// pipeDial returns a dial seam that connects the adapter to this responder
// over an in-memory pipe (a fresh responder goroutine per dial).
func (s *fakeDC) pipeDial() func(context.Context, *Config) (*ldap.Conn, error) {
	return func(context.Context, *Config) (*ldap.Conn, error) {
		client, server := net.Pipe()
		go s.serve(server)
		conn := ldap.NewConn(client, false)
		conn.Start()
		return conn, nil
	}
}

// listen serves the responder on a loopback TCP listener, optionally
// wrapped in TLS (ldaps://). It returns host:port.
func (s *fakeDC) listen(t *testing.T, tlsCfg *tls.Config) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	t.Cleanup(func() { _ = ln.Close() }) //nolint:errcheck // test cleanup
	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return ln.Addr().String()
}

func (s *fakeDC) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }() //nolint:errcheck // test responder
	for {
		packet, err := ber.ReadPacket(conn)
		if err != nil {
			// EOF / closed pipe when the client hangs up; handshake failures in
			// the negative TLS tests are asserted on the client side.
			return
		}
		next, ok := s.handle(conn, packet)
		if !ok {
			return
		}
		conn = next
	}
}

// handle answers one request. It returns the connection to continue on
// (replaced by a TLS server conn after StartTLS) and false to hang up.
func (s *fakeDC) handle(conn net.Conn, packet *ber.Packet) (net.Conn, bool) {
	if len(packet.Children) < 2 {
		s.failf("malformed LDAPMessage: %d children", len(packet.Children))
		return conn, false
	}
	msgID, _ := packet.Children[0].Value.(int64) //nolint:errcheck // test responder: zero id surfaces as client error
	op := packet.Children[1]
	switch op.Tag {
	case opBindRequest:
		if _, isTLS := conn.(*tls.Conn); s.startTLS != nil && !isTLS {
			s.failf("bind received before StartTLS completed")
		}
		return conn, s.write(conn, s.bindResponse(msgID, op))
	case opSearchRequest:
		return conn, s.search(conn, msgID, packet)
	case opExtendedRequest:
		return s.extended(conn, msgID, op)
	case opUnbindRequest:
		return conn, false
	case opAbandonRequest:
		return conn, true
	default:
		s.failf("unexpected protocolOp tag %d", op.Tag)
		return conn, false
	}
}

func (s *fakeDC) bindResponse(msgID int64, op *ber.Packet) *ber.Packet {
	s.mu.Lock()
	s.binds++
	s.mu.Unlock()
	name, _ := op.Children[1].Value.(string) //nolint:errcheck // absent → "" → invalid credentials
	password := op.Children[2].Data.String()
	if name != fakeBindDN || password != fakeBindPassword {
		return envelope(msgID, ldapResult(opBindResponse, resultInvalidCredentials, "80090308: LdapErr: DSID-0C09044E, AcceptSecurityContext error, data 52e"))
	}
	return envelope(msgID, ldapResult(opBindResponse, resultSuccess, ""))
}

func (s *fakeDC) extended(conn net.Conn, msgID int64, op *ber.Packet) (net.Conn, bool) {
	oid := ""
	if len(op.Children) > 0 {
		oid = op.Children[0].Data.String()
	}
	if oid != startTLSOID || s.startTLS == nil {
		s.failf("unexpected extended request %q", oid)
		return conn, s.write(conn, envelope(msgID, ldapResult(opExtendedResp, resultOperationsError, "unsupported")))
	}
	if !s.write(conn, envelope(msgID, ldapResult(opExtendedResp, resultSuccess, ""))) {
		return conn, false
	}
	return tls.Server(conn, s.startTLS), true
}

func (s *fakeDC) search(conn net.Conn, msgID int64, packet *ber.Packet) bool {
	op := packet.Children[1]
	if len(op.Children) < 8 {
		s.failf("search request has %d children, want 8", len(op.Children))
		return false
	}
	base, _ := op.Children[0].Value.(string) //nolint:errcheck // test responder
	scope, _ := op.Children[1].Value.(int64) //nolint:errcheck // test responder
	if base == "" && scope == int64(ldap.ScopeBaseObject) {
		s.mu.Lock()
		s.rootDSE++
		s.mu.Unlock()
		root := fakeUser{dn: "", attrs: []fakeAttr{{"defaultNamingContext", []string{fakeNamingContext}}}}
		return s.write(conn, envelope(msgID, entryOp(root))) &&
			s.write(conn, envelope(msgID, ldapResult(opSearchDone, resultSuccess, "")))
	}
	req := decodeSearch(op, packet)
	s.mu.Lock()
	s.searches = append(s.searches, req)
	s.mu.Unlock()
	return s.servePage(conn, msgID, &req)
}

func decodeSearch(op, packet *ber.Packet) fakeSearch {
	req := fakeSearch{}
	req.base, _ = op.Children[0].Value.(string)          //nolint:errcheck // test responder
	req.filter, _ = ldap.DecompileFilter(op.Children[6]) //nolint:errcheck // mismatch asserted by caller
	for _, a := range op.Children[7].Children {
		if name, ok := a.Value.(string); ok {
			req.attrs = append(req.attrs, name)
		}
	}
	if len(packet.Children) > 2 {
		for _, c := range packet.Children[2].Children {
			if pc, ok := decodeControl(c).(*ldap.ControlPaging); ok {
				req.cookie = string(pc.Cookie)
				req.pageSize = pc.PagingSize
			}
		}
	}
	return req
}

func decodeControl(c *ber.Packet) ldap.Control {
	ctl, err := ldap.DecodeControl(c)
	if err != nil {
		return nil
	}
	return ctl
}

func (s *fakeDC) servePage(conn net.Conn, msgID int64, req *fakeSearch) bool {
	page := 0
	if req.cookie != "" {
		n, err := strconv.Atoi(strings.TrimPrefix(req.cookie, fakeCookiePrefix))
		if err != nil || !strings.HasPrefix(req.cookie, fakeCookiePrefix) || n < 1 || n >= len(s.pages) {
			s.failf("unknown paging cookie %q", req.cookie)
			return s.write(conn, envelope(msgID, ldapResult(opSearchDone, resultOperationsError, "bad cookie")))
		}
		page = n
	}
	if s.stallOnPage > 0 && page+1 == s.stallOnPage {
		close(s.stalled)
		return true // swallow the request; the client must give up via ctx
	}
	for _, u := range s.pages[page] {
		if !s.write(conn, envelope(msgID, entryOp(u))) {
			return false
		}
	}
	next := ""
	if page+1 < len(s.pages) {
		next = fakeCookiePrefix + strconv.Itoa(page+1)
	}
	resp := &ldap.ControlPaging{Cookie: []byte(next)}
	return s.write(conn, envelope(msgID, ldapResult(opSearchDone, resultSuccess, ""), resp))
}

func (s *fakeDC) write(conn net.Conn, p *ber.Packet) bool {
	if _, err := conn.Write(p.Bytes()); err != nil {
		return false // client hung up (e.g. canceled); not a protocol error
	}
	return true
}

func envelope(msgID int64, op *ber.Packet, controls ...ldap.Control) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "messageID"))
	p.AppendChild(op)
	if len(controls) > 0 {
		ctls := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "controls")
		for _, c := range controls {
			ctls.AppendChild(c.Encode())
		}
		p.AppendChild(ctls)
	}
	return p
}

func ldapResult(tag ber.Tag, code int64, diag string) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "LDAPResult")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diag, "diagnosticMessage"))
	return op
}

func entryOp(u fakeUser) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, opSearchEntry, nil, "SearchResultEntry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, u.dn, "objectName"))
	list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for _, a := range u.attrs {
		pa := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
		pa.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.name, "type"))
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		for _, v := range a.vals {
			vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "value"))
		}
		pa.AppendChild(vals)
		list.AppendChild(pa)
	}
	op.AppendChild(list)
	return op
}
