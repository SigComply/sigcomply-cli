package activedirectory

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

// activedirectory_conformance_test.go drives the REAL LDAP adapter against
// the scripted fakeDC (fakedc_test.go) — the L2 stand-in for a source with
// no HTTP cassette — and runs the shared sourcetest conformance harness
// over it.

var standInNow = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

// Binary objectGUIDs (bytes ≥ 0x80 on purpose: not valid UTF-8, so a
// decoder that string-mangles them would change the ID).
var (
	guidJane   = knownGUIDBytes
	guidBob    = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	guidCarol  = []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00}
	guidSQL    = []byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	guidBackup = []byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
)

// standInPages is a two-page directory: page 1 carries an active employee
// and a disabled contractor; page 2 an expired employee, an SPN service
// account and a service account identified only by its OU.
func standInPages() [][]fakeUser {
	never := "9223372036854775807"
	return [][]fakeUser{
		{
			{dn: "CN=Jane Doe,OU=Staff,DC=corp,DC=example,DC=com", attrs: []fakeAttr{
				{attrObjectGUID, []string{string(guidJane)}},
				{attrSAMAccountName, []string{"jdoe"}},
				{attrUserPrincipalName, []string{"jdoe@corp.example.com"}},
				{attrMail, []string{"Jane.Doe@corp.example.com"}},
				{attrDisplayName, []string{"Jane Doe"}},
				{attrUserAccountControl, []string{"512"}},
				{attrAccountExpires, []string{"0"}},
				{attrEmployeeID, []string{"1001"}},
				{attrEmployeeType, []string{"employee"}},
			}},
			{dn: "CN=Bob Smith,OU=Contractors,DC=corp,DC=example,DC=com", attrs: []fakeAttr{
				{"OBJECTGUID", []string{string(guidBob)}}, // server echoes a different case
				{attrSAMAccountName, []string{"bsmith"}},
				{attrProxyAddresses, []string{"smtp:bob.alias@corp.example.com", "SMTP:bob.smith@corp.example.com"}},
				{attrGivenName, []string{"Bob"}},
				{attrSn, []string{"Smith"}},
				{attrUserAccountControl, []string{"514"}},
				{attrAccountExpires, []string{never}},
				{attrEmployeeNumber, []string{"C-2002"}},
				{attrEmployeeType, []string{"contractor"}},
			}},
		},
		{
			{dn: "CN=Carol White,OU=Staff,DC=corp,DC=example,DC=com", attrs: []fakeAttr{
				{attrObjectGUID, []string{string(guidCarol)}},
				{attrSAMAccountName, []string{"cwhite"}},
				{attrUserPrincipalName, []string{"cwhite@corp.example.com"}},
				{attrUserAccountControl, []string{"512"}},
				{attrAccountExpires, []string{"134247456000000000"}}, // 2026-06-01, before standInNow
				{attrEmployeeID, []string{"1003"}},
				{attrEmployeeType, []string{"employee"}},
			}},
			{dn: "CN=svc-sql,CN=Users,DC=corp,DC=example,DC=com", attrs: []fakeAttr{
				{attrObjectGUID, []string{string(guidSQL)}},
				{attrSAMAccountName, []string{"svc-sql"}},
				{attrUserPrincipalName, []string{"svc-sql@corp.example.com"}},
				{attrUserAccountControl, []string{"66048"}},
				{attrServicePrincipalName, []string{"MSSQLSvc/db01.corp.example.com:1433"}},
			}},
			{dn: "CN=svc-backup,OU=Service Accounts,DC=corp,DC=example,DC=com", attrs: []fakeAttr{
				{attrObjectGUID, []string{string(guidBackup)}},
				{attrSAMAccountName, []string{"svc-backup"}},
				{attrUserPrincipalName, []string{"svc-backup@corp.example.com"}},
				{attrDisplayName, []string{"Backup Service"}},
				{attrUserAccountControl, []string{"512"}},
				{attrAccountExpires, []string{never}},
			}},
		},
	}
}

// standInWant is the expected roster_entry set, keyed by ID.
var standInWant = map[string]rosterPayload{
	"6f9619ff-8b86-d011-b42d-00c04fc964ff": {ID: "6f9619ff-8b86-d011-b42d-00c04fc964ff", Status: "active",
		Email: "Jane.Doe@corp.example.com", DisplayName: "Jane Doe", EmployeeID: "1001", EmployeeType: "employee", SourceStatus: "enabled"},
	"33221100-5544-7766-8899-aabbccddeeff": {ID: "33221100-5544-7766-8899-aabbccddeeff", Status: "inactive",
		Email: "bob.smith@corp.example.com", DisplayName: "Bob Smith", EmployeeID: "C-2002", EmployeeType: "contractor", SourceStatus: "disabled"},
	"ccddeeff-aabb-8899-7766-554433221100": {ID: "ccddeeff-aabb-8899-7766-554433221100", Status: "inactive",
		Email: "cwhite@corp.example.com", DisplayName: "cwhite", EmployeeID: "1003", EmployeeType: "employee", SourceStatus: "expired"},
	"76543210-ba98-fedc-0123-456789abcdef": {ID: "76543210-ba98-fedc-0123-456789abcdef", Status: "active",
		Email: "svc-sql@corp.example.com", DisplayName: "svc-sql", IsServiceAccount: true, SourceStatus: "enabled"},
	"00000080-0000-0000-0000-000000000001": {ID: "00000080-0000-0000-0000-000000000001", Status: "active",
		Email: "svc-backup@corp.example.com", DisplayName: "Backup Service", IsServiceAccount: true, SourceStatus: "enabled"},
}

// standInConfig is the raw source config the stand-in tests start from.
func standInConfig(extra map[string]any) map[string]any {
	m := map[string]any{
		"url":                 "ldaps://" + fakeServerName,
		"bind_dn":             fakeBindDN,
		"bind_password":       fakeBindPassword,
		"page_size":           2,
		"service_account_ous": []any{fakeServiceAccountsOU},
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// newStandInPlugin builds the plugin from raw config exactly as the
// factory does, pinning the clock and (when dc is non-nil) swapping only
// the transport for the in-memory pipe.
func newStandInPlugin(t *testing.T, raw map[string]any, dc *fakeDC) *Plugin {
	t.Helper()
	t.Setenv(BindPasswordEnv, "")
	cfg, err := parseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	p := NewFromConfig(cfg)
	p.now = func() time.Time { return standInNow }
	if dc != nil {
		dir, ok := p.dir.(*ldapDirectory)
		if !ok {
			t.Fatalf("NewFromConfig directory is %T, want *ldapDirectory", p.dir)
		}
		dir.dial = dc.pipeDial()
	}
	return p
}

func decodeRoster(t *testing.T, recs []core.EvidenceRecord) map[string]rosterPayload {
	t.Helper()
	got := map[string]rosterPayload{}
	for i := range recs {
		var p rosterPayload
		if err := json.Unmarshal(recs[i].Payload, &p); err != nil {
			t.Fatalf("record %s: %v", recs[i].ID, err)
		}
		if p.ID != recs[i].ID {
			t.Errorf("record ID %q != payload id %q", recs[i].ID, p.ID)
		}
		if wantKey := strings.ToLower(p.Email); recs[i].IdentityKey != wantKey {
			t.Errorf("record %s identity key %q, want lowercased email", recs[i].ID, recs[i].IdentityKey)
		}
		got[p.ID] = p
	}
	return got
}

func TestStandInPagedCollect(t *testing.T) {
	dc := &fakeDC{pages: standInPages()}
	p := newStandInPlugin(t, standInConfig(nil), dc)

	recs, err := p.Collect(context.Background(), rosterReq)
	if err != nil {
		t.Fatal(err)
	}
	dc.check(t)
	if got := decodeRoster(t, recs); !reflect.DeepEqual(got, standInWant) {
		t.Errorf("roster mismatch\n got: %+v\nwant: %+v", got, standInWant)
	}

	dc.mu.Lock()
	defer dc.mu.Unlock()
	if dc.binds != 1 || dc.rootDSE != 1 {
		t.Errorf("binds=%d rootDSE=%d, want 1 and 1 (base_dn unset → RootDSE fallback)", dc.binds, dc.rootDSE)
	}
	if len(dc.searches) != 2 {
		t.Fatalf("paged searches = %d, want 2", len(dc.searches))
	}
	for i, s := range dc.searches {
		if s.base != fakeNamingContext || s.filter != DefaultUserFilter || s.pageSize != 2 {
			t.Errorf("search %d: base=%q filter=%q pageSize=%d", i, s.base, s.filter, s.pageSize)
		}
		if !reflect.DeepEqual(s.attrs, userAttributes) {
			t.Errorf("search %d attrs = %v, want %v", i, s.attrs, userAttributes)
		}
	}
	if dc.searches[0].cookie != "" || dc.searches[1].cookie != "page-1" {
		t.Errorf("cookies = %q, %q; want \"\" then the server's \"page-1\"", dc.searches[0].cookie, dc.searches[1].cookie)
	}
}

func TestStandInConformance(t *testing.T) {
	dc := &fakeDC{pages: standInPages()}
	p := newStandInPlugin(t, standInConfig(nil), dc)
	recs := sourcetest.RunConformance(t, &sourcetest.Options{
		Plugin:        p,
		Request:       rosterReq,
		EvidenceTypes: sourcetest.BuiltinEvidenceTypes(t),
		// Service accounts in the fixture carry no employee attributes, which
		// is normal in AD; the mapper omits the keys rather than emitting "".
		OptionalFields: []string{"roster_entry.employee_id", "roster_entry.employee_type"},
	})
	dc.check(t)
	if len(recs) != len(standInWant) {
		t.Errorf("records = %d, want %d", len(recs), len(standInWant))
	}
}

func TestStandInConfiguredBaseDNSkipsRootDSE(t *testing.T) {
	pages := standInPages()
	dc := &fakeDC{pages: pages}
	base := "OU=Staff,DC=corp,DC=example,DC=com"
	p := newStandInPlugin(t, standInConfig(map[string]any{"base_dn": base, "user_filter": "(objectClass=user)"}), dc)
	if _, err := p.Collect(context.Background(), rosterReq); err != nil {
		t.Fatal(err)
	}
	dc.check(t)
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if dc.rootDSE != 0 {
		t.Errorf("rootDSE reads = %d, want 0 when base_dn is set", dc.rootDSE)
	}
	if len(dc.searches) == 0 || dc.searches[0].base != base || dc.searches[0].filter != "(objectClass=user)" {
		t.Errorf("searches = %+v", dc.searches)
	}
}

func TestStandInBindFailure(t *testing.T) {
	dc := &fakeDC{pages: standInPages()}
	p := newStandInPlugin(t, standInConfig(map[string]any{"bind_password": "wrong-password"}), dc)
	_, err := p.Collect(context.Background(), rosterReq)
	if err == nil || !strings.Contains(err.Error(), "bind as") || !strings.Contains(err.Error(), "49") {
		t.Fatalf("err = %v, want a bind error carrying result code 49", err)
	}
	if strings.Contains(err.Error(), "wrong-password") {
		t.Errorf("bind error leaks the password: %v", err)
	}
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if len(dc.searches) != 0 || dc.rootDSE != 0 {
		t.Errorf("searched after a failed bind: %+v rootDSE=%d", dc.searches, dc.rootDSE)
	}
}

func TestStandInContextCancelClosesConnection(t *testing.T) {
	dc := &fakeDC{pages: standInPages(), stallOnPage: 2, stalled: make(chan struct{})}
	// A long request timeout proves it is the context, not go-ldap's timer,
	// that unblocks the stalled page.
	p := newStandInPlugin(t, standInConfig(map[string]any{"timeout": "10m"}), dc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-dc.stalled
		cancel()
	}()

	done := make(chan error, 1)
	go func() {
		_, err := p.Collect(ctx, rosterReq)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Collect did not return after ctx cancellation")
	}
}

// TestStandInLDAPS exercises the real dialer end to end over a loopback TLS
// listener: TCP dial, TLS handshake verified against ca_cert with
// tls_server_name, then the scripted directory.
func TestStandInLDAPS(t *testing.T) {
	certPEM, pair := newTestCert(t, fakeServerName, []string{fakeServerName})
	caPath := filepath.Join(t.TempDir(), "dc-ca.pem")
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	dc := &fakeDC{pages: standInPages()}
	addr := dc.listen(t, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})

	p := newStandInPlugin(t, standInConfig(map[string]any{
		"url": "ldaps://" + addr, "ca_cert": caPath, "tls_server_name": fakeServerName, "timeout": "5s",
	}), nil)
	recs, err := p.Collect(context.Background(), rosterReq)
	if err != nil {
		t.Fatal(err)
	}
	dc.check(t)
	if got := decodeRoster(t, recs); !reflect.DeepEqual(got, standInWant) {
		t.Errorf("roster over ldaps mismatch: %+v", got)
	}

	// Certificate not trusted (system roots only) → handshake error.
	untrusted := newStandInPlugin(t, standInConfig(map[string]any{
		"url": "ldaps://" + addr, "tls_server_name": fakeServerName, "timeout": "5s",
	}), nil)
	if _, err := untrusted.Collect(context.Background(), rosterReq); err == nil || !strings.Contains(err.Error(), "tls handshake") {
		t.Errorf("untrusted cert: err = %v, want tls handshake failure", err)
	}
	// Trusted CA but wrong name (URL host 127.0.0.1 is not in the SANs).
	wrongName := newStandInPlugin(t, standInConfig(map[string]any{
		"url": "ldaps://" + addr, "ca_cert": caPath, "timeout": "5s",
	}), nil)
	if _, err := wrongName.Collect(context.Background(), rosterReq); err == nil || !strings.Contains(err.Error(), "tls handshake") {
		t.Errorf("name mismatch: err = %v, want tls handshake failure", err)
	}
}

// TestStandInStartTLS exercises ldap:// + start_tls: the responder refuses
// to accept a bind before the StartTLS upgrade.
func TestStandInStartTLS(t *testing.T) {
	certPEM, pair := newTestCert(t, fakeServerName, []string{fakeServerName})
	caPath := filepath.Join(t.TempDir(), "dc-ca.pem")
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	dc := &fakeDC{pages: standInPages(), startTLS: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}}
	addr := dc.listen(t, nil)

	p := newStandInPlugin(t, standInConfig(map[string]any{
		"url": "ldap://" + addr, "start_tls": true, "ca_cert": caPath, "tls_server_name": fakeServerName, "timeout": "5s",
	}), nil)
	recs, err := p.Collect(context.Background(), rosterReq)
	if err != nil {
		t.Fatal(err)
	}
	dc.check(t)
	if len(recs) != len(standInWant) {
		t.Errorf("records over StartTLS = %d, want %d", len(recs), len(standInWant))
	}
}

func TestStandInDialFailure(t *testing.T) {
	t.Setenv(BindPasswordEnv, "")
	p := newStandInPlugin(t, standInConfig(map[string]any{"url": "ldaps://127.0.0.1:1", "timeout": "2s"}), nil)
	if _, err := p.Collect(context.Background(), rosterReq); err == nil || !strings.Contains(err.Error(), "dial 127.0.0.1:1") {
		t.Errorf("err = %v, want dial error", err)
	}
}
