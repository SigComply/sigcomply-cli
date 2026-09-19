package activedirectory

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeDirectory is the L1 searcher seam: it returns canned entries.
type fakeDirectory struct {
	entries []*ldap.Entry
	err     error
}

func (f *fakeDirectory) ListUsers(context.Context) ([]*ldap.Entry, error) {
	return f.entries, f.err
}

func guidN(n byte) []byte {
	b := make([]byte, 16)
	b[3] = n // Data1 is little-endian, so this lands in the leading hex pair
	return b
}

var rosterReq = core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRosterEntry}}

func TestCollectMapsAndSorts(t *testing.T) {
	t.Parallel()
	svcOU, err := ldap.ParseDN("OU=Service Accounts,DC=corp,DC=example,DC=com")
	if err != nil {
		t.Fatal(err)
	}
	p := New(Options{
		Directory: &fakeDirectory{entries: []*ldap.Entry{
			newEntry("CN=Zed,OU=Staff,DC=corp,DC=example,DC=com", guidN(0x30), map[string][]string{
				attrUserPrincipalName: {"Zed@Corp.Example.com"}, attrUserAccountControl: {"512"},
			}),
			newEntry("CN=backup,OU=Service Accounts,DC=corp,DC=example,DC=com", guidN(0x10), map[string][]string{
				attrSAMAccountName: {"backup"}, attrUserAccountControl: {"514"},
			}),
		}},
		ServiceAccountOUs: []*ldap.DN{svcOU},
		Now:               func() time.Time { return testNow },
	})
	recs, err := p.Collect(context.Background(), rosterReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	if recs[0].ID != "10000000-0000-0000-0000-000000000000" || recs[1].ID != "30000000-0000-0000-0000-000000000000" {
		t.Errorf("ids not sorted/decoded: %q, %q", recs[0].ID, recs[1].ID)
	}
	for _, r := range recs {
		if r.Type != EvidenceTypeRosterEntry || r.SourceID != SourceID || !r.CollectedAt.Equal(testNow) {
			t.Errorf("metadata: %+v", r)
		}
	}
	if recs[1].IdentityKey != "zed@corp.example.com" {
		t.Errorf("identity key = %q, want lowercased email", recs[1].IdentityKey)
	}
	if recs[0].IdentityKey != "" {
		t.Errorf("identity key for entry without email = %q, want empty", recs[0].IdentityKey)
	}

	assertExactPayload(t, recs[0].Payload, map[string]any{
		"id": "10000000-0000-0000-0000-000000000000", "status": statusInactive, "display_name": "backup",
		"is_service_account": true, "source_status": sourceStatusDisabled,
	})
}

// assertExactPayload checks the payload has exactly the wanted keys and
// values — empty optional strings must be omitted, not emitted as "".
func assertExactPayload(t *testing.T, payload []byte, want map[string]any) {
	t.Helper()
	var svc map[string]any
	if err := json.Unmarshal(payload, &svc); err != nil {
		t.Fatal(err)
	}
	if len(svc) != len(want) {
		t.Errorf("payload keys = %v, want exactly %v (empty optional strings omitted)", svc, want)
	}
	for k, v := range want {
		if svc[k] != v {
			t.Errorf("payload[%s] = %v, want %v", k, svc[k], v)
		}
	}
}

func TestCollectErrors(t *testing.T) {
	t.Parallel()
	p := New(Options{Directory: &fakeDirectory{}})
	if _, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"directory_user"}}); err == nil {
		t.Error("directory_user request must be refused: AD emits only roster_entry")
	}

	p = New(Options{Directory: &fakeDirectory{err: errors.New("boom")}})
	if _, err := p.Collect(context.Background(), rosterReq); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("list error not propagated: %v", err)
	}

	p = New(Options{Directory: &fakeDirectory{entries: []*ldap.Entry{newEntry("CN=nog", nil, nil)}}})
	if _, err := p.Collect(context.Background(), rosterReq); err == nil || !strings.Contains(err.Error(), "objectGUID") {
		t.Errorf("mapping error not propagated: %v", err)
	}

	p = New(Options{Directory: &fakeDirectory{}})
	recs, err := p.Collect(context.Background(), rosterReq)
	if err != nil || len(recs) != 0 {
		t.Errorf("empty directory: recs=%v err=%v", recs, err)
	}
}

func TestPluginIdentity(t *testing.T) {
	t.Parallel()
	p := New(Options{})
	if p.ID() != "active_directory" {
		t.Errorf("ID = %q", p.ID())
	}
	if got := p.Emits(); len(got) != 1 || got[0] != "roster_entry" {
		t.Errorf("Emits = %v", got)
	}
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init = %v", err)
	}
	if p.now().IsZero() {
		t.Error("default clock unset")
	}
}
