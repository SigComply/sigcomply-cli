package activedirectory

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// testNow is the fixed clock for every mapping test.
var testNow = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// knownGUIDBytes is the objectGUID wire form of Microsoft's documented
// example GUID {6F9619FF-8B86-D011-B42D-00C04FC964FF}: the first three
// groups are stored little-endian.
var knownGUIDBytes = []byte{
	0xFF, 0x19, 0x96, 0x6F, 0x86, 0x8B, 0x11, 0xD0,
	0xB4, 0x2D, 0x00, 0xC0, 0x4F, 0xC9, 0x64, 0xFF,
}

const knownGUID = "6f9619ff-8b86-d011-b42d-00c04fc964ff"

// newEntry builds an *ldap.Entry the way go-ldap decodes one off the wire
// (string and raw byte values both populated).
func newEntry(dn string, guid []byte, attrs map[string][]string) *ldap.Entry {
	e := &ldap.Entry{DN: dn}
	if guid != nil {
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{
			Name: attrObjectGUID, Values: []string{string(guid)}, ByteValues: [][]byte{guid},
		})
	}
	for name, vals := range attrs {
		raw := make([][]byte, len(vals))
		for i, v := range vals {
			raw[i] = []byte(v)
		}
		e.Attributes = append(e.Attributes, &ldap.EntryAttribute{Name: name, Values: vals, ByteValues: raw})
	}
	return e
}

func toFileTime(t time.Time) string {
	return strconv.FormatInt(t.Unix()*fileTimeTicksPerSec+fileTimeUnixEpochDiff, 10)
}

func TestGUIDString(t *testing.T) {
	t.Parallel()
	got, err := guidString(knownGUIDBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got != knownGUID {
		t.Errorf("guidString = %q, want %q", got, knownGUID)
	}
	seq := []byte{0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	if got, err := guidString(seq); err != nil || got != "12345678-1234-5678-1234-56789abcdef0" {
		t.Errorf("guidString(seq) = %q, %v", got, err)
	}
	for _, bad := range [][]byte{nil, {}, make([]byte, 15), make([]byte, 17)} {
		if _, err := guidString(bad); err == nil {
			t.Errorf("guidString(%d bytes) = nil error, want error", len(bad))
		}
	}
}

func TestFileTimeToTime(t *testing.T) {
	t.Parallel()
	// 116444736000000000 is exactly the Unix epoch.
	if got := fileTimeToTime(fileTimeUnixEpochDiff); !got.Equal(time.Unix(0, 0)) {
		t.Errorf("epoch FILETIME = %v, want 1970-01-01", got)
	}
	// 2025-01-01T00:00:00Z = 133801632000000000.
	if got := fileTimeToTime(133801632000000000); !got.Equal(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("2025 FILETIME = %v", got)
	}
	// Sub-second ticks survive.
	if got := fileTimeToTime(fileTimeUnixEpochDiff + 15); got.Nanosecond() != 1500 {
		t.Errorf("sub-second nanos = %d, want 1500", got.Nanosecond())
	}
}

func TestAccountExpired(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		raw     string
		want    bool
		wantErr bool
	}{
		{"absent", "", false, false},
		{"zero means never", "0", false, false},
		{"max int64 means never", "9223372036854775807", false, false},
		{"past", toFileTime(testNow.Add(-24 * time.Hour)), true, false},
		{"exactly now", toFileTime(testNow), true, false},
		{"future", toFileTime(testNow.Add(24 * time.Hour)), false, false},
		{"garbage", "soon", false, true},
		{"negative", "-5", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := accountExpired(tc.raw, testNow)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("expired = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUACDisabled(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw     string
		want    bool
		wantErr bool
	}{
		{"512", false, false},   // NORMAL_ACCOUNT
		{"514", true, false},    // NORMAL_ACCOUNT | ACCOUNTDISABLE
		{"66048", false, false}, // NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD
		{"66050", true, false},
		{"-2147483646", true, false}, // signed rendering with bit 0x2 set
		{"", false, true},
		{"abc", false, true},
	}
	for _, tc := range cases {
		got, err := uacDisabled(tc.raw)
		if (err != nil) != tc.wantErr {
			t.Errorf("uacDisabled(%q) err = %v, wantErr %v", tc.raw, err, tc.wantErr)
			continue
		}
		if got != tc.want {
			t.Errorf("uacDisabled(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestEntryStatus(t *testing.T) {
	t.Parallel()
	past := toFileTime(testNow.Add(-time.Hour))
	cases := []struct {
		name, uac, expires, wantStatus, wantSource string
	}{
		{"enabled never expires", "512", "0", statusActive, sourceStatusEnabled},
		{"enabled future expiry", "512", toFileTime(testNow.Add(time.Hour)), statusActive, sourceStatusEnabled},
		{"disabled", "514", "9223372036854775807", statusInactive, sourceStatusDisabled},
		{"expired", "512", past, statusInactive, sourceStatusExpired},
		{"disabled wins over expired", "514", past, statusInactive, sourceStatusDisabled},
	}
	for _, tc := range cases {
		e := newEntry("CN=x", knownGUIDBytes, map[string][]string{
			attrUserAccountControl: {tc.uac}, attrAccountExpires: {tc.expires},
		})
		status, source, err := entryStatus(e, testNow)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if status != tc.wantStatus || source != tc.wantSource {
			t.Errorf("%s: got (%s,%s), want (%s,%s)", tc.name, status, source, tc.wantStatus, tc.wantSource)
		}
	}
}

func TestEntryEmailFallbacks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		attrs map[string][]string
		want  string
	}{
		{"mail wins", map[string][]string{
			attrMail: {"jane@corp.example.com"}, attrProxyAddresses: {"SMTP:other@corp.example.com"},
			attrUserPrincipalName: {"jane@corp.local"},
		}, "jane@corp.example.com"},
		{"primary SMTP proxy address, not secondary", map[string][]string{
			attrProxyAddresses:    {"smtp:alias@corp.example.com", "SMTP:primary@corp.example.com", "X500:/o=corp"},
			attrUserPrincipalName: {"jane@corp.local"},
		}, "primary@corp.example.com"},
		{"only secondary proxy falls through to UPN", map[string][]string{
			attrProxyAddresses:    {"smtp:alias@corp.example.com"},
			attrUserPrincipalName: {"jane@corp.local"},
		}, "jane@corp.local"},
		{"UPN", map[string][]string{attrUserPrincipalName: {"jane@corp.local"}}, "jane@corp.local"},
		{"none", map[string][]string{attrSAMAccountName: {"jane"}}, ""},
	}
	for _, tc := range cases {
		if got := entryEmail(newEntry("CN=x", nil, tc.attrs)); got != tc.want {
			t.Errorf("%s: email = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestEntryDisplayNameFallbacks(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		attrs map[string][]string
		want  string
	}{
		{"displayName", map[string][]string{attrDisplayName: {"Jane Doe"}, attrGivenName: {"J"}, attrSAMAccountName: {"jdoe"}}, "Jane Doe"},
		{"given + sn", map[string][]string{attrGivenName: {"Jane"}, attrSn: {"Doe"}, attrSAMAccountName: {"jdoe"}}, "Jane Doe"},
		{"given only", map[string][]string{attrGivenName: {"Jane"}, attrSAMAccountName: {"jdoe"}}, "Jane"},
		{"sn only", map[string][]string{attrSn: {"Doe"}}, "Doe"},
		{"sAMAccountName", map[string][]string{attrSAMAccountName: {"jdoe"}}, "jdoe"},
		{"none", map[string][]string{}, ""},
	}
	for _, tc := range cases {
		if got := entryDisplayName(newEntry("CN=x", nil, tc.attrs)); got != tc.want {
			t.Errorf("%s: display_name = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestIsServiceAccount(t *testing.T) {
	t.Parallel()
	ou, err := ldap.ParseDN("OU=Service Accounts,DC=corp,DC=example,DC=com")
	if err != nil {
		t.Fatal(err)
	}
	ous := []*ldap.DN{ou}
	cases := []struct {
		name  string
		dn    string
		attrs map[string][]string
		want  bool
	}{
		{"SPN present", "CN=sql,CN=Users,DC=corp,DC=example,DC=com",
			map[string][]string{attrServicePrincipalName: {"MSSQLSvc/db01.corp.example.com:1433"}}, true},
		{"under service OU (case-insensitive)", "cn=svc-backup,ou=service accounts,dc=CORP,dc=example,dc=com", nil, true},
		{"nested under service OU", "CN=a,OU=Batch,OU=Service Accounts,DC=corp,DC=example,DC=com", nil, true},
		{"sibling OU with shared suffix text", "CN=a,OU=Not Service Accounts,DC=corp,DC=example,DC=com", nil, false},
		{"regular user", "CN=Jane,CN=Users,DC=corp,DC=example,DC=com", nil, false},
		{"empty SPN value ignored", "CN=Jane,CN=Users,DC=corp,DC=example,DC=com",
			map[string][]string{attrServicePrincipalName: {" "}}, false},
	}
	for _, tc := range cases {
		if got := isServiceAccount(newEntry(tc.dn, nil, tc.attrs), ous); got != tc.want {
			t.Errorf("%s: is_service_account = %v, want %v", tc.name, got, tc.want)
		}
	}
	// DN falls back to the distinguishedName attribute when Entry.DN is empty.
	e := newEntry("", nil, map[string][]string{attrDistinguishedName: {"CN=a,OU=Service Accounts,DC=corp,DC=example,DC=com"}})
	if !isServiceAccount(e, ous) {
		t.Error("distinguishedName fallback not used for OU match")
	}
	if isServiceAccount(newEntry("CN=a,OU=Service Accounts,DC=corp,DC=example,DC=com", nil, nil), nil) {
		t.Error("no OUs configured and no SPN must not flag a service account")
	}
}

func TestMapEntry(t *testing.T) {
	t.Parallel()
	e := newEntry("CN=Jane Doe,OU=Staff,DC=corp,DC=example,DC=com", knownGUIDBytes, map[string][]string{
		attrMail:               {"Jane.Doe@Corp.Example.com"},
		attrDisplayName:        {"Jane Doe"},
		attrUserAccountControl: {"512"},
		attrAccountExpires:     {"0"},
		attrEmployeeNumber:     {"E-100"},
		attrEmployeeType:       {"contractor"},
	})
	got, err := mapEntry(e, testNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := rosterPayload{
		ID: knownGUID, Status: statusActive, Email: "Jane.Doe@Corp.Example.com",
		DisplayName: "Jane Doe", EmployeeID: "E-100", EmployeeType: "contractor",
		SourceStatus: sourceStatusEnabled,
	}
	if got != want {
		t.Errorf("mapEntry = %+v\nwant      %+v", got, want)
	}

	// employeeID takes precedence over employeeNumber.
	e2 := newEntry("CN=x", knownGUIDBytes, map[string][]string{
		attrUserAccountControl: {"512"}, attrEmployeeID: {"42"}, attrEmployeeNumber: {"E-100"},
	})
	if got, err := mapEntry(e2, testNow, nil); err != nil || got.EmployeeID != "42" {
		t.Errorf("employee_id = %q (err %v), want 42", got.EmployeeID, err)
	}
}

func TestMapEntryErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		guid  []byte
		attrs map[string][]string
		want  string
	}{
		{"no objectGUID", nil, map[string][]string{attrUserAccountControl: {"512"}}, "objectGUID"},
		{"short objectGUID", []byte{1, 2, 3}, map[string][]string{attrUserAccountControl: {"512"}}, "objectGUID"},
		{"no UAC", knownGUIDBytes, map[string][]string{}, "userAccountControl"},
		{"bad accountExpires", knownGUIDBytes, map[string][]string{attrUserAccountControl: {"512"}, attrAccountExpires: {"x"}}, "accountExpires"},
	}
	for _, tc := range cases {
		_, err := mapEntry(newEntry("CN=bad", tc.guid, tc.attrs), testNow, nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "CN=bad") {
			t.Errorf("%s: err = %v, want mention of %q and the DN", tc.name, err, tc.want)
		}
	}
}
