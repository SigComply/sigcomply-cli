package directory

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	admin "google.golang.org/api/admin/directory/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// Shared fixture literals, named so goconst stays quiet.
const (
	rosterKeyStatus = "status"
)

// Shared fixture literals, named so goconst stays quiet.
const (
	externalIDKeyValue    = "value"
	rosterKeySourceStatus = "source_status"
)

// Shared fixture literals, named so goconst stays quiet.
const (
	externalIDKeyType = "type"
	rosterKeyEmail    = "email"
)

func rosterReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{RosterEvidenceTypeID}, PolicyID: "p1"}
}

// decodeJSONMap unmarshals a payload into a generic map so tests can
// assert omitted keys, not just zero values.
func decodeJSONMap(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return m
}

func TestCollect_Roster_MapsStatusEmailNameEmployeeID(t *testing.T) {
	fake := &fakeAPI{users: []*admin.User{
		{Id: "300", PrimaryEmail: "Carol@Acme.com", Archived: true},
		{
			Id: "100", PrimaryEmail: testAliceEmail, Name: &admin.UserName{FullName: testAliceName},
			ExternalIds: []any{
				map[string]any{externalIDKeyType: "custom", "customType": "badge", externalIDKeyValue: "B-1"},
				map[string]any{externalIDKeyType: externalIDTypeOrganization, externalIDKeyValue: "E-100"},
				map[string]any{externalIDKeyType: externalIDTypeOrganization, externalIDKeyValue: "E-999"},
			},
		},
		{Id: "200", PrimaryEmail: testBobEmail, Suspended: true, Archived: true},
	}}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), rosterReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("len = %d; want 3", len(records))
	}
	want := []struct {
		id, identity string
		payload      map[string]any
	}{
		{"100", testAliceEmail, map[string]any{
			"id": "100", rosterKeyStatus: rosterActive, rosterKeySourceStatus: rosterActive,
			rosterKeyEmail: testAliceEmail, "display_name": testAliceName, "employee_id": "E-100",
		}},
		{"200", testBobEmail, map[string]any{
			"id": "200", rosterKeyStatus: rosterInactive, rosterKeySourceStatus: "suspended", rosterKeyEmail: testBobEmail,
		}},
		{"300", "carol@acme.com", map[string]any{
			"id": "300", rosterKeyStatus: rosterInactive, rosterKeySourceStatus: "archived", rosterKeyEmail: "Carol@Acme.com",
		}},
	}
	for i, w := range want {
		r := records[i]
		if r.ID != w.id || r.Type != RosterEvidenceTypeID || r.SourceID != SourceID || !r.CollectedAt.Equal(now) {
			t.Errorf("record[%d] meta = %+v; want id %s type roster_entry", i, r, w.id)
		}
		if r.IdentityKey != w.identity {
			t.Errorf("record[%d] IdentityKey = %q; want lowercased %q", i, r.IdentityKey, w.identity)
		}
		if got := decodeJSONMap(t, r.Payload); !reflect.DeepEqual(got, w.payload) {
			t.Errorf("record[%d] payload = %v; want %v", i, got, w.payload)
		}
	}
}

func TestCollect_Roster_NoEmailOmitsOptionalsAndIdentity(t *testing.T) {
	p := New(Options{API: &fakeAPI{users: []*admin.User{{Id: "1", Name: &admin.UserName{}}}}})
	records, err := p.Collect(context.Background(), rosterReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].IdentityKey != "" {
		t.Errorf("IdentityKey = %q; want empty without email", records[0].IdentityKey)
	}
	want := map[string]any{"id": "1", rosterKeyStatus: rosterActive, rosterKeySourceStatus: rosterActive}
	if got := decodeJSONMap(t, records[0].Payload); !reflect.DeepEqual(got, want) {
		t.Errorf("payload = %v; want %v (empty optionals omitted)", got, want)
	}
}

func TestCollect_BothTypes_OneListing_StableSortedByID(t *testing.T) {
	fake := &fakeAPI{users: []*admin.User{
		{Id: "2", PrimaryEmail: "b@acme.com"},
		{Id: "1", PrimaryEmail: testUserEmail},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{
		AcceptedTypes: []string{EvidenceTypeID, RosterEvidenceTypeID},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.calls != 1 {
		t.Errorf("ListUsers calls = %d; want 1 (roster reuses the same listing)", fake.calls)
	}
	got := make([]string, 0, len(records))
	for _, r := range records {
		got = append(got, r.ID+"/"+r.Type)
	}
	want := []string{"1/directory_user", "1/roster_entry", "2/directory_user", "2/roster_entry"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v; want %v", got, want)
	}
}

func TestCollect_DirectoryUserOnly_NoRosterRecords(t *testing.T) {
	p := New(Options{API: &fakeAPI{users: []*admin.User{{Id: "1", PrimaryEmail: testUserEmail}}}})
	records, err := p.Collect(context.Background(), directoryReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].Type != EvidenceTypeID {
		t.Errorf("records = %+v; want one directory_user", records)
	}
}

func TestCollect_ArchivedUser_DirectoryUserInactive(t *testing.T) {
	p := New(Options{API: &fakeAPI{users: []*admin.User{{Id: "1", PrimaryEmail: testUserEmail, Archived: true}}}})
	records, err := p.Collect(context.Background(), directoryReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if u := decodePayload(t, &records[0]); u.IsActive {
		t.Error("archived user is_active = true; want false (archived users cannot sign in)")
	}
}

func TestOrganizationEmployeeID_Shapes(t *testing.T) {
	cases := []struct {
		name string
		ext  any
		want string
	}{
		{"nil", nil, ""},
		{"not a slice", map[string]any{externalIDKeyType: externalIDTypeOrganization, externalIDKeyValue: "E1"}, ""},
		{"string", "E1", ""},
		{"empty slice", []any{}, ""},
		{"non-map items skipped", []any{"E1", 42, nil, map[string]any{externalIDKeyType: externalIDTypeOrganization, externalIDKeyValue: "E2"}}, "E2"},
		{"non-string type", []any{map[string]any{externalIDKeyType: 1, externalIDKeyValue: "E1"}}, ""},
		{"non-string value", []any{map[string]any{externalIDKeyType: externalIDTypeOrganization, externalIDKeyValue: 7}}, ""},
		{"missing value", []any{map[string]any{externalIDKeyType: externalIDTypeOrganization}}, ""},
		{"empty value skipped", []any{
			map[string]any{externalIDKeyType: externalIDTypeOrganization, externalIDKeyValue: ""},
			map[string]any{externalIDKeyType: externalIDTypeOrganization, externalIDKeyValue: "E3"},
		}, "E3"},
		{"only other types", []any{map[string]any{externalIDKeyType: "account", externalIDKeyValue: "A1"}}, ""},
		{"typed pointer slice", []*admin.UserExternalId{nil, {Type: "custom", Value: "X"}, {Type: externalIDTypeOrganization, Value: "E4"}}, "E4"},
		{"typed value slice", []admin.UserExternalId{{Type: externalIDTypeOrganization, Value: "E5"}}, "E5"},
		{"map slice type not []any", []map[string]any{{externalIDKeyType: externalIDTypeOrganization, externalIDKeyValue: "E6"}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := organizationEmployeeID(tc.ext); got != tc.want {
				t.Errorf("organizationEmployeeID(%#v) = %q; want %q", tc.ext, got, tc.want)
			}
		})
	}
}

// TestOrganizationEmployeeID_DecodedFromJSON pins the shape the real SDK
// deserializer produces for the interface{}-typed field.
func TestOrganizationEmployeeID_DecodedFromJSON(t *testing.T) {
	var u admin.User
	body := `{"id":"1","externalIds":[{"type":"account","value":"A"},{"type":"organization","value":"E-7"}]}`
	if err := json.Unmarshal([]byte(body), &u); err != nil {
		t.Fatal(err)
	}
	if got := organizationEmployeeID(u.ExternalIds); got != "E-7" {
		t.Errorf("employee id = %q; want E-7", got)
	}
}
