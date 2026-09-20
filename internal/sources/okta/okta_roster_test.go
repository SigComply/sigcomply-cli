package okta

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

func TestRosterStatus(t *testing.T) {
	cases := map[string]string{
		oktaStatusActive:        rosterActive,
		"RECOVERY":              rosterActive,
		"PASSWORD_EXPIRED":      rosterActive,
		oktaStatusLockedOut:     rosterActive,
		"active":                rosterActive,
		oktaStatusStaged:        rosterPending,
		"PROVISIONED":           rosterPending,
		oktaStatusSuspended:     rosterInactive,
		oktaStatusDeprovisioned: rosterInactive,
		"SOMETHING_NEW":         rosterInactive,
		"":                      rosterInactive,
	}
	for raw, want := range cases {
		if got := rosterStatus(raw); got != want {
			t.Errorf("rosterStatus(%q) = %q; want %q", raw, got, want)
		}
	}
}

// directory_user.is_active uses the same active set as roster_entry.
func TestCollectUsers_IsActiveMatchesRosterActiveSet(t *testing.T) {
	statuses := []string{oktaStatusActive, "RECOVERY", "PASSWORD_EXPIRED", oktaStatusLockedOut, oktaStatusStaged, "PROVISIONED", oktaStatusSuspended, oktaStatusDeprovisioned}
	users := make([]User, 0, len(statuses))
	for _, st := range statuses {
		users = append(users, User{ID: st, Email: strings.ToLower(st) + "@acme.com", Status: st})
	}
	p := New(Options{API: &fakeAPI{users: users}})
	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range recs {
		var up userPayload
		mustUnmarshal(t, r.Payload, &up)
		want := rosterStatus(r.ID) == rosterActive
		if up.IsActive != want {
			t.Errorf("status %s: is_active = %v; want %v", r.ID, up.IsActive, want)
		}
	}
}

func TestCollectRoster_MapsSortsAndValidates(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	fake := &fakeAPI{roster: []RosterUser{
		{ID: "u_zed", Status: oktaStatusDeprovisioned, Email: "Zed@Acme.com", FirstName: "Zed", LastName: "Z", Login: "zed@acme.com"},
		{ID: "u_amy", Status: oktaStatusActive, Email: testEmailAmy, FirstName: "Amy", LastName: "Adams", Login: testEmailAmy,
			EmployeeNumber: "E100", UserType: "Employee"},
		{ID: "u_joe", Status: oktaStatusStaged, Email: "joe@acme.com", Login: "joe.login"},
		{ID: "u_noemail", Status: oktaStatusSuspended, Login: "svc"},
	}}
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRosterEntry}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.listUsersCount != 0 {
		t.Errorf("roster collect called ListUsers %d times; want 0 (no per-user MFA/role calls)", fake.listUsersCount)
	}
	gotIDs := make([]string, 0, len(recs))
	for _, r := range recs {
		gotIDs = append(gotIDs, r.ID)
	}
	if strings.Join(gotIDs, ",") != "u_amy,u_joe,u_noemail,u_zed" {
		t.Fatalf("ids = %v; want sorted", gotIDs)
	}

	want := map[string]struct {
		identity string
		payload  string
	}{
		"u_amy":     {testEmailAmy, `{"id":"u_amy","status":"active","email":"amy@acme.com","display_name":"Amy Adams","employee_id":"E100","employee_type":"Employee","source_status":"ACTIVE"}`},
		"u_joe":     {"joe@acme.com", `{"id":"u_joe","status":"pending","email":"joe@acme.com","display_name":"joe.login","source_status":"STAGED"}`},
		"u_noemail": {"", `{"id":"u_noemail","status":"inactive","display_name":"svc","source_status":"SUSPENDED"}`},
		"u_zed":     {"zed@acme.com", `{"id":"u_zed","status":"inactive","email":"Zed@Acme.com","display_name":"Zed Z","source_status":"DEPROVISIONED"}`},
	}
	et, ok := sourcetest.BuiltinEvidenceTypes(t).Lookup(EvidenceTypeRosterEntry)
	if !ok {
		t.Fatal("roster_entry evidence type not registered")
	}
	for _, r := range recs {
		w := want[r.ID]
		if string(r.Payload) != w.payload {
			t.Errorf("%s payload =\n %s\nwant\n %s", r.ID, r.Payload, w.payload)
		}
		if r.IdentityKey != w.identity {
			t.Errorf("%s IdentityKey = %q; want %q", r.ID, r.IdentityKey, w.identity)
		}
		if r.Type != EvidenceTypeRosterEntry || r.SourceID != SourceID || !r.CollectedAt.Equal(now) {
			t.Errorf("%s metadata = %q/%q/%v", r.ID, r.Type, r.SourceID, r.CollectedAt)
		}
		if err := evidencetypes.Validate(et.Schema, r.Payload); err != nil {
			t.Errorf("%s: schema: %v", r.ID, err)
		}
	}
}

func TestCollect_MultiTypeIncludesRoster(t *testing.T) {
	fake := &fakeAPI{
		users:  []User{{ID: "u1", Email: testEmailUser, Status: oktaStatusActive}},
		roster: []RosterUser{{ID: "u1", Email: testEmailUser, Status: oktaStatusActive}},
	}
	p := New(Options{API: fake})
	recs, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser, EvidenceTypeRosterEntry}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 || recs[0].Type != EvidenceTypeDirectoryUser || recs[1].Type != EvidenceTypeRosterEntry {
		t.Errorf("records = %+v; want one directory_user then one roster_entry", recs)
	}
	if fake.listAppsCount != 0 {
		t.Errorf("apps listed %d times for a slot not accepting okta_app", fake.listAppsCount)
	}
}

func TestCollectRoster_ErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{rosterErr: errors.New("forbidden")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRosterEntry}})
	if err == nil || !strings.Contains(err.Error(), "list roster users") {
		t.Errorf("want list roster users error; got %v", err)
	}
}

// usersOnlyAPI implements API but not RosterAPI.
type usersOnlyAPI struct{}

func (usersOnlyAPI) ListUsers(context.Context) ([]User, error) { return nil, nil }
func (usersOnlyAPI) ListApps(context.Context) ([]App, error)   { return nil, nil }
func (usersOnlyAPI) ListPasswordPolicies(context.Context) ([]PasswordPolicy, error) {
	return nil, nil
}

func TestCollectRoster_APIWithoutRosterSupport(t *testing.T) {
	p := New(Options{API: usersOnlyAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRosterEntry}})
	if err == nil || !strings.Contains(err.Error(), "cannot list roster users") {
		t.Errorf("want unsupported-roster error; got %v", err)
	}
}

func TestHTTPAPI_ListRosterUsers_TwoPassesPagedDeduped(t *testing.T) {
	var base string
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/users" {
			t.Errorf("unexpected per-user call: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		queries = append(queries, r.URL.RawQuery)
		switch r.URL.RawQuery {
		case "limit=200":
			w.Header().Set("Link", `<`+base+`/api/v1/users?after=u2&limit=200>; rel="next"`)
			_, _ = w.Write([]byte(`[{"id":"u1","status":"ACTIVE","profile":{"email":"a@x.com","firstName":"Ann","lastName":"A",` + //nolint:errcheck // test handler
				`"login":"a@x.com","employeeNumber":"E1","userType":"Employee"}}]`))
		case "after=u2&limit=200":
			_, _ = w.Write([]byte(`[{"id":"u2","status":"SUSPENDED","profile":{"email":"b@x.com","firstName":null,"login":"b@x.com"}}]`)) //nolint:errcheck // test handler
		case `filter=status+eq+%22DEPROVISIONED%22&limit=200`:
			_, _ = w.Write([]byte(`[{"id":"u2","status":"SUSPENDED","profile":{"email":"b@x.com"}},` + //nolint:errcheck // test handler
				`{"id":"u3","status":"DEPROVISIONED","profile":{"email":"c@x.com","login":"c@x.com"}}]`))
		default:
			t.Errorf("unexpected query: %q", r.URL.RawQuery)
			_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
		}
	}))
	defer srv.Close()
	base = srv.URL
	api := &httpAPI{base: srv.URL, token: testToken, client: srv.Client()}
	users, err := api.ListRosterUsers(context.Background())
	if err != nil {
		t.Fatalf("ListRosterUsers: %v", err)
	}
	wantQueries := "limit=200|after=u2&limit=200|filter=status+eq+%22DEPROVISIONED%22&limit=200"
	if got := strings.Join(queries, "|"); got != wantQueries {
		t.Errorf("queries = %s; want %s", got, wantQueries)
	}
	if len(users) != 3 {
		t.Fatalf("len = %d; want 3 (u2 de-duplicated)", len(users))
	}
	want := RosterUser{ID: "u1", Status: oktaStatusActive, Email: "a@x.com", FirstName: "Ann", LastName: "A", Login: "a@x.com", EmployeeNumber: "E1", UserType: "Employee"}
	if users[0] != want {
		t.Errorf("u1 = %+v; want %+v", users[0], want)
	}
	if users[2].ID != "u3" || users[2].Status != oktaStatusDeprovisioned {
		t.Errorf("third user = %+v; want deprovisioned u3", users[2])
	}
}

func TestHTTPAPI_ListRosterUsers_ErrorOnFilterPass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "filter=") {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`[]`)) //nolint:errcheck // test handler
	}))
	defer srv.Close()
	api := &httpAPI{base: srv.URL, token: testToken, client: srv.Client()}
	if _, err := api.ListRosterUsers(context.Background()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("want 403 error; got %v", err)
	}
}

func TestRosterPayload_JSONShape(t *testing.T) {
	b, err := json.Marshal(rosterPayload{ID: "u", Status: rosterPending})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"id":"u","status":"pending"}` {
		t.Errorf("empty optionals must be omitted; got %s", b)
	}
}
