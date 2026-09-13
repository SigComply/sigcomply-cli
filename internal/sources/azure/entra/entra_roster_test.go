package entra

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	"github.com/sigcomply/sigcomply-cli/internal/sources/sourcetest"
)

func acceptRoster() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeRosterEntry}}
}

func TestCollectRoster_MapsExcludesGuestsSortsAndValidates(t *testing.T) {
	t.Parallel()
	api := &fakeAPI{roster: []RosterUser{
		{ID: "u-zed", Mail: "", UPN: "Zed@Contoso.com", DisplayName: "Zed", AccountEnabled: false, UserType: "Member"},
		{ID: "u-amy", Mail: " Amy@Contoso.com ", UPN: "amy@contoso.onmicrosoft.com", DisplayName: "Amy A",
			AccountEnabled: true, UserType: "Member", EmployeeID: "E1", EmployeeType: "Contractor"},
		{ID: "u-guest", Mail: "partner@fabrikam.com", UPN: "partner_fabrikam.com#EXT#@contoso.com", AccountEnabled: true, UserType: "Guest"},
		{ID: "u-guest2", Mail: "p2@fabrikam.com", AccountEnabled: true, UserType: "guest"},
		{ID: "u-bare", UPN: "bare@contoso.com", AccountEnabled: true}, // userType unknown → kept
	}}
	p := New(Options{API: api, Tenant: "tenant-123", Now: fixedNow})
	recs, err := p.Collect(context.Background(), acceptRoster())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if api.calls != 0 {
		t.Errorf("roster collect called ListUsers (registration report path) %d times; want 0", api.calls)
	}
	want := map[string]struct{ identity, payload string }{
		"u-amy":  {"amy@contoso.com", `{"id":"u-amy","status":"active","email":"Amy@Contoso.com","display_name":"Amy A","employee_id":"E1","employee_type":"Contractor","source_status":"enabled"}`},
		"u-bare": {"bare@contoso.com", `{"id":"u-bare","status":"active","email":"bare@contoso.com","source_status":"enabled"}`},
		"u-zed":  {"zed@contoso.com", `{"id":"u-zed","status":"inactive","email":"Zed@Contoso.com","display_name":"Zed","source_status":"disabled"}`},
	}
	if len(recs) != len(want) {
		t.Fatalf("records = %d, want %d (guests excluded)", len(recs), len(want))
	}
	if recs[0].ID != "u-amy" || recs[1].ID != "u-bare" || recs[2].ID != "u-zed" {
		t.Errorf("not sorted by ID: %s %s %s", recs[0].ID, recs[1].ID, recs[2].ID)
	}
	et, ok := sourcetest.BuiltinEvidenceTypes(t).Lookup(EvidenceTypeRosterEntry)
	if !ok {
		t.Fatal("roster_entry evidence type not registered")
	}
	for i := range recs {
		w := want[recs[i].ID]
		assertRosterRecord(t, &recs[i], w.identity, w.payload, et.Schema)
	}
}

// assertRosterRecord checks one roster_entry record's payload bytes, identity,
// metadata, tenant scope, and schema validity.
func assertRosterRecord(t *testing.T, r *core.EvidenceRecord, identity, payload string, schema json.RawMessage) {
	t.Helper()
	if string(r.Payload) != payload {
		t.Errorf("%s payload =\n %s\nwant\n %s", r.ID, r.Payload, payload)
	}
	if r.IdentityKey != identity {
		t.Errorf("%s IdentityKey = %q, want %q", r.ID, r.IdentityKey, identity)
	}
	if r.Type != EvidenceTypeRosterEntry || r.SourceID != SourceID || !r.CollectedAt.Equal(fixedNow()) {
		t.Errorf("%s metadata = %q/%q/%v", r.ID, r.Type, r.SourceID, r.CollectedAt)
	}
	if r.Scope == nil || r.Scope.Account != "tenant-123" {
		t.Errorf("%s Scope = %v, want tenant-123", r.ID, r.Scope)
	}
	if err := evidencetypes.Validate(schema, r.Payload); err != nil {
		t.Errorf("%s: schema: %v", r.ID, err)
	}
}

func TestCollect_BothTypesInOneCall(t *testing.T) {
	t.Parallel()
	api := &fakeAPI{
		users:  []User{{ID: "u1", UPN: "a@contoso.com", Email: "a@contoso.com", IsActive: true}},
		roster: []RosterUser{{ID: "u1", Mail: "a@contoso.com", AccountEnabled: true, UserType: "Member"}},
	}
	p := New(Options{API: api, Now: fixedNow})
	recs, err := p.Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID, EvidenceTypeRosterEntry}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 2 || recs[0].Type != EvidenceTypeID || recs[1].Type != EvidenceTypeRosterEntry {
		t.Errorf("records = %+v; want directory_user then roster_entry", recs)
	}
}

func TestCollectRoster_OnlyRosterDoesNotListUsers(t *testing.T) {
	t.Parallel()
	api := &fakeAPI{}
	p := New(Options{API: api, Now: fixedNow})
	recs, err := p.Collect(context.Background(), acceptRoster())
	if err != nil || len(recs) != 0 {
		t.Fatalf("Collect = %v, %v; want no records, no error", recs, err)
	}
	if api.calls != 0 || api.rosterCalls != 1 {
		t.Errorf("calls users=%d roster=%d, want 0/1", api.calls, api.rosterCalls)
	}
}

func TestCollectRoster_ErrorPropagation(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("boom")
	p := New(Options{API: &fakeAPI{err: wantErr}})
	_, err := p.Collect(context.Background(), acceptRoster())
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "list roster users") {
		t.Fatalf("error = %v, want wrapped list roster users %v", err, wantErr)
	}
}

// The roster read must work on a tenant without Entra P1/P2: it pages /users
// with the roster projection and never touches the registration report.
func TestRealGraph_ListRosterUsers_PaginatesWithoutRegistrationReport(t *testing.T) {
	t.Parallel()
	var srv *httptest.Server
	var queries []string
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want Bearer test-token", got)
		}
		if r.URL.Path != "/users" {
			t.Errorf("unexpected Graph call %s (roster must not read the P1/P2 report)", r.URL.Path)
			http.Error(w, `{"error":{"code":"RequestFromNonPremiumTenantOrB2CTenant"}}`, http.StatusForbidden)
			return
		}
		queries = append(queries, r.URL.RawQuery)
		if r.URL.Query().Get("page") == "2" {
			writeJSON(t, w, map[string]any{"value": []map[string]any{
				{"id": "u-guest", "mail": "g@fabrikam.com", "userPrincipalName": "g_fabrikam.com#EXT#@contoso.com", "accountEnabled": true, "userType": "Guest"},
			}})
			return
		}
		writeJSON(t, w, map[string]any{
			"@odata.nextLink": srv.URL + "/users?page=2",
			"value": []map[string]any{
				{"id": "u-adele", "mail": "adele@contoso.com", "userPrincipalName": "adele@contoso.com", "displayName": "Adele",
					"accountEnabled": true, "userType": "Member", "employeeId": "E7", "employeeType": "Employee"},
				{"id": "u-carol", "mail": nil, "userPrincipalName": "carol@contoso.com", "displayName": "Carol",
					"accountEnabled": false, "userType": "Member", "employeeId": nil, "employeeType": nil},
			},
		})
	}))
	defer srv.Close()

	users, err := newRealGraph(srv.URL).ListRosterUsers(context.Background())
	if err != nil {
		t.Fatalf("ListRosterUsers: %v", err)
	}
	wantFirst := "$select=id,mail,userPrincipalName,displayName,accountEnabled,userType,employeeId,employeeType&$top=999"
	if len(queries) != 2 || queries[0] != wantFirst || queries[1] != "page=2" {
		t.Errorf("queries = %q, want [%q page=2]", queries, wantFirst)
	}
	want := []RosterUser{
		{ID: "u-adele", Mail: "adele@contoso.com", UPN: "adele@contoso.com", DisplayName: "Adele", AccountEnabled: true,
			UserType: "Member", EmployeeID: "E7", EmployeeType: "Employee"},
		{ID: "u-carol", UPN: "carol@contoso.com", DisplayName: "Carol", UserType: "Member"},
		{ID: "u-guest", Mail: "g@fabrikam.com", UPN: "g_fabrikam.com#EXT#@contoso.com", AccountEnabled: true, UserType: "Guest"},
	}
	if len(users) != len(want) {
		t.Fatalf("users = %d, want %d", len(users), len(want))
	}
	for i := range want {
		if users[i] != want[i] {
			t.Errorf("user[%d] = %+v, want %+v", i, users[i], want[i])
		}
	}
}

func TestRealGraph_ListRosterUsers_Errors(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := newRealGraph(srv.URL).ListRosterUsers(context.Background())
	if err == nil || !strings.Contains(err.Error(), "User.Read.All") || !strings.Contains(err.Error(), "403") {
		t.Errorf("want 403 with User.Read.All hint, got %v", err)
	}

	r := &realGraph{base: "http://unused", client: &http.Client{}, cred: fakeCred{err: errors.New("no creds")}}
	if _, err := r.ListRosterUsers(context.Background()); err == nil || !strings.Contains(err.Error(), "graph token") {
		t.Errorf("want graph-token error, got %v", err)
	}
}
