package entra

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/internal/azcommon"
)

// fakeAPI is the in-memory API seam for Collect-level tests.
type fakeAPI struct {
	users []User
	err   error
	calls int
}

func (f *fakeAPI) ListUsers(context.Context) ([]User, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.users, nil
}

func fixedNow() time.Time { return time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC) }

func acceptDirectoryUser() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}
}

func TestPlugin_IDAndEmits(t *testing.T) {
	t.Parallel()
	p := New(Options{API: &fakeAPI{}})
	if got := p.ID(); got != "azure.entra" {
		t.Errorf("ID() = %q, want azure.entra", got)
	}
	if got := p.Emits(); !reflect.DeepEqual(got, []string{"directory_user"}) {
		t.Errorf("Emits() = %v, want [directory_user]", got)
	}
}

func TestCollect_RejectsNonDirectoryUserType(t *testing.T) {
	t.Parallel()
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil {
		t.Fatal("expected error when slot does not accept directory_user")
	}
}

func TestCollect_MapsSortsAndScopes(t *testing.T) {
	t.Parallel()
	login := time.Date(2026, 5, 1, 9, 30, 0, 0, time.UTC)
	api := &fakeAPI{users: []User{
		// Deliberately out of ID order to exercise the sort.
		{
			ID: "u-zelda", UPN: "zelda@contoso.com", Email: "zelda@contoso.com",
			DisplayName: "Zelda Z", IsActive: false, IsAdmin: false, MFAEnabled: false,
		},
		{
			ID: "u-adele", UPN: "adele@contoso.com", Email: "adele@contoso.com",
			DisplayName: "Adele V", IsActive: true, IsAdmin: true, MFAEnabled: true,
			LastLoginAt: login,
		},
	}}
	p := New(Options{API: api, Tenant: "tenant-123", Now: fixedNow})

	records, err := p.Collect(context.Background(), acceptDirectoryUser())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if records[0].ID != "u-adele" || records[1].ID != "u-zelda" {
		t.Fatalf("records not sorted by ID: %q, %q", records[0].ID, records[1].ID)
	}

	adele := records[0]
	if adele.IdentityKey != "adele@contoso.com" {
		t.Errorf("IdentityKey = %q, want adele@contoso.com", adele.IdentityKey)
	}
	if adele.SourceID != "azure.entra" || adele.Type != "directory_user" {
		t.Errorf("unexpected SourceID/Type: %q/%q", adele.SourceID, adele.Type)
	}
	if !adele.CollectedAt.Equal(fixedNow()) {
		t.Errorf("CollectedAt = %v, want %v", adele.CollectedAt, fixedNow())
	}
	if adele.Scope == nil || adele.Scope.Account != "tenant-123" {
		t.Errorf("Scope.Account = %v, want tenant-123", adele.Scope)
	}

	var got userPayload
	if err := json.Unmarshal(adele.Payload, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	want := userPayload{
		ID:          "u-adele",
		DisplayName: "Adele V",
		Email:       "adele@contoso.com",
		MFAEnabled:  true,
		IsAdmin:     true,
		IsActive:    true,
		LastLoginAt: &login,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("payload mismatch:\n got %+v\nwant %+v", got, want)
	}

	// The disabled, never-logged-in user: last_login_at must be omitted.
	if strings.Contains(string(records[1].Payload), "last_login_at") {
		t.Errorf("zero last-login should be omitted, got %s", records[1].Payload)
	}
}

func TestCollect_EmailFallbackToUPN(t *testing.T) {
	t.Parallel()
	// Guest with no mailbox: Email empty → IdentityKey falls back to UPN,
	// and the email field is omitted from the payload (no format:email risk).
	api := &fakeAPI{users: []User{
		{ID: "u-guest", UPN: "guest_ext#EXT#@contoso.com", DisplayName: "", IsActive: true},
	}}
	p := New(Options{API: api, Now: fixedNow})
	records, err := p.Collect(context.Background(), acceptDirectoryUser())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	rec := records[0]
	if rec.IdentityKey != "guest_ext#EXT#@contoso.com" {
		t.Errorf("IdentityKey = %q, want UPN fallback", rec.IdentityKey)
	}
	if strings.Contains(string(rec.Payload), "\"email\"") {
		t.Errorf("empty email should be omitted, got %s", rec.Payload)
	}
	// Empty displayName falls back to UPN.
	var got userPayload
	if err := json.Unmarshal(rec.Payload, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got.DisplayName != "guest_ext#EXT#@contoso.com" {
		t.Errorf("DisplayName = %q, want UPN fallback", got.DisplayName)
	}
}

func TestCollect_ErrorPropagation(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("boom")
	p := New(Options{API: &fakeAPI{err: wantErr}})
	_, err := p.Collect(context.Background(), acceptDirectoryUser())
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped %v", err, wantErr)
	}
}

func TestCollect_KISSNoDRY_RefetchesEachCall(t *testing.T) {
	t.Parallel()
	api := &fakeAPI{users: []User{{ID: "u1", UPN: "a@b.com"}}}
	p := New(Options{API: api, Now: fixedNow})
	for i := 0; i < 3; i++ {
		if _, err := p.Collect(context.Background(), acceptDirectoryUser()); err != nil {
			t.Fatalf("Collect #%d: %v", i, err)
		}
	}
	if api.calls != 3 {
		t.Errorf("ListUsers called %d times, want 3 (no caching)", api.calls)
	}
}

// --- real Microsoft Graph adapter (httptest) ---

// fakeCred returns a static bearer token, mirroring azcommon_test's fakeCred.
type fakeCred struct{ err error }

func (f fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func newRealGraph(base string) *realGraph {
	return &realGraph{base: base, client: &http.Client{}, cred: fakeCred{}}
}

// newGraphFixture stands in for Microsoft Graph: a single page of
// registration details and a two-page /users listing (the first page
// advertises an absolute @odata.nextLink back to itself). The handler asserts
// the bearer token on every request.
func newGraphFixture(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want Bearer test-token", got)
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/reports/authenticationMethods/userRegistrationDetails"):
			writeJSON(t, w, map[string]any{"value": []map[string]any{
				{"id": "u-adele", "isAdmin": true, "isMfaRegistered": true},
				{"id": "u-bob", "isAdmin": false, "isMfaRegistered": false},
			}})
		case strings.HasPrefix(r.URL.Path, "/users") && r.URL.Query().Get("page") == "2":
			writeJSON(t, w, map[string]any{"value": []map[string]any{
				{"id": "u-carol", "userPrincipalName": "carol@contoso.com", "mail": nil, "displayName": "Carol", "accountEnabled": false},
			}})
		case strings.HasPrefix(r.URL.Path, "/users"):
			writeJSON(t, w, map[string]any{
				"@odata.nextLink": srv.URL + "/users?page=2",
				"value": []map[string]any{
					{"id": "u-adele", "userPrincipalName": "adele@contoso.com", "mail": "adele@contoso.com", "displayName": "Adele", "accountEnabled": true,
						"signInActivity": map[string]any{"lastSignInDateTime": "2026-05-01T09:30:00Z"}},
					{"id": "u-bob", "userPrincipalName": "bob@contoso.com", "mail": "bob@contoso.com", "displayName": "Bob", "accountEnabled": true},
				},
			})
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}))
	return srv
}

func TestRealGraph_ListUsers_MergesAndPaginates(t *testing.T) {
	t.Parallel()
	srv := newGraphFixture(t)
	defer srv.Close()

	users, err := newRealGraph(srv.URL).ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("got %d users, want 3 (2 + paginated 1)", len(users))
	}
	byID := map[string]User{}
	for _, u := range users {
		byID[u.ID] = u
	}

	want := []User{
		{ID: "u-adele", Email: "adele@contoso.com", MFAEnabled: true, IsAdmin: true, IsActive: true, LastLoginAt: time.Date(2026, 5, 1, 9, 30, 0, 0, time.UTC)},
		// Bob present in the report (non-mfa, non-admin), never signed in.
		{ID: "u-bob", Email: "bob@contoso.com", IsActive: true},
		// Carol absent from the report → honest false flags; nil mail → empty email.
		{ID: "u-carol"},
	}
	for i := range want {
		got := byID[want[i].ID]
		assertEntraUser(t, &got, &want[i])
	}
}

// assertEntraUser checks the merge-relevant fields of a collected user.
func assertEntraUser(t *testing.T, got, want *User) {
	t.Helper()
	if got.MFAEnabled != want.MFAEnabled || got.IsAdmin != want.IsAdmin || got.IsActive != want.IsActive {
		t.Errorf("%s flags = mfa:%v admin:%v active:%v, want %v/%v/%v",
			want.ID, got.MFAEnabled, got.IsAdmin, got.IsActive, want.MFAEnabled, want.IsAdmin, want.IsActive)
	}
	if got.Email != want.Email {
		t.Errorf("%s email = %q, want %q", want.ID, got.Email, want.Email)
	}
	if want.LastLoginAt.IsZero() {
		if !got.LastLoginAt.IsZero() {
			t.Errorf("%s want zero last login, got %v", want.ID, got.LastLoginAt)
		}
	} else if !got.LastLoginAt.Equal(want.LastLoginAt) {
		t.Errorf("%s last login = %v, want %v", want.ID, got.LastLoginAt, want.LastLoginAt)
	}
}

func TestRealGraph_RegistrationReportError_HasLicensingHint(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/reports/") {
			http.Error(w, `{"error":{"code":"Authorization_RequestDenied"}}`, http.StatusForbidden)
			return
		}
		t.Errorf("users should not be fetched after report failure; got %s", r.URL.Path)
	}))
	defer srv.Close()

	_, err := newRealGraph(srv.URL).ListUsers(context.Background())
	if err == nil {
		t.Fatal("expected error on report 403")
	}
	if !strings.Contains(err.Error(), "AuditLog.Read.All") || !strings.Contains(err.Error(), "P1/P2") {
		t.Errorf("error missing licensing hint: %v", err)
	}
}

func TestRealGraph_UsersError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/reports/") {
			writeJSON(t, w, map[string]any{"value": []map[string]any{}})
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := newRealGraph(srv.URL).ListUsers(context.Background())
	if err == nil || !strings.Contains(err.Error(), "list users") {
		t.Fatalf("want list-users error, got %v", err)
	}
}

func TestRealGraph_TokenError(t *testing.T) {
	t.Parallel()
	r := &realGraph{base: "http://unused", client: &http.Client{}, cred: fakeCred{err: errors.New("no creds")}}
	_, err := r.ListUsers(context.Background())
	if err == nil || !strings.Contains(err.Error(), "graph token") {
		t.Fatalf("want graph-token error, got %v", err)
	}
}

func TestNewFromGraph_UsesGraphBaseAndTenant(t *testing.T) {
	t.Parallel()
	p := NewFromGraph(fakeCred{}, azcommon.Config{TenantID: "t-1"})
	if p.tenant != "t-1" {
		t.Errorf("tenant = %q, want t-1", p.tenant)
	}
	rg, ok := p.api.(*realGraph)
	if !ok {
		t.Fatalf("api type = %T, want *realGraph", p.api)
	}
	if rg.base != graphBaseURL {
		t.Errorf("base = %q, want %q", rg.base, graphBaseURL)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
