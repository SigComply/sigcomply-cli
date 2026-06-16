package directory

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI lets tests drive the plugin without hitting Google. It records
// the customer argument so we can assert the default-alias behavior.
type fakeAPI struct {
	users    []*admin.User
	err      error
	calls    int
	customer string
}

func (f *fakeAPI) ListUsers(_ context.Context, customer string) ([]*admin.User, error) {
	f.calls++
	f.customer = customer
	if f.err != nil {
		return nil, f.err
	}
	return f.users, nil
}

func directoryReq() core.SlotRequest {
	return core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1"}
}

func TestIDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != "gcp.directory" {
		t.Errorf("ID = %q; want gcp.directory", p.ID())
	}
	emits := p.Emits()
	if len(emits) != 1 || emits[0] != "directory_user" {
		t.Errorf("Emits = %v; want [directory_user]", emits)
	}
}

func TestInit_NoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// decodePayload unmarshals an evidence record's payload or fails the test.
func decodePayload(t *testing.T, r *core.EvidenceRecord) userPayload {
	t.Helper()
	var p userPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("Unmarshal payload: %v", err)
	}
	return p
}

func TestCollect_HappyPath_SortsByID_AndMapsFields(t *testing.T) {
	fake := &fakeAPI{users: []*admin.User{
		{ // Zoe: 2SV on, not admin, active — listed second despite earlier input.
			Id:              "200",
			PrimaryEmail:    "zoe@acme.com",
			Name:            &admin.UserName{FullName: "Zoe Zane"},
			IsEnrolledIn2Sv: true,
		},
		{ // Alice: no 2SV, super-admin, suspended.
			Id:           "100",
			PrimaryEmail: "alice@acme.com",
			Name:         &admin.UserName{FullName: "Alice Adams"},
			IsAdmin:      true,
			Suspended:    true,
		},
	}}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), directoryReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len = %d; want 2", len(records))
	}
	// Sorted by ID ascending: "100" (alice) before "200" (zoe).
	if records[0].ID != "100" || records[1].ID != "200" {
		t.Fatalf("not sorted by ID: %q, %q", records[0].ID, records[1].ID)
	}

	wantRecordMeta(t, &records[0], "alice@acme.com", now)
	wantRecordMeta(t, &records[1], "zoe@acme.com", now)

	wantAlice := userPayload{ID: "100", DisplayName: "Alice Adams", Email: "alice@acme.com", MFAEnabled: false, IsAdmin: true, IsActive: false}
	if got := decodePayload(t, &records[0]); !reflect.DeepEqual(got, wantAlice) {
		t.Errorf("alice payload = %+v; want %+v", got, wantAlice)
	}
	wantZoe := userPayload{ID: "200", DisplayName: "Zoe Zane", Email: "zoe@acme.com", MFAEnabled: true, IsAdmin: false, IsActive: true}
	if got := decodePayload(t, &records[1]); !reflect.DeepEqual(got, wantZoe) {
		t.Errorf("zoe payload = %+v; want %+v", got, wantZoe)
	}
}

// wantRecordMeta asserts the record-level (non-payload) fields.
func wantRecordMeta(t *testing.T, r *core.EvidenceRecord, wantIdentity string, now time.Time) {
	t.Helper()
	if r.Type != EvidenceTypeID {
		t.Errorf("Type = %q; want %q", r.Type, EvidenceTypeID)
	}
	if r.SourceID != SourceID {
		t.Errorf("SourceID = %q; want %q", r.SourceID, SourceID)
	}
	if r.IdentityKey != wantIdentity {
		t.Errorf("IdentityKey = %q; want %q", r.IdentityKey, wantIdentity)
	}
	if !r.CollectedAt.Equal(now) {
		t.Errorf("CollectedAt = %v; want %v", r.CollectedAt, now)
	}
}

func TestCollect_DelegatedAdmin_CountsAsAdmin(t *testing.T) {
	fake := &fakeAPI{users: []*admin.User{
		{Id: "1", PrimaryEmail: "deleg@acme.com", IsDelegatedAdmin: true},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), directoryReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var u userPayload
	if err := json.Unmarshal(records[0].Payload, &u); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !u.IsAdmin {
		t.Errorf("delegated admin IsAdmin = false; want true")
	}
}

func TestCollect_NilNameAndNilUser_NoPanic(t *testing.T) {
	fake := &fakeAPI{users: []*admin.User{
		nil,
		{Id: "1", PrimaryEmail: "noname@acme.com", Name: nil},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), directoryReq())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len = %d; want 1 (nil user skipped)", len(records))
	}
	var u userPayload
	if err := json.Unmarshal(records[0].Payload, &u); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if u.DisplayName != "" {
		t.Errorf("DisplayName = %q; want empty (nil Name)", u.DisplayName)
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"object_storage_bucket"}})
	if err == nil {
		t.Fatal("want error for unaccepted type; got nil")
	}
}

func TestCollect_PropagatesAPIError(t *testing.T) {
	wantErr := errors.New("boom")
	p := New(Options{API: &fakeAPI{err: wantErr}})
	_, err := p.Collect(context.Background(), directoryReq())
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("err = %v; want wrapped %v", err, wantErr)
	}
}

func TestCollect_KISS_NoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{users: []*admin.User{{Id: "1", PrimaryEmail: "a@acme.com"}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), directoryReq()); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.calls != 3 {
		t.Errorf("calls = %d; want 3 (no caching per KISS-no-DRY)", fake.calls)
	}
}

func TestCollect_DefaultsCustomerAlias(t *testing.T) {
	fake := &fakeAPI{}
	p := New(Options{API: fake}) // no Customer set
	if _, err := p.Collect(context.Background(), directoryReq()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.customer != defaultCustomer {
		t.Errorf("customer = %q; want %q", fake.customer, defaultCustomer)
	}
}

func TestCollect_HonorsExplicitCustomer(t *testing.T) {
	fake := &fakeAPI{}
	p := New(Options{API: fake, Customer: "C01abc"})
	if _, err := p.Collect(context.Background(), directoryReq()); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.customer != "C01abc" {
		t.Errorf("customer = %q; want C01abc", fake.customer)
	}
}

// TestRealDirectory_ListUsers_Pagination exercises the production
// adapter against an httptest server, verifying it pages through
// NextPageToken and accumulates users across pages. This covers the
// real SDK path the fakeAPI tests skip.
func TestRealDirectory_ListUsers_Pagination(t *testing.T) {
	page1, err := json.Marshal(admin.Users{
		Users:         []*admin.User{{Id: "1", PrimaryEmail: "a@acme.com"}},
		NextPageToken: "page2",
	})
	if err != nil {
		t.Fatalf("marshal page1: %v", err)
	}
	page2, err := json.Marshal(admin.Users{
		Users: []*admin.User{{Id: "2", PrimaryEmail: "b@acme.com"}},
	})
	if err != nil {
		t.Fatalf("marshal page2: %v", err)
	}

	var gotCustomer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCustomer = r.URL.Query().Get("customer")
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("pageToken") {
		case "":
			_, _ = w.Write(page1) //nolint:errcheck // test handler
		case "page2":
			_, _ = w.Write(page2) //nolint:errcheck // test handler
		default:
			http.Error(w, "unexpected page", http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	svc, err := admin.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	r := &realDirectory{svc: svc}
	users, err := r.ListUsers(context.Background(), defaultCustomer)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("len = %d; want 2 (both pages)", len(users))
	}
	if users[0].Id != "1" || users[1].Id != "2" {
		t.Errorf("ids = %q,%q; want 1,2", users[0].Id, users[1].Id)
	}
	if gotCustomer != defaultCustomer {
		t.Errorf("customer query = %q; want %q", gotCustomer, defaultCustomer)
	}
}

// TestRealDirectory_ListUsers_Error verifies the adapter surfaces HTTP
// errors from the Admin SDK.
func TestRealDirectory_ListUsers_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	svc, err := admin.NewService(context.Background(),
		option.WithoutAuthentication(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	r := &realDirectory{svc: svc}
	if _, err := r.ListUsers(context.Background(), defaultCustomer); err == nil {
		t.Fatal("want error from 403; got nil")
	}
}
