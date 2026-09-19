package identitycenter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	istypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// identitycenter_test.go: aws.identity_center L1 — fake-API unit tests for the
// field mapping, the roster status normalisation, lazy identity-store
// discovery, and the slot-mismatch error.

// Fixture vocabulary shared by every test in this package — the fake-API
// unit tests and the cassette conformance tests alike. Case-varied
// spellings ("User-A1B2C3@Example.com", " ENABLED") stay inline: they are
// the point of the normalisation assertions.
const (
	// testStoreID is the identity store both the fake API and the
	// cassette serve.
	testStoreID = "d-9067012345"

	// The first fixture user, present in both the fake pages and the
	// cassette.
	testUserName    = "example-user"
	testDisplayName = "Ada Example"
	testUserEmail   = "user-a1b2c3@example.com"

	// testEmployeeType is the SCIM userType that user carries.
	testEmployeeType = "employee"

	// fieldEmail is the payload key / table label for the address.
	fieldEmail = "email"

	// Raw UserStatus values exactly as the identity store spells them.
	statusEnabled  = "ENABLED"
	statusDisabled = "DISABLED"
)

var testNow = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

// fakeAPI is the in-memory stand-in for the two AWS clients. pages is served
// one ListUsers call at a time so pagination is exercised without a cassette.
type fakeAPI struct {
	instances     []ssotypes.InstanceMetadata
	instancesErr  error
	pages         [][]istypes.User
	usersErr      error
	listUsersCall int
	seenStoreIDs  []string
	listInstances int
}

func (f *fakeAPI) ListInstances(context.Context, *ssoadmin.ListInstancesInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
	f.listInstances++
	if f.instancesErr != nil {
		return nil, f.instancesErr
	}
	return &ssoadmin.ListInstancesOutput{Instances: f.instances}, nil
}

func (f *fakeAPI) ListUsers(_ context.Context, in *identitystore.ListUsersInput, _ ...func(*identitystore.Options)) (*identitystore.ListUsersOutput, error) {
	if f.usersErr != nil {
		return nil, f.usersErr
	}
	f.seenStoreIDs = append(f.seenStoreIDs, deref(in.IdentityStoreId))
	i := f.listUsersCall
	f.listUsersCall++
	if i >= len(f.pages) {
		return &identitystore.ListUsersOutput{}, nil
	}
	out := &identitystore.ListUsersOutput{Users: f.pages[i]}
	if i+1 < len(f.pages) {
		next := fmt.Sprintf("page-%d", i+1)
		out.NextToken = &next
	}
	return out, nil
}

func s(v string) *string { return &v }

func instance(storeID string) ssotypes.InstanceMetadata {
	return ssotypes.InstanceMetadata{IdentityStoreId: s(storeID), InstanceArn: s("arn:aws:sso:::instance/ssoins-1111aaaa2222bbbb")}
}

func newFakePlugin(t *testing.T, api *fakeAPI, storeID string) *Plugin {
	t.Helper()
	return New(Options{
		API:             api,
		Region:          "eu-west-1",
		IdentityStoreID: storeID,
		Now:             func() time.Time { return testNow },
	})
}

func collect(t *testing.T, p *Plugin, types ...string) []core.EvidenceRecord {
	t.Helper()
	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: types})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return recs
}

func payloadOf[T any](t *testing.T, r *core.EvidenceRecord) T {
	t.Helper()
	var p T
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		t.Fatalf("unmarshal %s payload: %v", r.Type, err)
	}
	return p
}

// assertPayloadOmits fails for every key that is present in the payload.
// An unknowable field must be ABSENT, never emitted as false/zero/"" —
// the null trap — because roster_entry is additionalProperties:false with
// minLength:1 on its optional strings and directory_user consumers read
// "absent" as "not observed".
func assertPayloadOmits(t *testing.T, payload json.RawMessage, keys ...string) {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	for _, k := range keys {
		if _, ok := raw[k]; ok {
			t.Errorf("payload carries %q; an unknowable field must be omitted", k)
		}
	}
}

// --- identity metadata -----------------------------------------------------

func TestIDAndEmits(t *testing.T) {
	p := New(Options{})
	if p.ID() != "aws.identity_center" {
		t.Errorf("ID() = %q", p.ID())
	}
	if got := p.Emits(); len(got) != 2 || got[0] != EvidenceTypeDirectoryUser || got[1] != EvidenceTypeRosterEntry {
		t.Errorf("Emits() = %v", got)
	}
	// directory_user, never directory_user.v2: the v2-only root/access-key
	// policies must not see SSO identities and pass trivially.
	for _, et := range p.Emits() {
		if strings.HasSuffix(et, ".v2") {
			t.Errorf("Emits() includes %q; Identity Center must emit the v1 shape", et)
		}
	}
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

// --- directory_user mapping ------------------------------------------------

func TestCollectDirectoryUserFieldMapping(t *testing.T) {
	created := time.Date(2024, 3, 1, 9, 30, 0, 0, time.UTC)
	api := &fakeAPI{pages: [][]istypes.User{{{
		UserId:      s("u-1"),
		UserName:    s(testUserName),
		DisplayName: s(testDisplayName),
		UserStatus:  istypes.UserStatusEnabled,
		UserType:    s(testEmployeeType),
		CreatedAt:   &created,
		Emails: []istypes.Email{
			{Value: s("alias-a1b2c3@example.com")},
			{Value: s(testUserEmail), Primary: true},
		},
	}}}}
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeDirectoryUser)
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	r := recs[0]
	p := payloadOf[userPayload](t, &r)

	// Every scalar the mapping owes us, as one table: a new field is a
	// new row rather than another branch.
	for _, c := range []struct {
		field string
		got   any
		want  any
	}{
		{"Type", r.Type, EvidenceTypeDirectoryUser},
		{"ID", r.ID, "u-1"},
		{"SourceID", r.SourceID, SourceID},
		// The lowercased *primary* email, not the first address listed.
		{"IdentityKey", r.IdentityKey, testUserEmail},
		{"username", p.Username, testUserName},
		{"display_name", p.DisplayName, testDisplayName},
		{fieldEmail, p.Email, testUserEmail},
		// Identity Center publishes no MFA state, so it must be false.
		{"mfa_enabled", p.MFAEnabled, false},
		// An ENABLED user is active.
		{"is_active", p.IsActive, true},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}
	if !r.CollectedAt.Equal(testNow) {
		t.Errorf("CollectedAt = %v, want the injected clock %v", r.CollectedAt, testNow)
	}
	if p.CreatedAt == nil || !p.CreatedAt.Equal(created) {
		t.Errorf("created_at = %v, want %v", p.CreatedAt, created)
	}
	if r.Scope == nil || r.Scope.Account != testStoreID || r.Scope.Region != "eu-west-1" {
		t.Errorf("Scope = %+v", r.Scope)
	}
	// is_admin / last_login_at / mfa_factor_count are unknowable here and must
	// be ABSENT, not false/zero (the null trap).
	assertPayloadOmits(t, r.Payload, "is_admin", "last_login_at", "mfa_factor_count", "is_service_account", "is_external")
}

func TestCollectDirectoryUserIdentityKeyIsLowercased(t *testing.T) {
	api := &fakeAPI{pages: [][]istypes.User{{{
		UserId: s("u-1"), UserName: s(testUserName), UserStatus: istypes.UserStatusEnabled,
		Emails: []istypes.Email{{Value: s("User-A1B2C3@Example.com"), Primary: true}},
	}}}}
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeDirectoryUser, EvidenceTypeRosterEntry)
	for _, r := range recs {
		if r.IdentityKey != testUserEmail {
			t.Errorf("%s IdentityKey = %q, want lowercased", r.Type, r.IdentityKey)
		}
	}
}

func TestDisplayNameFallbacks(t *testing.T) {
	cases := []struct {
		name string
		user istypes.User
		want string
	}{
		{"display name wins", istypes.User{UserId: s("u"), UserName: s("un"), DisplayName: s(testDisplayName),
			Name: &istypes.Name{Formatted: s("Formatted")}}, testDisplayName},
		{"formatted next", istypes.User{UserId: s("u"), UserName: s("un"),
			Name: &istypes.Name{Formatted: s(testDisplayName), GivenName: s("Ada")}}, testDisplayName},
		{"given + family", istypes.User{UserId: s("u"), UserName: s("un"),
			Name: &istypes.Name{GivenName: s("Ada"), FamilyName: s("Example")}}, testDisplayName},
		{"user name last", istypes.User{UserId: s("u"), UserName: s(testUserName)}, testUserName},
		{"empty name object falls through", istypes.User{UserId: s("u"), UserName: s(testUserName),
			Name: &istypes.Name{}}, testUserName},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.user.UserStatus = istypes.UserStatusEnabled
			api := &fakeAPI{pages: [][]istypes.User{{c.user}}}
			recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeDirectoryUser)
			if got := payloadOf[userPayload](t, &recs[0]).DisplayName; got != c.want {
				t.Errorf("display_name = %q, want %q", got, c.want)
			}
		})
	}
}

// TestEmailOnlyWhenAddressShaped guards the schema's format:email — the
// collector validates every payload before signing, so a non-address value
// would fail the whole binding rather than one field.
func TestEmailOnlyWhenAddressShaped(t *testing.T) {
	for _, raw := range []string{"not-an-email", "@example.com", "user@", "user@localhost", "us er@example.com", ""} {
		api := &fakeAPI{pages: [][]istypes.User{{{
			UserId: s("u-1"), UserName: s(testUserName), UserStatus: istypes.UserStatusEnabled,
			Emails: []istypes.Email{{Value: s(raw), Primary: true}},
		}}}}
		recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeDirectoryUser)
		if got := payloadOf[userPayload](t, &recs[0]).Email; got != "" {
			t.Errorf("email for %q = %q, want dropped", raw, got)
		}
	}
	api := &fakeAPI{pages: [][]istypes.User{{{
		UserId: s("u-1"), UserName: s(testUserName), UserStatus: istypes.UserStatusEnabled,
		Emails: []istypes.Email{{Value: s(testUserEmail), Primary: true}},
	}}}}
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeDirectoryUser)
	if got := payloadOf[userPayload](t, &recs[0]).Email; got != testUserEmail {
		t.Errorf("email = %q, want kept", got)
	}
}

// --- roster_entry mapping --------------------------------------------------

func TestRosterStatusNormalisation(t *testing.T) {
	cases := map[string]string{
		statusEnabled: rosterActive,
		"enabled":     rosterActive,
		// Deliberate: the normalizer must trim, so a raw value the
		// directory returned with stray whitespace still resolves.
		//nolint:gocritic // deliberate: asserts the normalizer trims
		" ENABLED": rosterActive,
		// Absent status: a store that predates the attribute returns nothing
		// for every user, and "the whole directory is inactive" is not a
		// useful verdict — directory_user's own default is "assume active".
		"":             rosterActive,
		statusDisabled: rosterInactive,
		// Fail-safe default: an unknown status never vouches for an account.
		"SUSPENDED":                rosterInactive,
		"SOMETHING_AWS_ADDS_LATER": rosterInactive,
	}
	for raw, want := range cases {
		if got := rosterStatus(raw); got != want {
			t.Errorf("rosterStatus(%q) = %q, want %q", raw, got, want)
		}
	}
	// roster_entry's enum is closed; nothing else may ever be emitted.
	for raw := range cases {
		got := rosterStatus(raw)
		if got != rosterActive && got != rosterInactive {
			t.Errorf("rosterStatus(%q) = %q, outside the schema enum", raw, got)
		}
	}
}

func TestRosterEntryFieldMapping(t *testing.T) {
	api := &fakeAPI{pages: [][]istypes.User{{
		{UserId: s("u-1"), UserName: s(testUserName), DisplayName: s(testDisplayName),
			UserStatus: istypes.UserStatusEnabled, UserType: s(testEmployeeType),
			Emails: []istypes.Email{{Value: s(testUserEmail), Primary: true}}},
		{UserId: s("u-2"), UserName: s("example-user-2"), UserStatus: istypes.UserStatusDisabled},
	}}}
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeRosterEntry)
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2", len(recs))
	}
	first := payloadOf[rosterPayload](t, &recs[0])
	switch {
	case first.Status != rosterActive:
		t.Errorf("status = %q", first.Status)
	case first.SourceStatus != statusEnabled:
		t.Errorf("source_status = %q, want the directory's own value", first.SourceStatus)
	case first.EmployeeType != testEmployeeType:
		t.Errorf("employee_type = %q, want the SCIM userType", first.EmployeeType)
	case first.DisplayName != testDisplayName:
		t.Errorf("display_name = %q", first.DisplayName)
	}
	// roster_entry is additionalProperties:false with minLength:1 on every
	// optional string, so an unknown value must be OMITTED, never "".
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(recs[1].Payload, &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{fieldEmail, "employee_type", "employee_id", "is_service_account"} {
		if _, ok := raw[k]; ok {
			t.Errorf("roster payload carries %q for a user without one", k)
		}
	}
	if _, ok := raw["display_name"]; !ok {
		t.Error("roster payload dropped display_name; it falls back to the user name")
	}
}

// TestRosterEntryWithoutEmailIsStillEmitted pins the roster_entry contract:
// an entry with no email cannot vouch for an account, so the accounts that
// would have matched surface as unlinked rather than silently passing.
func TestRosterEntryWithoutEmailIsStillEmitted(t *testing.T) {
	api := &fakeAPI{pages: [][]istypes.User{{{
		UserId: s("u-1"), UserName: s(testUserName), UserStatus: istypes.UserStatusEnabled,
	}}}}
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeRosterEntry)
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1 (an emailless person is still on the roster)", len(recs))
	}
	if recs[0].IdentityKey != "" {
		t.Errorf("IdentityKey = %q, want empty", recs[0].IdentityKey)
	}
}

// --- slot selection, ordering, pagination ----------------------------------

func TestCollectEmitsOnlyAcceptedTypes(t *testing.T) {
	users := []istypes.User{{UserId: s("u-1"), UserName: s(testUserName), UserStatus: istypes.UserStatusEnabled}}
	for _, c := range []struct {
		accepts []string
		want    int
	}{
		{[]string{EvidenceTypeDirectoryUser}, 1},
		{[]string{EvidenceTypeRosterEntry}, 1},
		{[]string{EvidenceTypeDirectoryUser, EvidenceTypeRosterEntry}, 2},
		{[]string{"iam_binding", EvidenceTypeRosterEntry}, 1},
	} {
		api := &fakeAPI{pages: [][]istypes.User{users}}
		recs := collect(t, newFakePlugin(t, api, testStoreID), c.accepts...)
		if len(recs) != c.want {
			t.Errorf("accepts %v → %d records, want %d", c.accepts, len(recs), c.want)
		}
	}
}

// TestCollectRejectsUnacceptedSlot: a slot accepting none of the plugin's
// types is a planner bug, not an empty result.
func TestCollectRejectsUnacceptedSlot(t *testing.T) {
	api := &fakeAPI{pages: [][]istypes.User{{{UserId: s("u-1"), UserStatus: istypes.UserStatusEnabled}}}}
	p := newFakePlugin(t, api, testStoreID)
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"directory_user.v2", "iam_binding"}})
	if err == nil {
		t.Fatal("Collect with an unaccepted slot returned no error")
	}
	if !strings.Contains(err.Error(), "aws.identity_center") || !strings.Contains(err.Error(), "directory_user") {
		t.Errorf("error = %v; want it to name the source and the emitted types", err)
	}
	if api.listUsersCall != 0 {
		t.Error("Collect called ListUsers despite the slot accepting nothing")
	}
}

func TestCollectPaginatesAndSortsStably(t *testing.T) {
	api := &fakeAPI{pages: [][]istypes.User{
		{{UserId: s("u-3"), UserName: s("example-user-3"), UserStatus: istypes.UserStatusEnabled}},
		{{UserId: s("u-1"), UserName: s(testUserName), UserStatus: istypes.UserStatusEnabled},
			{UserId: s("u-2"), UserName: s("example-user-2"), UserStatus: istypes.UserStatusEnabled}},
	}}
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeDirectoryUser, EvidenceTypeRosterEntry)
	if len(recs) != 6 {
		t.Fatalf("records = %d, want 6 (3 paged users x 2 types)", len(recs))
	}
	if api.listUsersCall != 2 {
		t.Errorf("ListUsers calls = %d, want 2 (NextToken followed)", api.listUsersCall)
	}
	for i := 1; i < len(recs); i++ {
		if recs[i-1].ID > recs[i].ID {
			t.Fatalf("records not sorted by ID: %q before %q", recs[i-1].ID, recs[i].ID)
		}
	}
	// Stable within one ID: directory_user is emitted before roster_entry.
	if recs[0].Type != EvidenceTypeDirectoryUser || recs[1].Type != EvidenceTypeRosterEntry {
		t.Errorf("per-ID order = %q,%q", recs[0].Type, recs[1].Type)
	}
}

func TestCollectSkipsUserWithoutID(t *testing.T) {
	api := &fakeAPI{pages: [][]istypes.User{{
		{UserName: s(testUserName), UserStatus: istypes.UserStatusEnabled},
		{UserId: s("u-1"), UserName: s("example-user-2"), UserStatus: istypes.UserStatusEnabled},
	}}}
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeDirectoryUser)
	if len(recs) != 1 || recs[0].ID != "u-1" {
		t.Errorf("records = %+v, want only the user carrying an id", recs)
	}
}

func TestCollectPropagatesListUsersError(t *testing.T) {
	api := &fakeAPI{usersErr: errors.New("AccessDeniedException")}
	p := newFakePlugin(t, api, testStoreID)
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}})
	if err == nil || !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Fatalf("err = %v, want the AWS error wrapped", err)
	}
}

// --- lazy identity-store discovery -----------------------------------------

func TestConfiguredStoreIDSkipsDiscovery(t *testing.T) {
	api := &fakeAPI{pages: [][]istypes.User{{{UserId: s("u-1"), UserStatus: istypes.UserStatusEnabled}}}}
	collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeDirectoryUser)
	if api.listInstances != 0 {
		t.Errorf("ListInstances calls = %d; a configured identity_store_id needs none", api.listInstances)
	}
	if len(api.seenStoreIDs) != 1 || api.seenStoreIDs[0] != testStoreID {
		t.Errorf("ListUsers IdentityStoreId = %v, want %q", api.seenStoreIDs, testStoreID)
	}
}

func TestDiscoversStoreIDFromSingleInstance(t *testing.T) {
	api := &fakeAPI{
		instances: []ssotypes.InstanceMetadata{instance(testStoreID)},
		pages:     [][]istypes.User{{{UserId: s("u-1"), UserStatus: istypes.UserStatusEnabled}}},
	}
	recs := collect(t, newFakePlugin(t, api, ""), EvidenceTypeDirectoryUser)
	if api.listInstances != 1 {
		t.Errorf("ListInstances calls = %d, want 1", api.listInstances)
	}
	if len(api.seenStoreIDs) != 1 || api.seenStoreIDs[0] != testStoreID {
		t.Errorf("ListUsers IdentityStoreId = %v, want the discovered %q", api.seenStoreIDs, testStoreID)
	}
	if recs[0].Scope == nil || recs[0].Scope.Account != testStoreID {
		t.Errorf("Scope = %+v, want the discovered store id", recs[0].Scope)
	}
}

func TestDiscoveryIgnoresInstancesWithoutStoreID(t *testing.T) {
	api := &fakeAPI{
		instances: []ssotypes.InstanceMetadata{{InstanceArn: s("arn:aws:sso:::instance/ssoins-0000")}, instance(testStoreID)},
		pages:     [][]istypes.User{{{UserId: s("u-1"), UserStatus: istypes.UserStatusEnabled}}},
	}
	collect(t, newFakePlugin(t, api, ""), EvidenceTypeDirectoryUser)
	if len(api.seenStoreIDs) != 1 || api.seenStoreIDs[0] != testStoreID {
		t.Errorf("IdentityStoreId = %v, want %q", api.seenStoreIDs, testStoreID)
	}
}

func TestDiscoveryErrors(t *testing.T) {
	cases := []struct {
		name string
		api  *fakeAPI
		want string
	}{
		{"no instance", &fakeAPI{}, "no IAM Identity Center instance"},
		{"ambiguous", &fakeAPI{instances: []ssotypes.InstanceMetadata{instance("d-1111111111"), instance("d-2222222222")}}, "identity_store_id"},
		{"api error", &fakeAPI{instancesErr: errors.New("AccessDeniedException")}, "AccessDeniedException"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.api.pages = [][]istypes.User{{{UserId: s("u-1"), UserStatus: istypes.UserStatusEnabled}}}
			p := newFakePlugin(t, c.api, "")
			_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}})
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "aws.identity_center") {
				t.Errorf("error = %v, want it to mention %q", err, c.want)
			}
			if c.api.listUsersCall != 0 {
				t.Error("ListUsers was called despite discovery failing")
			}
		})
	}
}

func TestNewDefaultsClockToNow(t *testing.T) {
	api := &fakeAPI{pages: [][]istypes.User{{{UserId: s("u-1"), UserStatus: istypes.UserStatusEnabled}}}}
	p := New(Options{API: api, Region: "us-east-1", IdentityStoreID: " " + testStoreID + " "})
	before := time.Now().UTC().Add(-time.Second)
	recs := collect(t, p, EvidenceTypeDirectoryUser)
	if recs[0].CollectedAt.Before(before) {
		t.Errorf("CollectedAt = %v, want a real clock", recs[0].CollectedAt)
	}
	if api.listInstances != 0 || api.seenStoreIDs[0] != testStoreID {
		t.Errorf("identity_store_id was not trimmed: %v", api.seenStoreIDs)
	}
}

func TestNewFromAWSResolvesCredentialsEagerly(t *testing.T) {
	// No credentials at all: the factory path must fail as a config error
	// rather than build a client that reports an empty account later.
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", t.TempDir()+"/none")
	t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/none")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
	if _, err := NewFromAWS(context.Background(), "us-east-1", ""); err == nil {
		t.Error("NewFromAWS succeeded with no credentials; it must resolve them eagerly")
	} else if !strings.Contains(err.Error(), "aws.identity_center") {
		t.Errorf("error = %v, want it prefixed with the source id", err)
	}
}

func TestNewFromAWSWithCredentials(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	p, err := NewFromAWS(context.Background(), "us-east-1", testStoreID)
	if err != nil {
		t.Fatalf("NewFromAWS: %v", err)
	}
	if p.identityStoreID != testStoreID || p.region != "us-east-1" {
		t.Errorf("plugin = %+v", p)
	}
	if _, ok := p.api.(*awsAPI); !ok {
		t.Errorf("api = %T, want the real SDK adapter", p.api)
	}
}

func TestDerefNil(t *testing.T) {
	if deref(nil) != "" {
		t.Error("deref(nil) must be empty")
	}
}
