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

// testRegion is the region newFakePlugin builds every plugin in — deliberately
// not awstest.Region, so a mapping that leaked the cassette's region would show.
const testRegion = "eu-west-1"

// readOnlyPolicy is the AWS-managed policy standing in for "not admin".
const readOnlyPolicy = "ReadOnlyAccess"

// readOnlySet is the non-admin permission set's display name.
const readOnlySet = "ReadOnly"

// fakeAPI is the in-memory stand-in for the two AWS clients. pages is served
// one ListUsers call at a time so pagination is exercised without a cassette.
type fakeAPI struct {
	instances     []ssotypes.InstanceMetadata
	instancePages [][]ssotypes.InstanceMetadata
	instancesErr  error
	pages         [][]istypes.User
	usersErr      error
	listUsersCall int
	seenStoreIDs  []string
	listInstances int

	// Permission-set traversal fixtures, each keyed the way the SDK input
	// names them. assignments is keyed "<permissionSetArn>|<accountId>",
	// the pair ListAccountAssignments requires.
	permissionSets []string
	psNames        map[string]string
	psPolicies     map[string][]string
	psAccounts     map[string][]string
	assignments    map[string][]ssotypes.AccountAssignment
	groupNames     map[string]string
	memberships    map[string][]string
	grantErr       error

	listPermSets    int
	describeGroups  int
	listMemberships int
	listAssignments int
}

func (f *fakeAPI) ListPermissionSets(context.Context, *ssoadmin.ListPermissionSetsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error) {
	f.listPermSets++
	if f.grantErr != nil {
		return nil, f.grantErr
	}
	return &ssoadmin.ListPermissionSetsOutput{PermissionSets: f.permissionSets}, nil
}

func (f *fakeAPI) DescribePermissionSet(_ context.Context, in *ssoadmin.DescribePermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error) {
	name, ok := f.psNames[deref(in.PermissionSetArn)]
	if !ok {
		// Mirrors a permission set whose Name the API does not return: the
		// plugin must fall back to the ARN's last segment.
		return &ssoadmin.DescribePermissionSetOutput{}, nil
	}
	return &ssoadmin.DescribePermissionSetOutput{PermissionSet: &ssotypes.PermissionSet{Name: s(name)}}, nil
}

func (f *fakeAPI) ListManagedPoliciesInPermissionSet(_ context.Context, in *ssoadmin.ListManagedPoliciesInPermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListManagedPoliciesInPermissionSetOutput, error) {
	out := &ssoadmin.ListManagedPoliciesInPermissionSetOutput{}
	for _, name := range f.psPolicies[deref(in.PermissionSetArn)] {
		out.AttachedManagedPolicies = append(out.AttachedManagedPolicies, ssotypes.AttachedManagedPolicy{Name: s(name)})
	}
	return out, nil
}

func (f *fakeAPI) ListAccountsForProvisionedPermissionSet(_ context.Context, in *ssoadmin.ListAccountsForProvisionedPermissionSetInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error) {
	return &ssoadmin.ListAccountsForProvisionedPermissionSetOutput{AccountIds: f.psAccounts[deref(in.PermissionSetArn)]}, nil
}

func (f *fakeAPI) ListAccountAssignments(_ context.Context, in *ssoadmin.ListAccountAssignmentsInput, _ ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error) {
	f.listAssignments++
	key := deref(in.PermissionSetArn) + "|" + deref(in.AccountId)
	return &ssoadmin.ListAccountAssignmentsOutput{AccountAssignments: f.assignments[key]}, nil
}

func (f *fakeAPI) DescribeGroup(_ context.Context, in *identitystore.DescribeGroupInput, _ ...func(*identitystore.Options)) (*identitystore.DescribeGroupOutput, error) {
	f.describeGroups++
	name, ok := f.groupNames[deref(in.GroupId)]
	if !ok {
		return &identitystore.DescribeGroupOutput{}, nil
	}
	return &identitystore.DescribeGroupOutput{DisplayName: s(name)}, nil
}

func (f *fakeAPI) ListGroupMemberships(_ context.Context, in *identitystore.ListGroupMembershipsInput, _ ...func(*identitystore.Options)) (*identitystore.ListGroupMembershipsOutput, error) {
	f.listMemberships++
	out := &identitystore.ListGroupMembershipsOutput{}
	for _, uid := range f.memberships[deref(in.GroupId)] {
		out.GroupMemberships = append(out.GroupMemberships, istypes.GroupMembership{
			MemberId: &istypes.MemberIdMemberUserId{Value: uid},
		})
	}
	return out, nil
}

// ListInstances serves `instances` in one page by default; set
// instancePages to hand them out a page at a time and exercise the
// NextToken loop.
func (f *fakeAPI) ListInstances(context.Context, *ssoadmin.ListInstancesInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error) {
	i := f.listInstances
	f.listInstances++
	if f.instancesErr != nil {
		return nil, f.instancesErr
	}
	if len(f.instancePages) == 0 {
		return &ssoadmin.ListInstancesOutput{Instances: f.instances}, nil
	}
	if i >= len(f.instancePages) {
		return &ssoadmin.ListInstancesOutput{}, nil
	}
	out := &ssoadmin.ListInstancesOutput{Instances: f.instancePages[i]}
	if i+1 < len(f.instancePages) {
		next := fmt.Sprintf("instances-%d", i+1)
		out.NextToken = &next
	}
	return out, nil
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
	// Every collection that needs directory_user or iam_binding resolves the
	// instance ARN, so a fake with no instances would fail before reaching
	// the mapping under test. Tests that care about discovery set
	// `instances` (or `instancesErr`) themselves; this only fills the gap.
	if api.instances == nil && api.instancePages == nil && api.instancesErr == nil {
		api.instances = []ssotypes.InstanceMetadata{instance(testStoreID)}
	}
	return New(Options{
		API:             api,
		Region:          testRegion,
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
	if got := p.Emits(); len(got) != 3 || got[0] != EvidenceTypeDirectoryUser ||
		got[1] != EvidenceTypeRosterEntry || got[2] != EvidenceTypeIAMBinding {
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
		// No permission set grants this user admin, so a real false.
		{"is_admin", p.IsAdmin, false},
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
	if r.Scope == nil || r.Scope.Account != testStoreID || r.Scope.Region != testRegion {
		t.Errorf("Scope = %+v", r.Scope)
	}
	// last_login_at / mfa_factor_count are unknowable and must be ABSENT, not
	// false/zero (the null trap). is_admin is NOT among them any more: the
	// permission-set traversal answers it, and this estate has no permission
	// sets, so the answer is a real false rather than a fabricated one.
	assertPayloadOmits(t, r.Payload, "last_login_at", "mfa_factor_count", "is_service_account", "is_external")
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
		// iam_binding is accepted now, but this estate has no permission
		// sets, so only the roster record comes back.
		{[]string{EvidenceTypeIAMBinding, EvidenceTypeRosterEntry}, 1},
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
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"directory_user.v2", "password_policy"}})
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

// TestConfiguredStoreIDSkipsDiscoveryForRoster: with identity_store_id set and
// a roster-only slot, the plugin makes no sso-admin call at all — which is what
// keeps "designate Identity Center as the roster" a two-permission operation.
func TestConfiguredStoreIDSkipsDiscoveryForRoster(t *testing.T) {
	api := &fakeAPI{pages: [][]istypes.User{{{UserId: s("u-1"), UserStatus: istypes.UserStatusEnabled}}}}
	collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeRosterEntry)
	if api.listInstances != 0 {
		t.Errorf("ListInstances calls = %d; a roster-only slot needs none", api.listInstances)
	}
	if api.listPermSets != 0 {
		t.Errorf("ListPermissionSets calls = %d; a roster-only slot must not traverse grants", api.listPermSets)
	}
	if len(api.seenStoreIDs) != 1 || api.seenStoreIDs[0] != testStoreID {
		t.Errorf("ListUsers IdentityStoreId = %v, want %q", api.seenStoreIDs, testStoreID)
	}
}

// TestConfiguredStoreIDStillDiscoversInstanceARN: directory_user needs
// is_admin, which needs the permission-set traversal, which is scoped by the
// instance ARN — and nothing but ListInstances publishes that. So a configured
// identity_store_id selects among the visible instances rather than skipping
// the call.
func TestConfiguredStoreIDStillDiscoversInstanceARN(t *testing.T) {
	api := &fakeAPI{
		instances: []ssotypes.InstanceMetadata{instance("d-1111111111"), instance(testStoreID)},
		pages:     [][]istypes.User{{{UserId: s("u-1"), UserStatus: istypes.UserStatusEnabled}}},
	}
	collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeDirectoryUser)
	if api.listInstances != 1 {
		t.Errorf("ListInstances calls = %d, want 1", api.listInstances)
	}
	if len(api.seenStoreIDs) != 1 || api.seenStoreIDs[0] != testStoreID {
		t.Errorf("ListUsers IdentityStoreId = %v, want the configured %q", api.seenStoreIDs, testStoreID)
	}
}

// TestConfiguredStoreIDNotVisibleIsAnError: two visible instances and the
// configured one is neither — a silent fallback to "the first one" would audit
// the wrong directory.
func TestConfiguredStoreIDNotVisibleIsAnError(t *testing.T) {
	api := &fakeAPI{
		instances: []ssotypes.InstanceMetadata{instance("d-1111111111")},
		pages:     [][]istypes.User{{{UserId: s("u-1"), UserStatus: istypes.UserStatusEnabled}}},
	}
	p := newFakePlugin(t, api, testStoreID)
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}})
	if err == nil || !strings.Contains(err.Error(), testStoreID) {
		t.Fatalf("err = %v, want it to name the configured store id", err)
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
		{"no instance", &fakeAPI{instances: []ssotypes.InstanceMetadata{}}, "no IAM Identity Center instance"},
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
	api := &fakeAPI{
		instances: []ssotypes.InstanceMetadata{instance(testStoreID)},
		pages:     [][]istypes.User{{{UserId: s("u-1"), UserStatus: istypes.UserStatusEnabled}}},
	}
	p := New(Options{API: api, Region: "us-east-1", IdentityStoreID: " " + testStoreID + " "})
	before := time.Now().UTC().Add(-time.Second)
	recs := collect(t, p, EvidenceTypeDirectoryUser)
	if recs[0].CollectedAt.Before(before) {
		t.Errorf("CollectedAt = %v, want a real clock", recs[0].CollectedAt)
	}
	if len(api.seenStoreIDs) != 1 || api.seenStoreIDs[0] != testStoreID {
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

// --- permission-set traversal ----------------------------------------------

// Grant fixtures. The two permission sets are the two verdicts
// isBroadAdminSet has to reach: one by its attached AWS-managed policy, one
// by neither signal.
const (
	psAdminARN    = "arn:aws:sso:::permissionSet/ssoins-1111aaaa2222bbbb/ps-1111111111111111"
	psReadOnlyARN = "arn:aws:sso:::permissionSet/ssoins-1111aaaa2222bbbb/ps-2222222222222222"
	psUnnamedARN  = "arn:aws:sso:::permissionSet/ssoins-1111aaaa2222bbbb/ps-3333333333333333"

	testAccountID = "000000000000"
	testGroupID   = "g-1111"
	testGroupName = "Platform Admins"

	userAdaID  = "u-ada"
	userDanaID = "u-dana"
	danaEmail  = "user-d4e5f6@example.com"
)

// grantFake wires the full traversal: an admin permission set held by a group
// Ada belongs to, and a read-only one held by Dana directly.
func grantFake() *fakeAPI {
	return &fakeAPI{
		pages: [][]istypes.User{{
			{UserId: s(userAdaID), UserName: s(testUserName), UserStatus: istypes.UserStatusEnabled,
				Emails: []istypes.Email{{Value: s(testUserEmail), Primary: true}}},
			{UserId: s(userDanaID), UserName: s("example-user-2"), UserStatus: istypes.UserStatusEnabled,
				Emails: []istypes.Email{{Value: s(danaEmail), Primary: true}}},
		}},
		permissionSets: []string{psAdminARN, psReadOnlyARN},
		psNames:        map[string]string{psAdminARN: adminPolicyName, psReadOnlyARN: readOnlySet},
		psPolicies: map[string][]string{
			psAdminARN:    {adminPolicyName},
			psReadOnlyARN: {readOnlyPolicy},
		},
		psAccounts: map[string][]string{
			psAdminARN:    {testAccountID},
			psReadOnlyARN: {testAccountID},
		},
		assignments: map[string][]ssotypes.AccountAssignment{
			psAdminARN + "|" + testAccountID: {{
				AccountId: s(testAccountID), PermissionSetArn: s(psAdminARN),
				PrincipalId: s(testGroupID), PrincipalType: ssotypes.PrincipalTypeGroup,
			}},
			psReadOnlyARN + "|" + testAccountID: {{
				AccountId: s(testAccountID), PermissionSetArn: s(psReadOnlyARN),
				PrincipalId: s(userDanaID), PrincipalType: ssotypes.PrincipalTypeUser,
			}},
		},
		groupNames:  map[string]string{testGroupID: testGroupName},
		memberships: map[string][]string{testGroupID: {userAdaID}},
	}
}

func bindingsByID(t *testing.T, recs []core.EvidenceRecord) map[string]bindingPayload {
	t.Helper()
	out := map[string]bindingPayload{}
	for i := range recs {
		if recs[i].Type != EvidenceTypeIAMBinding {
			continue
		}
		out[recs[i].ID] = payloadOf[bindingPayload](t, &recs[i])
	}
	return out
}

// TestCollectIAMBindingFieldMapping pins the whole iam_binding payload for the
// two assignment shapes: a group grant and a direct user grant.
func TestCollectIAMBindingFieldMapping(t *testing.T) {
	api := grantFake()
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeIAMBinding)
	if len(recs) != 2 {
		t.Fatalf("records = %d, want 2 (one per assignment)", len(recs))
	}
	byID := bindingsByID(t, recs)

	adminID := adminPolicyName + "|" + testAccountID + "|group:" + testGroupName
	readID := readOnlySet + "|" + testAccountID + "|user:" + danaEmail
	for _, c := range []struct {
		field string
		got   any
		want  any
	}{
		{"admin id", byID[adminID].ID, adminID},
		{"admin role", byID[adminID].Role, adminPolicyName},
		// The group's display name, not its GUID: principal_id is what an
		// operator reads in the violation message.
		{"admin principal_id", byID[adminID].PrincipalID, testGroupName},
		{"admin principal_type", byID[adminID].PrincipalType, principalTypeGroup},
		{"admin is_broad_admin_role", byID[adminID].IsBroadAdminRole, true},
		{"admin has_condition", byID[adminID].HasCondition, false},
		{"admin account_id", byID[adminID].AccountID, testAccountID},
		{"admin permission_set_arn", byID[adminID].PermissionSetARN, psAdminARN},
		{"admin identity_store_id", byID[adminID].IdentityStoreID, testStoreID},

		{"read role", byID[readID].Role, readOnlySet},
		// A direct user assignment joins the roster on the user's email,
		// exactly as the directory_user record does.
		{"read principal_id", byID[readID].PrincipalID, danaEmail},
		{"read principal_type", byID[readID].PrincipalType, principalTypeUser},
		{"read is_broad_admin_role", byID[readID].IsBroadAdminRole, false},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}

	for i := range recs {
		r := recs[i]
		if r.SourceID != SourceID || !r.CollectedAt.Equal(testNow) {
			t.Errorf("envelope = %+v", r)
		}
		// Scope.Account is the AWS account the grant applies IN — a grant
		// belongs to the account it opens, not to the identity store.
		if r.Scope == nil || r.Scope.Account != testAccountID || r.Scope.Region != testRegion {
			t.Errorf("Scope = %+v, want the target AWS account", r.Scope)
		}
	}
	// IdentityKey is the lowercased principal, so a user grant and that
	// user's directory_user record present the roster with the same key.
	for i := range recs {
		if want := strings.ToLower(payloadOf[bindingPayload](t, &recs[i]).PrincipalID); recs[i].IdentityKey != want {
			t.Errorf("binding %s IdentityKey = %q, want %q", recs[i].ID, recs[i].IdentityKey, want)
		}
	}
}

// TestGroupGrantsAreNotExpandedIntoUserBindings is the load-bearing decision:
// iso27001.{5.3,8.3}.no_broad_admin_* is phrased none(principal_type == "user"
// AND is_broad_admin_role AND NOT has_condition), and its remediation says to
// grant admin through groups. Expanding a group grant into member records
// would report the recommended pattern as a violation of the policy that
// recommends it.
func TestGroupGrantsAreNotExpandedIntoUserBindings(t *testing.T) {
	api := grantFake()
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeIAMBinding)
	for _, p := range bindingsByID(t, recs) {
		if p.PrincipalType == principalTypeUser && p.IsBroadAdminRole {
			t.Errorf("group-granted admin surfaced as a user binding: %+v", p)
		}
		if p.PrincipalID == testUserEmail {
			t.Errorf("group member %q was expanded into a binding of its own", p.PrincipalID)
		}
	}
}

// TestIsAdminResolvesThroughGroupMembership is the other half of that split:
// is_admin asks whether the person holds elevated privileges, which does not
// care how the grant was made. Ada holds admin only through the group.
func TestIsAdminResolvesThroughGroupMembership(t *testing.T) {
	api := grantFake()
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeDirectoryUser)
	got := map[string]bool{}
	for i := range recs {
		got[recs[i].ID] = payloadOf[userPayload](t, &recs[i]).IsAdmin
	}
	want := map[string]bool{userAdaID: true, userDanaID: false}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("is_admin[%s] = %v, want %v", id, got[id], w)
		}
	}
}

// TestDirectUserAdminAssignmentSetsIsAdmin: the same verdict without a group
// in the path.
func TestDirectUserAdminAssignmentSetsIsAdmin(t *testing.T) {
	api := grantFake()
	api.assignments[psAdminARN+"|"+testAccountID] = []ssotypes.AccountAssignment{{
		AccountId: s(testAccountID), PermissionSetArn: s(psAdminARN),
		PrincipalId: s(userDanaID), PrincipalType: ssotypes.PrincipalTypeUser,
	}}
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeDirectoryUser, EvidenceTypeIAMBinding)
	for i := range recs {
		if recs[i].Type != EvidenceTypeDirectoryUser || recs[i].ID != userDanaID {
			continue
		}
		if !payloadOf[userPayload](t, &recs[i]).IsAdmin {
			t.Error("a directly-assigned AdministratorAccess holder is not is_admin")
		}
	}
	// And it IS the violation the least-privilege policies look for.
	found := false
	for _, p := range bindingsByID(t, recs) {
		if p.PrincipalType == principalTypeUser && p.IsBroadAdminRole && !p.HasCondition {
			found = true
		}
	}
	if !found {
		t.Error("a direct user admin assignment produced no unconditional broad-admin user binding")
	}
}

// TestDirectoryUserOnlySkipsNonAdminFanOut: with only directory_user asked
// for, a permission set that cannot change is_admin is dropped before its
// account/assignment fan-out — the expensive half of the traversal.
func TestDirectoryUserOnlySkipsNonAdminFanOut(t *testing.T) {
	api := grantFake()
	collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeDirectoryUser)
	if api.listAssignments != 1 {
		t.Errorf("ListAccountAssignments calls = %d, want 1 (the admin set only)", api.listAssignments)
	}

	full := grantFake()
	collect(t, newFakePlugin(t, full, testStoreID), EvidenceTypeDirectoryUser, EvidenceTypeIAMBinding)
	if full.listAssignments != 2 {
		t.Errorf("with iam_binding asked for, ListAccountAssignments calls = %d, want 2", full.listAssignments)
	}
}

// TestGroupLookupsAreMemoizedWithinOneCollect: many assignments name the same
// group; the per-call memo is the sanctioned KISS-no-DRY exception.
func TestGroupLookupsAreMemoizedWithinOneCollect(t *testing.T) {
	api := grantFake()
	api.assignments[psReadOnlyARN+"|"+testAccountID] = []ssotypes.AccountAssignment{{
		AccountId: s(testAccountID), PermissionSetArn: s(psReadOnlyARN),
		PrincipalId: s(testGroupID), PrincipalType: ssotypes.PrincipalTypeGroup,
	}}
	collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeIAMBinding)
	if api.describeGroups != 1 || api.listMemberships != 1 {
		t.Errorf("DescribeGroup=%d ListGroupMemberships=%d, want 1 each across two assignments to the same group",
			api.describeGroups, api.listMemberships)
	}
}

// TestPermissionSetNameFallsBackToARNSegment: role must never be empty — it is
// the iam_binding id and the violation text.
func TestPermissionSetNameFallsBackToARNSegment(t *testing.T) {
	api := grantFake()
	api.permissionSets = []string{psUnnamedARN}
	api.psAccounts = map[string][]string{psUnnamedARN: {testAccountID}}
	api.assignments = map[string][]ssotypes.AccountAssignment{
		psUnnamedARN + "|" + testAccountID: {{
			AccountId: s(testAccountID), PermissionSetArn: s(psUnnamedARN),
			PrincipalId: s(userDanaID), PrincipalType: ssotypes.PrincipalTypeUser,
		}},
	}
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeIAMBinding)
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	if got := payloadOf[bindingPayload](t, &recs[0]).Role; got != "ps-3333333333333333" {
		t.Errorf("role = %q, want the ARN's last segment", got)
	}
}

// TestUnknownPrincipalTypeIsSkipped: an assignment kind AWS adds later must not
// be reported as a user — that is the population the least-privilege policies
// evaluate.
func TestUnknownPrincipalTypeIsSkipped(t *testing.T) {
	api := grantFake()
	api.assignments[psAdminARN+"|"+testAccountID] = []ssotypes.AccountAssignment{{
		AccountId: s(testAccountID), PermissionSetArn: s(psAdminARN),
		PrincipalId: s("svc-1"), PrincipalType: ssotypes.PrincipalType("SERVICE"),
	}}
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeIAMBinding)
	for _, p := range bindingsByID(t, recs) {
		if p.PrincipalID == "svc-1" {
			t.Errorf("unclassifiable principal was emitted: %+v", p)
		}
	}
}

// TestUserWithoutEmailFallsBackToUserID: a grant whose holder has no address
// stays in the checked population as an unlinked account rather than vanishing.
func TestUserWithoutEmailFallsBackToUserID(t *testing.T) {
	api := grantFake()
	api.pages = [][]istypes.User{{{UserId: s(userDanaID), UserName: s("example-user-2"), UserStatus: istypes.UserStatusEnabled}}}
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeIAMBinding)
	found := false
	for _, p := range bindingsByID(t, recs) {
		if p.PrincipalType == principalTypeUser && p.PrincipalID == userDanaID {
			found = true
		}
	}
	if !found {
		t.Error("an emailless grant holder was dropped instead of surfacing unlinked")
	}
}

func TestIsBroadAdminSet(t *testing.T) {
	for name, c := range map[string]struct {
		set      string
		policies []string
		want     bool
	}{
		"AdministratorAccess attached": {"Ops", []string{readOnlyPolicy, adminPolicyName}, true},
		"admin in the name":            {"BreakGlassAdmin", []string{readOnlyPolicy}, true},
		"case-insensitive name":        {"SysADMIN", nil, true},
		"neither signal":               {readOnlySet, []string{readOnlyPolicy}, false},
		"power user is not admin":      {"PowerUser", []string{"PowerUserAccess"}, false},
	} {
		if got := isBroadAdminSet(c.set, c.policies); got != c.want {
			t.Errorf("%s: isBroadAdminSet(%q, %v) = %v, want %v", name, c.set, c.policies, got, c.want)
		}
	}
}

// TestGrantTraversalErrorFailsTheCollection: a missing sso:* permission is a
// coverage gap the operator must see, not a silently omitted is_admin.
func TestGrantTraversalErrorFailsTheCollection(t *testing.T) {
	api := grantFake()
	api.grantErr = errors.New("AccessDeniedException")
	p := newFakePlugin(t, api, testStoreID)
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}})
	if err == nil || !strings.Contains(err.Error(), "AccessDeniedException") ||
		!strings.Contains(err.Error(), "aws.identity_center") {
		t.Fatalf("err = %v, want the AWS error wrapped and the source named", err)
	}
}

// TestRecordsAreGloballyIDSorted: the conformance harness asserts a single
// ascending ID order across every emitted type, not per type group.
func TestRecordsAreGloballyIDSorted(t *testing.T) {
	api := grantFake()
	recs := collect(t, newFakePlugin(t, api, testStoreID),
		EvidenceTypeDirectoryUser, EvidenceTypeRosterEntry, EvidenceTypeIAMBinding)
	if len(recs) != 6 {
		t.Fatalf("records = %d, want 6 (2 users x 2 types + 2 bindings)", len(recs))
	}
	for i := 1; i < len(recs); i++ {
		if recs[i-1].ID > recs[i].ID {
			t.Errorf("records not ID-sorted at %d: %q > %q", i, recs[i-1].ID, recs[i].ID)
		}
	}
}

// --- discovery pagination --------------------------------------------------

// TestDiscoveryPagesInstances: both decisions resolveInstance makes are about
// HOW MANY instances are visible, so reading one page would turn "two
// instances, refuse to guess" into "one instance, pick it" — a run that
// silently audits the wrong directory.
func TestDiscoveryPagesInstances(t *testing.T) {
	api := &fakeAPI{
		instancePages: [][]ssotypes.InstanceMetadata{
			{instance("d-1111111111")},
			{instance("d-2222222222")},
		},
		pages: [][]istypes.User{{{UserId: s("u-1"), UserStatus: istypes.UserStatusEnabled}}},
	}
	p := newFakePlugin(t, api, "")
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeDirectoryUser}})
	if err == nil || !strings.Contains(err.Error(), "2 IAM Identity Center instances") {
		t.Fatalf("err = %v; want the ambiguity refusal counting BOTH pages", err)
	}
	if api.listInstances != 2 {
		t.Errorf("ListInstances calls = %d, want 2 (the NextToken loop)", api.listInstances)
	}
}

// TestDiscoveryFindsConfiguredStoreOnLaterPage: the same dropped page would
// turn a configured, perfectly valid identity_store_id into a false
// "not among the instances visible" config error.
func TestDiscoveryFindsConfiguredStoreOnLaterPage(t *testing.T) {
	api := &fakeAPI{
		instancePages: [][]ssotypes.InstanceMetadata{
			{instance("d-1111111111")},
			{instance(testStoreID)},
		},
		pages: [][]istypes.User{{{UserId: s("u-1"), UserStatus: istypes.UserStatusEnabled}}},
	}
	collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeDirectoryUser)
	if len(api.seenStoreIDs) != 1 || api.seenStoreIDs[0] != testStoreID {
		t.Errorf("ListUsers IdentityStoreId = %v, want %q from page 2", api.seenStoreIDs, testStoreID)
	}
}

// --- record-id uniqueness --------------------------------------------------

// TestDuplicatePrincipalNameEmitsOneBinding: Identity Store enforces
// uniqueness on UserName, not on email, so two users can share a primary
// address. Holding the same permission set in the same account, they build the
// same record ID and byte-identical payloads — and the collector re-sorts with
// an UNSTABLE sort.Slice, so two equal-ID records can swap between runs and
// change signed envelope bytes for unchanged directory state. Dropping the
// duplicate loses nothing; both people still appear as directory_user records.
func TestDuplicatePrincipalNameEmitsOneBinding(t *testing.T) {
	api := grantFake()
	api.pages = [][]istypes.User{{
		{UserId: s(userDanaID), UserName: s("example-user-2"), UserStatus: istypes.UserStatusEnabled,
			Emails: []istypes.Email{{Value: s(danaEmail), Primary: true}}},
		{UserId: s("u-twin"), UserName: s("example-user-twin"), UserStatus: istypes.UserStatusEnabled,
			Emails: []istypes.Email{{Value: s(danaEmail), Primary: true}}},
	}}
	api.assignments[psReadOnlyARN+"|"+testAccountID] = []ssotypes.AccountAssignment{
		{AccountId: s(testAccountID), PermissionSetArn: s(psReadOnlyARN),
			PrincipalId: s(userDanaID), PrincipalType: ssotypes.PrincipalTypeUser},
		{AccountId: s(testAccountID), PermissionSetArn: s(psReadOnlyARN),
			PrincipalId: s("u-twin"), PrincipalType: ssotypes.PrincipalTypeUser},
	}
	recs := collect(t, newFakePlugin(t, api, testStoreID),
		EvidenceTypeDirectoryUser, EvidenceTypeIAMBinding)
	seen := map[string]int{}
	users := 0
	for i := range recs {
		seen[recs[i].ID]++
		if recs[i].Type == EvidenceTypeDirectoryUser {
			users++
		}
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("record id %q emitted %d times; ids must be unique", id, n)
		}
	}
	if users != 2 {
		t.Errorf("directory_user records = %d, want 2 — the two people are still distinct", users)
	}
}

// --- principal_id / email agreement ---------------------------------------

// TestNonAddressEmailKeysBothRecordsTheSameWay: a user whose stored "email" is
// a non-address identifier must present the SAME account.key from their
// directory_user record and from any grant they hold, or the roster join sees
// one person as two identities. directory_user drops it via emailOrEmpty, so
// the binding must too — falling back to the user id.
func TestNonAddressEmailKeysBothRecordsTheSameWay(t *testing.T) {
	api := grantFake()
	api.pages = [][]istypes.User{{{
		UserId: s(userDanaID), UserName: s("example-user-2"), UserStatus: istypes.UserStatusEnabled,
		Emails: []istypes.Email{{Value: s("not-an-address"), Primary: true}},
	}}}
	recs := collect(t, newFakePlugin(t, api, testStoreID),
		EvidenceTypeDirectoryUser, EvidenceTypeIAMBinding)
	for i := range recs {
		switch recs[i].Type {
		case EvidenceTypeDirectoryUser:
			if got := payloadOf[userPayload](t, &recs[i]).Email; got != "" {
				t.Errorf("directory_user email = %q, want it dropped", got)
			}
		case EvidenceTypeIAMBinding:
			p := payloadOf[bindingPayload](t, &recs[i])
			if p.PrincipalType != principalTypeUser {
				continue // the group grant, which names the group
			}
			if p.PrincipalID != userDanaID {
				t.Errorf("binding principal_id = %q, want the user id fallback %q", p.PrincipalID, userDanaID)
			}
		}
	}
}

// TestNonAdminGroupGrantSkipsMembershipLookup: nothing reads a non-admin
// permission set's holders, so its groups' memberships are never fetched —
// which keeps identitystore:ListGroupMemberships off the path of the ordinary
// grants that make up most of an estate.
func TestNonAdminGroupGrantSkipsMembershipLookup(t *testing.T) {
	api := grantFake()
	api.assignments[psAdminARN+"|"+testAccountID] = nil
	api.assignments[psReadOnlyARN+"|"+testAccountID] = []ssotypes.AccountAssignment{{
		AccountId: s(testAccountID), PermissionSetArn: s(psReadOnlyARN),
		PrincipalId: s(testGroupID), PrincipalType: ssotypes.PrincipalTypeGroup,
	}}
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeIAMBinding)
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	if api.listMemberships != 0 {
		t.Errorf("ListGroupMemberships calls = %d; a non-admin grant needs no membership", api.listMemberships)
	}
	// The group is still named, so the binding stays readable.
	if got := payloadOf[bindingPayload](t, &recs[0]).PrincipalID; got != testGroupName {
		t.Errorf("principal_id = %q, want %q", got, testGroupName)
	}
}

// TestBlankPermissionSetARNIsSkipped: a blank ARN would produce an empty role,
// which the schema has no minLength to catch, and a garbage record id.
func TestBlankPermissionSetARNIsSkipped(t *testing.T) {
	api := grantFake()
	api.permissionSets = []string{"  ", psReadOnlyARN}
	recs := collect(t, newFakePlugin(t, api, testStoreID), EvidenceTypeIAMBinding)
	for i := range recs {
		if payloadOf[bindingPayload](t, &recs[i]).Role == "" {
			t.Errorf("record %q has an empty role", recs[i].ID)
		}
	}
	if len(recs) != 1 {
		t.Errorf("records = %d, want 1 (the blank ARN contributes none)", len(recs))
	}
}
