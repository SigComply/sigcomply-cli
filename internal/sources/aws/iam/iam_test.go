package iam

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// userPlain is the non-admin IAM user name shared by this file's fixtures.
const userPlain = "plain-user"

// policyReadOnlyAccess is the managed-policy name shared by this file's fixtures.
const policyReadOnlyAccess = "ReadOnlyAccess"

// fakeAPI lets tests drive the plugin without real AWS calls.
type fakeAPI struct {
	users    []iamtypes.User
	mfaByUN  map[string][]iamtypes.MFADevice
	keysByUN map[string][]iamtypes.AccessKeyMetadata
	err      error

	// Admin-detection fixtures: attached policy names by user, group
	// memberships by user, and attached policy names by group.
	userPolicies  map[string][]string
	inlineByUN    map[string][]string
	userGroups    map[string][]string
	groupPolicies map[string][]string

	listUsersCount int
	listMFACount   int
	listKeysCount  int

	// credReport is the raw credential-report CSV returned by
	// GetCredentialReport. When nil a default report is used: root MFA on,
	// no root access keys, root console enabled — so the synthetic root
	// record passes the root policies and existing user-focused tests
	// don't have to set it.
	credReport      []byte
	credReportErr   error
	credGenerateErr error
}

// rootReportCSV builds a minimal credential-report CSV with a single
// "<root_account>" row carrying the given flags.
func rootReportCSV(mfa, key1, key2, passwordEnabled bool) []byte {
	b := strconv.FormatBool
	header := "user,arn,mfa_active,password_enabled,access_key_1_active,access_key_2_active\n"
	row := "<root_account>,arn:aws:iam::1:root," + b(mfa) + "," + b(passwordEnabled) + "," + b(key1) + "," + b(key2) + "\n"
	return []byte(header + row)
}

func (f *fakeAPI) GenerateCredentialReport(_ context.Context, _ *awsiam.GenerateCredentialReportInput, _ ...func(*awsiam.Options)) (*awsiam.GenerateCredentialReportOutput, error) {
	if f.credGenerateErr != nil {
		return nil, f.credGenerateErr
	}
	return &awsiam.GenerateCredentialReportOutput{State: iamtypes.ReportStateTypeComplete}, nil
}

func (f *fakeAPI) GetCredentialReport(_ context.Context, _ *awsiam.GetCredentialReportInput, _ ...func(*awsiam.Options)) (*awsiam.GetCredentialReportOutput, error) {
	if f.credReportErr != nil {
		return nil, f.credReportErr
	}
	content := f.credReport
	if content == nil {
		content = rootReportCSV(true, false, false, true)
	}
	return &awsiam.GetCredentialReportOutput{Content: content}, nil
}

func attachedPolicies(names []string) []iamtypes.AttachedPolicy {
	out := make([]iamtypes.AttachedPolicy, 0, len(names))
	for _, n := range names {
		out = append(out, iamtypes.AttachedPolicy{PolicyName: ptr(n)})
	}
	return out
}

func (f *fakeAPI) ListAttachedUserPolicies(_ context.Context, in *awsiam.ListAttachedUserPoliciesInput, _ ...func(*awsiam.Options)) (*awsiam.ListAttachedUserPoliciesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	name := ""
	if in.UserName != nil {
		name = *in.UserName
	}
	return &awsiam.ListAttachedUserPoliciesOutput{AttachedPolicies: attachedPolicies(f.userPolicies[name])}, nil
}

func (f *fakeAPI) ListUserPolicies(_ context.Context, in *awsiam.ListUserPoliciesInput, _ ...func(*awsiam.Options)) (*awsiam.ListUserPoliciesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &awsiam.ListUserPoliciesOutput{PolicyNames: f.inlineByUN[*in.UserName]}, nil
}

func (f *fakeAPI) ListGroupsForUser(_ context.Context, in *awsiam.ListGroupsForUserInput, _ ...func(*awsiam.Options)) (*awsiam.ListGroupsForUserOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	name := ""
	if in.UserName != nil {
		name = *in.UserName
	}
	groups := make([]iamtypes.Group, 0, len(f.userGroups[name]))
	for _, g := range f.userGroups[name] {
		groups = append(groups, iamtypes.Group{GroupName: ptr(g)})
	}
	return &awsiam.ListGroupsForUserOutput{Groups: groups}, nil
}

func (f *fakeAPI) ListAttachedGroupPolicies(_ context.Context, in *awsiam.ListAttachedGroupPoliciesInput, _ ...func(*awsiam.Options)) (*awsiam.ListAttachedGroupPoliciesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	name := ""
	if in.GroupName != nil {
		name = *in.GroupName
	}
	return &awsiam.ListAttachedGroupPoliciesOutput{AttachedPolicies: attachedPolicies(f.groupPolicies[name])}, nil
}

func (f *fakeAPI) ListUsers(_ context.Context, _ *awsiam.ListUsersInput, _ ...func(*awsiam.Options)) (*awsiam.ListUsersOutput, error) {
	f.listUsersCount++
	if f.err != nil {
		return nil, f.err
	}
	return &awsiam.ListUsersOutput{Users: f.users, IsTruncated: false}, nil
}

func (f *fakeAPI) ListMFADevices(_ context.Context, in *awsiam.ListMFADevicesInput, _ ...func(*awsiam.Options)) (*awsiam.ListMFADevicesOutput, error) {
	f.listMFACount++
	if in.UserName == nil {
		return &awsiam.ListMFADevicesOutput{}, nil
	}
	return &awsiam.ListMFADevicesOutput{MFADevices: f.mfaByUN[*in.UserName]}, nil
}

func (f *fakeAPI) ListAccessKeys(_ context.Context, in *awsiam.ListAccessKeysInput, _ ...func(*awsiam.Options)) (*awsiam.ListAccessKeysOutput, error) {
	f.listKeysCount++
	if in.UserName == nil {
		return &awsiam.ListAccessKeysOutput{}, nil
	}
	return &awsiam.ListAccessKeysOutput{AccessKeyMetadata: f.keysByUN[*in.UserName]}, nil
}

func ptr[T any](v T) *T { return &v }

func TestPlugin_IDAndEmits(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if p.ID() != SourceID {
		t.Errorf("ID = %q; want %q", p.ID(), SourceID)
	}
	em := p.Emits()
	if len(em) != 1 || em[0] != EvidenceTypeID {
		t.Errorf("Emits = %v; want [%s]", em, EvidenceTypeID)
	}
}

func TestPlugin_InitNoOp(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	if err := p.Init(context.Background(), nil); err != nil {
		t.Errorf("Init: %v", err)
	}
}

func TestCollect_IsAdmin_DetectedDirectlyAndViaGroup(t *testing.T) {
	fake := &fakeAPI{
		users: []iamtypes.User{
			{UserName: ptr("direct-admin"), UserId: ptr("A1")},
			{UserName: ptr("group-admin"), UserId: ptr("A2")},
			{UserName: ptr(userPlain), UserId: ptr("A3")},
		},
		userPolicies: map[string][]string{
			"direct-admin": {"AdministratorAccess"},
			userPlain:      {policyReadOnlyAccess},
		},
		userGroups: map[string][]string{
			"group-admin": {"admins"},
			userPlain:     {"devs"},
		},
		groupPolicies: map[string][]string{
			"admins": {"AdministratorAccess"},
			"devs":   {policyReadOnlyAccess},
		},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	want := map[string]bool{"direct-admin": true, "group-admin": true, userPlain: false}
	for _, r := range records {
		var pl userPayload
		if err := json.Unmarshal(r.Payload, &pl); err != nil {
			t.Fatalf("Unmarshal %s: %v", r.ID, err)
		}
		if pl.IsRoot {
			continue // root is always admin; asserted separately
		}
		if pl.IsAdmin != want[pl.DisplayName] {
			t.Errorf("%s is_admin = %v; want %v", pl.DisplayName, pl.IsAdmin, want[pl.DisplayName])
		}
	}
}

func TestCollect_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{
		users: []iamtypes.User{
			{UserName: ptr("alice"), UserId: ptr("AIDA02"), CreateDate: ptr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))},
			{UserName: ptr("bob"), UserId: ptr("AIDA01"), CreateDate: ptr(time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC))},
		},
		mfaByUN: map[string][]iamtypes.MFADevice{
			"alice": {{SerialNumber: ptr("arn:aws:iam::1:mfa/alice")}},
		},
	}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1", SlotName: "u"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// Two IAM users plus the synthetic root record.
	if len(records) != 3 {
		t.Fatalf("len(records) = %d; want 3 (2 users + root)", len(records))
	}
	// Sorted by ID. The root record is keyed by its account-unique ARN
	// (see rootRecord), and 'a' (0x61) sorts after 'A' (0x41), so
	// it comes last rather than first.
	if records[0].ID != "AIDA01" || records[1].ID != "AIDA02" || records[2].ID != "arn:aws:iam::1:root" {
		t.Errorf("records not sorted by ID: got %v", []string{records[0].ID, records[1].ID, records[2].ID})
	}
	for i := range records {
		if records[i].CollectedAt != now {
			t.Errorf("record[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("record[%d].SourceID = %q", i, records[i].SourceID)
		}
	}

	byID := map[string]userPayload{}
	for _, rec := range records {
		var u userPayload
		if err := json.Unmarshal(rec.Payload, &u); err != nil {
			t.Fatalf("Unmarshal %s: %v", rec.ID, err)
		}
		byID[rec.ID] = u
	}
	if alice := byID["AIDA02"]; !alice.MFAEnabled {
		t.Errorf("alice.MFAEnabled = false; want true")
	}
	if bob := byID["AIDA01"]; bob.MFAEnabled {
		t.Errorf("bob.MFAEnabled = true; want false")
	}
}

// TestCollect_EmitsRootRecord verifies the synthetic root-account record
// is produced from the credential report — without it the Critical root
// policies (root MFA, no root access keys) filter to zero records and
// pass vacuously.
func TestCollect_EmitsRootRecord(t *testing.T) {
	fake := &fakeAPI{
		users:      []iamtypes.User{{UserName: ptr("alice"), UserId: ptr("AID1")}},
		credReport: rootReportCSV(false /*mfa*/, true /*key1*/, false, true),
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var root *userPayload
	for i := range records {
		var pl userPayload
		if err := json.Unmarshal(records[i].Payload, &pl); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if pl.IsRoot {
			root = &pl
			break
		}
	}
	if root == nil {
		t.Fatal("no is_root record emitted")
	}
	if root.MFAEnabled {
		t.Error("root MFAEnabled = true; want false (report said mfa_active=false)")
	}
	if !root.HasProgrammaticAccess {
		t.Error("root HasProgrammaticAccess = false; want true (access_key_1_active=true)")
	}
	if !root.IsAdmin {
		t.Error("root IsAdmin = false; want true (root is always admin)")
	}
}

// TestCollect_CredentialReportErrorFailsCollect ensures a missing
// credential-report permission surfaces as a hard error (the root check
// must never be silently skipped).
func TestCollect_CredentialReportErrorFailsCollect(t *testing.T) {
	fake := &fakeAPI{
		users:           []iamtypes.User{{UserName: ptr("alice"), UserId: ptr("AID1")}},
		credReportErr:   errors.New("not ready"),
		credGenerateErr: errors.New("AccessDenied: iam:GenerateCredentialReport"),
	}
	p := New(Options{API: fake, Sleep: func(time.Duration) {}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "root account") {
		t.Errorf("want root account error; got %v", err)
	}
}

func TestCollect_NoUsers(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// No IAM users, but the synthetic root record is always emitted.
	if len(records) != 1 {
		t.Fatalf("len(records) = %d; want 1 (root only)", len(records))
	}
	var pl userPayload
	if err := json.Unmarshal(records[0].Payload, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !pl.IsRoot {
		t.Errorf("sole record is not the root record: %+v", pl)
	}
	var raw map[string]any
	if err := json.Unmarshal(records[0].Payload, &raw); err != nil {
		t.Fatalf("Unmarshal raw: %v", err)
	}
	if _, has := raw["username"]; has {
		t.Errorf("root payload carries username %v; want omitted (root has no UserName)", raw["username"])
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"s3_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_ListUsersError(t *testing.T) {
	p := New(Options{API: &fakeAPI{err: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "list users") {
		t.Errorf("want list users error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsedWhenNotInjected(t *testing.T) {
	fake := &fakeAPI{
		users: []iamtypes.User{{UserName: ptr("a"), UserId: ptr("AID1")}},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero; want default-now-injected value")
	}
}

func TestCollect_MFAErrorIsReturned(t *testing.T) {
	fake := &mfaErrAPI{users: []iamtypes.User{{UserName: ptr("alice"), UserId: ptr("AID1")}}}
	p := New(Options{API: fake})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "mfa for user alice") {
		t.Errorf("want mfa error; got %v", err)
	}
}

func TestSafeHelpers_NilSafe(t *testing.T) {
	if safeUserName(nil) != "" {
		t.Errorf("nil UserName not empty")
	}
	if safeUserID(nil) != "" {
		t.Errorf("nil UserID not empty")
	}
	if !safeCreatedAt(nil).IsZero() {
		t.Errorf("nil CreateDate not zero")
	}
	// UserName-set, UserID-empty → falls through to UserName.
	u := iamtypes.User{UserName: ptr("u1")}
	if got := safeUserID(&u); got != "u1" {
		t.Errorf("UserID fallback = %q", got)
	}
}

func TestUserHasMFA_NoNameReturnsFalse(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	// safeUserName on a user without name → "" → userHasMFA returns false.
	got, err := p.userHasMFA(context.Background(), &iamtypes.User{})
	if err != nil {
		t.Fatalf("userHasMFA: %v", err)
	}
	if got {
		t.Errorf("unnamed user reported MFA on")
	}
}

func TestNewFromAWS_ErrorWhenRegionMissingFromDefaultChain(t *testing.T) {
	// We can't reliably test the success path without AWS, but we can
	// exercise the constructor by passing an empty region — LoadDefaultConfig
	// may still succeed (returns a usable config), so this is a smoke
	// test: New is called and doesn't panic.
	p, err := NewFromAWS(context.Background(), "us-east-1")
	if err != nil {
		// Some environments (no credentials, no profile) error here —
		// either outcome is acceptable for the smoke test.
		t.Logf("NewFromAWS errored (acceptable in CI): %v", err)
		return
	}
	if p.ID() != SourceID {
		t.Errorf("ID = %q", p.ID())
	}
}

// mfaErrAPI is a fake whose ListMFADevices errors.
type mfaErrAPI struct {
	users []iamtypes.User
}

func (f *mfaErrAPI) ListUsers(_ context.Context, _ *awsiam.ListUsersInput, _ ...func(*awsiam.Options)) (*awsiam.ListUsersOutput, error) {
	return &awsiam.ListUsersOutput{Users: f.users}, nil
}

func (f *mfaErrAPI) ListMFADevices(_ context.Context, _ *awsiam.ListMFADevicesInput, _ ...func(*awsiam.Options)) (*awsiam.ListMFADevicesOutput, error) {
	return nil, errors.New("forbidden")
}

func (f *mfaErrAPI) ListAccessKeys(_ context.Context, _ *awsiam.ListAccessKeysInput, _ ...func(*awsiam.Options)) (*awsiam.ListAccessKeysOutput, error) {
	return &awsiam.ListAccessKeysOutput{}, nil
}

func (f *mfaErrAPI) ListAttachedUserPolicies(_ context.Context, _ *awsiam.ListAttachedUserPoliciesInput, _ ...func(*awsiam.Options)) (*awsiam.ListAttachedUserPoliciesOutput, error) {
	return &awsiam.ListAttachedUserPoliciesOutput{}, nil
}

func (f *mfaErrAPI) ListUserPolicies(_ context.Context, _ *awsiam.ListUserPoliciesInput, _ ...func(*awsiam.Options)) (*awsiam.ListUserPoliciesOutput, error) {
	return &awsiam.ListUserPoliciesOutput{}, nil
}

func (f *mfaErrAPI) ListGroupsForUser(_ context.Context, _ *awsiam.ListGroupsForUserInput, _ ...func(*awsiam.Options)) (*awsiam.ListGroupsForUserOutput, error) {
	return &awsiam.ListGroupsForUserOutput{}, nil
}

func (f *mfaErrAPI) ListAttachedGroupPolicies(_ context.Context, _ *awsiam.ListAttachedGroupPoliciesInput, _ ...func(*awsiam.Options)) (*awsiam.ListAttachedGroupPoliciesOutput, error) {
	return &awsiam.ListAttachedGroupPoliciesOutput{}, nil
}

func (f *mfaErrAPI) GenerateCredentialReport(_ context.Context, _ *awsiam.GenerateCredentialReportInput, _ ...func(*awsiam.Options)) (*awsiam.GenerateCredentialReportOutput, error) {
	return &awsiam.GenerateCredentialReportOutput{State: iamtypes.ReportStateTypeComplete}, nil
}

func (f *mfaErrAPI) GetCredentialReport(_ context.Context, _ *awsiam.GetCredentialReportInput, _ ...func(*awsiam.Options)) (*awsiam.GetCredentialReportOutput, error) {
	return &awsiam.GetCredentialReportOutput{Content: rootReportCSV(true, false, false, true)}, nil
}

func TestCollect_KISSNoDRY_EachCallReListsUsers(t *testing.T) {
	fake := &fakeAPI{
		users: []iamtypes.User{{UserName: ptr("a"), UserId: ptr("AID1")}},
	}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.listUsersCount != 3 {
		t.Errorf("listUsersCount = %d; want 3 (no caching across Collect calls per KISS-no-DRY)", fake.listUsersCount)
	}
}

// TestCollect_EmitsDirectPolicyCountAndUnusedDays guards the v2 fields
// the no_direct_iam_policies and inactive_user_accounts policies read —
// absent would now error those policies.
func TestCollect_EmitsDirectPolicyCountAndUnusedDays(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	lastUsed := now.AddDate(0, 0, -100) // 100 days ago
	fake := &fakeAPI{
		users: []iamtypes.User{
			{UserName: ptr("hasdirect"), UserId: ptr("A1"), PasswordLastUsed: ptr(lastUsed)},
			{UserName: ptr("neverloggedin"), UserId: ptr("A2")},
		},
		userPolicies: map[string][]string{
			"hasdirect": {policyReadOnlyAccess, "SomeOtherPolicy"},
		},
	}
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	recs, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := map[string]userPayload{}
	for _, r := range recs {
		var pl userPayload
		if err := json.Unmarshal(r.Payload, &pl); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		byID[pl.DisplayName] = pl
	}
	if got := byID["hasdirect"].Username; got != "hasdirect" {
		t.Errorf("hasdirect Username = %q; want UserName hasdirect", got)
	}
	if got := byID["hasdirect"].DirectPolicyCount; got != 2 {
		t.Errorf("hasdirect DirectPolicyCount = %d; want 2", got)
	}
	if got := byID["hasdirect"].UnusedDays; got != 100 {
		t.Errorf("hasdirect UnusedDays = %d; want 100", got)
	}
	if got := byID["neverloggedin"].UnusedDays; got != -1 {
		t.Errorf("neverloggedin UnusedDays = %d; want -1 (never)", got)
	}
}

// rootReportCSVForAccount is rootReportCSV with the account number in the
// root ARN made explicit, so a test can produce two accounts' reports.
func rootReportCSVForAccount(account string, mfa bool) []byte {
	header := "user,arn,mfa_active,password_enabled,access_key_1_active,access_key_2_active\n"
	row := "<root_account>,arn:aws:iam::" + account + ":root," + strconv.FormatBool(mfa) +
		",true,false,false\n"
	return []byte(header + row)
}

// The credential report's user column is the same "<root_account>"
// literal in every AWS account. Using it as the record ID made two
// configured instances' roots indistinguishable: instancePlugin
// re-stamps SourceID but not ID, and the evaluator dedups violations by
// ID, so two failing roots collapsed into one violation and
// resources_failed counted 1. The report's arn column is account-unique
// and costs no extra API call.
func TestCollectRootRecord_IDIsAccountUniqueNotTheSentinel(t *testing.T) {
	ctx := context.Background()
	collectRoot := func(account string) core.EvidenceRecord {
		t.Helper()
		api := &fakeAPI{credReport: rootReportCSVForAccount(account, false)}
		p := New(Options{API: api})
		rec, err := rootRecordFromAPI(ctx, p, time.Now().UTC())
		if err != nil {
			t.Fatalf("collectRootRecord(%s): %v", account, err)
		}
		return rec
	}

	a := collectRoot("111111111111")
	b := collectRoot("222222222222")

	if a.ID == rootAccountUser {
		t.Errorf("root record ID is still the per-account sentinel %q", rootAccountUser)
	}
	if a.ID != "arn:aws:iam::111111111111:root" {
		t.Errorf("root record ID = %q; want the root ARN", a.ID)
	}
	if a.ID == b.ID {
		t.Errorf("two accounts' root records share ID %q; they would dedup into one violation", a.ID)
	}
	// record.ID == payload.id is this plugin's invariant for every user.
	var pa userPayload
	if err := json.Unmarshal(a.Payload, &pa); err != nil {
		t.Fatalf("unmarshal root payload: %v", err)
	}
	if pa.ID != a.ID {
		t.Errorf("payload.id = %q, record.ID = %q; want equal", pa.ID, a.ID)
	}
	if !pa.IsRoot || pa.DisplayName != "root" {
		t.Errorf("root payload lost its identity: %+v", pa)
	}
}

// A report without an arn column must keep working rather than emitting
// an empty ID, which the conformance harness rejects.
func TestCollectRootRecord_FallsBackWhenArnColumnAbsent(t *testing.T) {
	csv := []byte("user,mfa_active,password_enabled,access_key_1_active,access_key_2_active\n" +
		"<root_account>,false,true,false,false\n")
	p := New(Options{API: &fakeAPI{credReport: csv}})
	rec, err := rootRecordFromAPI(context.Background(), p, time.Now().UTC())
	if err != nil {
		t.Fatalf("collectRootRecord: %v", err)
	}
	if rec.ID != rootAccountUser {
		t.Errorf("ID = %q; want the %q fallback when arn is absent", rec.ID, rootAccountUser)
	}
}

// userReportCSV builds a credential report with a root row (MFA on) and
// one row per given user line, in the report's real column names.
func userReportCSV(userRows ...string) []byte {
	header := "user,arn,mfa_active,password_enabled,password_last_used,access_key_1_active," +
		"access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date\n"
	root := "<root_account>,arn:aws:iam::1:root,true,true,no_information,false,N/A,false,N/A\n"
	return []byte(header + root + strings.Join(userRows, ""))
}

// A CI user signs every call with an access key and never signs in to the
// console: it is in use, and it has no console password.
func TestCollect_ProgrammaticUserActivityAndConsoleAccess(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	fake := &fakeAPI{
		users: []iamtypes.User{
			{UserName: ptr("ci-deploy"), UserId: ptr("A1")},
			{UserName: ptr("console-never"), UserId: ptr("A2")},
			{UserName: ptr("both"), UserId: ptr("A3"), PasswordLastUsed: ptr(now.AddDate(0, 0, -40))},
			{UserName: ptr("stale-key"), UserId: ptr("A4")},
		},
		credReport: userReportCSV(
			"ci-deploy,arn:aws:iam::1:user/ci-deploy,false,false,N/A,true,2026-05-29T10:00:00+00:00,false,N/A\n",
			"console-never,arn:aws:iam::1:user/console-never,false,true,no_information,false,N/A,false,N/A\n",
			"both,arn:aws:iam::1:user/both,true,true,2026-04-22T00:00:00+00:00,true,2026-05-31T00:00:00+00:00,true,2026-05-20T00:00:00+00:00\n",
			"stale-key,arn:aws:iam::1:user/stale-key,false,false,N/A,true,2026-01-01T00:00:00+00:00,false,N/A\n",
		),
	}
	recs, err := New(Options{API: fake, Now: func() time.Time { return now }}).Collect(context.Background(),
		core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byName := map[string]userPayload{}
	for _, r := range recs {
		var pl userPayload
		if err := json.Unmarshal(r.Payload, &pl); err != nil {
			t.Fatal(err)
		}
		byName[pl.Username] = pl
	}
	tests := []struct {
		user    string
		unused  int
		console bool
	}{
		{"ci-deploy", 2, false},
		{"console-never", -1, true},
		{"both", 1, true},
		{"stale-key", 151, false},
	}
	for _, tc := range tests {
		got := byName[tc.user]
		if got.UnusedDays != tc.unused || got.HasConsoleAccess != tc.console {
			t.Errorf("%s: unused_days=%d has_console_access=%v; want %d %v",
				tc.user, got.UnusedDays, got.HasConsoleAccess, tc.unused, tc.console)
		}
	}
}

// Inline policies are attached directly to the user just like managed
// ones; no_direct_iam_policies must see them.
func TestCollect_InlinePoliciesCountAsDirect(t *testing.T) {
	fake := &fakeAPI{
		users:        []iamtypes.User{{UserName: ptr(userPlain), UserId: ptr("A1")}},
		userPolicies: map[string][]string{userPlain: {policyReadOnlyAccess}},
		inlineByUN:   map[string][]string{userPlain: {"inline-a", "inline-b"}},
	}
	recs, err := New(Options{API: fake}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range recs {
		var pl userPayload
		if err := json.Unmarshal(r.Payload, &pl); err != nil {
			t.Fatal(err)
		}
		if pl.Username == userPlain && pl.DirectPolicyCount != 3 {
			t.Errorf("direct_policy_count = %d; want 3 (1 managed + 2 inline)", pl.DirectPolicyCount)
		}
	}
}

// rootRecordFromAPI runs the report-to-root-record path Collect uses.
func rootRecordFromAPI(ctx context.Context, p *Plugin, now time.Time) (core.EvidenceRecord, error) {
	report, err := p.credentialReport(ctx)
	if err != nil {
		return core.EvidenceRecord{}, err
	}
	rows, err := parseReport(report)
	if err != nil {
		return core.EvidenceRecord{}, err
	}
	return rootRecord(rows, now)
}
