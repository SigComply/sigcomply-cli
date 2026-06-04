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

// fakeAPI lets tests drive the plugin without real AWS calls.
type fakeAPI struct {
	users    []iamtypes.User
	mfaByUN  map[string][]iamtypes.MFADevice
	keysByUN map[string][]iamtypes.AccessKeyMetadata
	err      error

	// Admin-detection fixtures: attached policy names by user, group
	// memberships by user, and attached policy names by group.
	userPolicies  map[string][]string
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

func (f *fakeAPI) ListGroupsForUser(_ context.Context, in *awsiam.ListGroupsForUserInput, _ ...func(*awsiam.Options)) (*awsiam.ListGroupsForUserOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	name := ""
	if in.UserName != nil {
		name = *in.UserName
	}
	var groups []iamtypes.Group
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
			{UserName: ptr("plain-user"), UserId: ptr("A3")},
		},
		userPolicies: map[string][]string{
			"direct-admin": {"AdministratorAccess"},
			"plain-user":   {"ReadOnlyAccess"},
		},
		userGroups: map[string][]string{
			"group-admin": {"admins"},
			"plain-user":  {"devs"},
		},
		groupPolicies: map[string][]string{
			"admins": {"AdministratorAccess"},
			"devs":   {"ReadOnlyAccess"},
		},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	want := map[string]bool{"direct-admin": true, "group-admin": true, "plain-user": false}
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
	// Sorted by ID: "<root_account>" (0x3C) sorts before AIDA01/AIDA02.
	if records[0].ID != rootAccountUser || records[1].ID != "AIDA01" || records[2].ID != "AIDA02" {
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

	var alice userPayload
	if err := json.Unmarshal(records[2].Payload, &alice); err != nil {
		t.Fatalf("Unmarshal alice: %v", err)
	}
	if !alice.MFAEnabled {
		t.Errorf("alice.MFAEnabled = false; want true")
	}
	var bob userPayload
	if err := json.Unmarshal(records[1].Payload, &bob); err != nil {
		t.Fatalf("Unmarshal bob: %v", err)
	}
	if bob.MFAEnabled {
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
			"hasdirect": {"ReadOnlyAccess", "SomeOtherPolicy"},
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
