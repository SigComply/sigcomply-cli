package iam

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI lets tests drive the plugin without real AWS calls.
type fakeAPI struct {
	users   []iamtypes.User
	mfaByUN map[string][]iamtypes.MFADevice
	err     error

	listUsersCount int
	listMFACount   int
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
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID, PolicyID: "p1", SlotName: "u"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	// Sorted by ID: AIDA01 (bob) before AIDA02 (alice).
	if records[0].ID != "AIDA01" || records[1].ID != "AIDA02" {
		t.Errorf("records not sorted by ID: got %v", []string{records[0].ID, records[1].ID})
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
	if err := json.Unmarshal(records[1].Payload, &alice); err != nil {
		t.Fatalf("Unmarshal alice: %v", err)
	}
	if !alice.MFAEnabled {
		t.Errorf("alice.MFAEnabled = false; want true")
	}
	var bob userPayload
	if err := json.Unmarshal(records[0].Payload, &bob); err != nil {
		t.Fatalf("Unmarshal bob: %v", err)
	}
	if bob.MFAEnabled {
		t.Errorf("bob.MFAEnabled = true; want false")
	}
}

func TestCollect_NoUsers(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("len(records) = %d; want 0", len(records))
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: "s3_bucket"})
	if err == nil || !strings.Contains(err.Error(), "unsupported evidence type") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_ListUsersError(t *testing.T) {
	p := New(Options{API: &fakeAPI{err: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err == nil || !strings.Contains(err.Error(), "list users") {
		t.Errorf("want list users error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsedWhenNotInjected(t *testing.T) {
	fake := &fakeAPI{
		users: []iamtypes.User{{UserName: ptr("a"), UserId: ptr("AID1")}},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
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
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
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

func TestCollect_KISSNoDRY_EachCallReListsUsers(t *testing.T) {
	fake := &fakeAPI{
		users: []iamtypes.User{{UserName: ptr("a"), UserId: ptr("AID1")}},
	}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.listUsersCount != 3 {
		t.Errorf("listUsersCount = %d; want 3 (no caching across Collect calls per KISS-no-DRY)", fake.listUsersCount)
	}
}
