package accesskeys

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

// fakeAPI drives the plugin without real AWS calls.
type fakeAPI struct {
	users    []iamtypes.User
	keysByUN map[string][]iamtypes.AccessKeyMetadata
	lastUsed map[string]*time.Time // keyed by AccessKeyId; absent or nil → never used
	listErr  error
	keysErr  error
	usedErr  error

	listUsersCount int
	listKeysCount  int
	lastUsedCount  int
}

func (f *fakeAPI) ListUsers(_ context.Context, _ *awsiam.ListUsersInput, _ ...func(*awsiam.Options)) (*awsiam.ListUsersOutput, error) {
	f.listUsersCount++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &awsiam.ListUsersOutput{Users: f.users, IsTruncated: false}, nil
}

func (f *fakeAPI) ListAccessKeys(_ context.Context, in *awsiam.ListAccessKeysInput, _ ...func(*awsiam.Options)) (*awsiam.ListAccessKeysOutput, error) {
	f.listKeysCount++
	if f.keysErr != nil {
		return nil, f.keysErr
	}
	if in.UserName == nil {
		return &awsiam.ListAccessKeysOutput{}, nil
	}
	return &awsiam.ListAccessKeysOutput{AccessKeyMetadata: f.keysByUN[*in.UserName]}, nil
}

func (f *fakeAPI) GetAccessKeyLastUsed(_ context.Context, in *awsiam.GetAccessKeyLastUsedInput, _ ...func(*awsiam.Options)) (*awsiam.GetAccessKeyLastUsedOutput, error) {
	f.lastUsedCount++
	if f.usedErr != nil {
		return nil, f.usedErr
	}
	var lu *time.Time
	if in.AccessKeyId != nil {
		lu = f.lastUsed[*in.AccessKeyId]
	}
	return &awsiam.GetAccessKeyLastUsedOutput{AccessKeyLastUsed: &iamtypes.AccessKeyLastUsed{LastUsedDate: lu}}, nil
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

// TestCollect_HappyPath covers one active+used key, one never-used key,
// and one inactive (used) key; verifies sort order, age/last-used math,
// and that last_used_days is omitted for the never-used key.
func TestCollect_HappyPath(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	created := now.Add(-100 * 24 * time.Hour) // 100 days old
	usedAt := now.Add(-30 * 24 * time.Hour)   // last used 30 days ago

	fake := &fakeAPI{
		users: []iamtypes.User{
			{UserName: ptr("alice"), UserId: ptr("AIDA1")},
			{UserName: ptr("bob"), UserId: ptr("AIDA2")},
		},
		keysByUN: map[string][]iamtypes.AccessKeyMetadata{
			"alice": {
				{AccessKeyId: ptr("AKIA_ACTIVE_USED"), Status: iamtypes.StatusTypeActive, CreateDate: ptr(created), UserName: ptr("alice")},
				{AccessKeyId: ptr("AKIA_NEVER_USED"), Status: iamtypes.StatusTypeActive, CreateDate: ptr(created), UserName: ptr("alice")},
			},
			"bob": {
				{AccessKeyId: ptr("AKIA_INACTIVE"), Status: iamtypes.StatusTypeInactive, CreateDate: ptr(created), UserName: ptr("bob")},
			},
		},
		lastUsed: map[string]*time.Time{
			"AKIA_ACTIVE_USED": ptr(usedAt),
			"AKIA_INACTIVE":    ptr(usedAt),
			// AKIA_NEVER_USED intentionally absent → nil → never used.
		},
	}
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1", SlotName: "evidence"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("len(records) = %d; want 3", len(records))
	}

	// Sorted by ID: ACTIVE_USED < INACTIVE < NEVER_USED.
	wantOrder := []string{"AKIA_ACTIVE_USED", "AKIA_INACTIVE", "AKIA_NEVER_USED"}
	assertRecordMeta(t, records, wantOrder, now)
	assertActiveUsedKey(t, &records[0])
	assertInactiveKey(t, decode(t, records[1].Payload))
	assertNeverUsedKey(t, &records[2])
}

// assertRecordMeta verifies sort order and per-record metadata.
func assertRecordMeta(t *testing.T, records []core.EvidenceRecord, wantOrder []string, now time.Time) {
	t.Helper()
	for i, want := range wantOrder {
		meta := []struct {
			name      string
			got, want any
		}{
			{"ID", records[i].ID, want},
			{"SourceID", records[i].SourceID, SourceID},
			{"Type", records[i].Type, EvidenceTypeID},
			{"CollectedAt", records[i].CollectedAt, now},
		}
		for _, c := range meta {
			if c.got != c.want {
				t.Errorf("records[%d].%s = %v; want %v", i, c.name, c.got, c.want)
			}
		}
	}
}

// assertActiveUsedKey checks the active+used key: age 100, last_used 30,
// never_used false, last_used_days present.
func assertActiveUsedKey(t *testing.T, rec *core.EvidenceRecord) {
	t.Helper()
	used := decode(t, rec.Payload)
	if used.UserID != "alice" || used.AgeDays != 100 || used.NeverUsed || !used.IsActive {
		t.Errorf("active-used payload wrong: %+v", used)
	}
	if !rawHasField(t, rec.Payload, "last_used_days") {
		t.Errorf("active-used key must include last_used_days")
	}
	if used.LastUsedDays == nil || *used.LastUsedDays != 30 {
		t.Errorf("active-used last_used_days = %v; want 30", used.LastUsedDays)
	}
}

// assertInactiveKey checks the inactive (still used) key: is_active false.
func assertInactiveKey(t *testing.T, inactive keyPayload) {
	t.Helper()
	if inactive.IsActive || inactive.UserID != "bob" || inactive.NeverUsed {
		t.Errorf("inactive payload wrong: %+v", inactive)
	}
}

// assertNeverUsedKey checks the never-used key: never_used true,
// last_used_days OMITTED.
func assertNeverUsedKey(t *testing.T, rec *core.EvidenceRecord) {
	t.Helper()
	never := decode(t, rec.Payload)
	if !never.NeverUsed || never.LastUsedDays != nil {
		t.Errorf("never-used payload wrong: %+v", never)
	}
	if rawHasField(t, rec.Payload, "last_used_days") {
		t.Errorf("never-used key must OMIT last_used_days; got %s", rec.Payload)
	}
}

func TestCollect_NoUsers(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("len(records) = %d; want 0", len(records))
	}
}

func TestCollect_UserWithNoKeys(t *testing.T) {
	fake := &fakeAPI{users: []iamtypes.User{{UserName: ptr("nokeys"), UserId: ptr("AIDA9")}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("len(records) = %d; want 0", len(records))
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
	p := New(Options{API: &fakeAPI{listErr: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "list users") {
		t.Errorf("want list users error; got %v", err)
	}
}

func TestCollect_ListAccessKeysError(t *testing.T) {
	fake := &fakeAPI{
		users:   []iamtypes.User{{UserName: ptr("alice"), UserId: ptr("AIDA1")}},
		keysErr: errors.New("denied"),
	}
	p := New(Options{API: fake})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "list access keys for user alice") {
		t.Errorf("want list access keys error; got %v", err)
	}
}

func TestCollect_GetLastUsedError(t *testing.T) {
	fake := &fakeAPI{
		users: []iamtypes.User{{UserName: ptr("alice"), UserId: ptr("AIDA1")}},
		keysByUN: map[string][]iamtypes.AccessKeyMetadata{
			"alice": {{AccessKeyId: ptr("AKIA1"), Status: iamtypes.StatusTypeActive, CreateDate: ptr(time.Now())}},
		},
		usedErr: errors.New("throttled"),
	}
	p := New(Options{API: fake})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "last-used for key AKIA1") {
		t.Errorf("want last-used error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsedWhenNotInjected(t *testing.T) {
	fake := &fakeAPI{
		users: []iamtypes.User{{UserName: ptr("a"), UserId: ptr("AID1")}},
		keysByUN: map[string][]iamtypes.AccessKeyMetadata{
			"a": {{AccessKeyId: ptr("AKIA1"), Status: iamtypes.StatusTypeActive, CreateDate: ptr(time.Now().Add(-time.Hour))}},
		},
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

func TestCollect_KISSNoDRY_EachCallReListsUsers(t *testing.T) {
	fake := &fakeAPI{users: []iamtypes.User{{UserName: ptr("a"), UserId: ptr("AID1")}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.listUsersCount != 3 {
		t.Errorf("listUsersCount = %d; want 3 (no caching across Collect calls)", fake.listUsersCount)
	}
}

func TestWholeDaysSince(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	if got := wholeDaysSince(time.Time{}, now); got != 0 {
		t.Errorf("zero time → %d; want 0", got)
	}
	if got := wholeDaysSince(now.Add(24*time.Hour), now); got != 0 {
		t.Errorf("future time → %d; want 0", got)
	}
	if got := wholeDaysSince(now.Add(-90*24*time.Hour-time.Hour), now); got != 90 {
		t.Errorf("90d+1h ago → %d; want 90", got)
	}
}

func TestSafeHelpers_NilSafe(t *testing.T) {
	if safeKeyID(nil) != "" {
		t.Errorf("nil key id not empty")
	}
	if !safeCreateDate(nil).IsZero() {
		t.Errorf("nil create date not zero")
	}
	if safeUserName(nil) != "" {
		t.Errorf("nil user name not empty")
	}
}

func TestNewFromAWS_SmokeTest(t *testing.T) {
	p, err := NewFromAWS(context.Background(), "us-east-1")
	if err != nil {
		t.Logf("NewFromAWS errored (acceptable in CI): %v", err)
		return
	}
	if p.ID() != SourceID {
		t.Errorf("ID = %q", p.ID())
	}
}

// --- helpers ---

func decode(t *testing.T, b []byte) keyPayload {
	t.Helper()
	var pl keyPayload
	if err := json.Unmarshal(b, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return pl
}

func rawHasField(t *testing.T, b []byte, field string) bool {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("Unmarshal raw: %v", err)
	}
	_, ok := m[field]
	return ok
}
