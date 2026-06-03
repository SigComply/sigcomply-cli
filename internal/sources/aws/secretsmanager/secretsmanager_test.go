package secretsmanager

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awssm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

type fakeAPI struct {
	// pages is returned one element per ListSecrets call; the last page
	// carries an empty NextToken to terminate paging.
	pages [][]smtypes.SecretListEntry
	err   error

	count int
}

func (f *fakeAPI) ListSecrets(_ context.Context, in *awssm.ListSecretsInput, _ ...func(*awssm.Options)) (*awssm.ListSecretsOutput, error) {
	f.count++
	if f.err != nil {
		return nil, f.err
	}
	idx := 0
	if in.NextToken != nil {
		// token encodes the next page index as a string.
		for i := range f.pages {
			if *in.NextToken == pageToken(i) {
				idx = i
				break
			}
		}
	}
	out := &awssm.ListSecretsOutput{}
	if idx < len(f.pages) {
		out.SecretList = f.pages[idx]
	}
	if idx+1 < len(f.pages) {
		tok := pageToken(idx + 1)
		out.NextToken = &tok
	}
	return out, nil
}

func pageToken(i int) string { return "page-" + string(rune('0'+i)) }

func ptr[T any](v T) *T { return &v }

func mustPayload(t *testing.T, r *core.EvidenceRecord) secretPayload {
	t.Helper()
	var pl secretPayload
	if err := json.Unmarshal(r.Payload, &pl); err != nil {
		t.Fatalf("Unmarshal %s: %v", r.ID, err)
	}
	return pl
}

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

type fieldMappingCase struct {
	name        string
	entry       smtypes.SecretListEntry
	wantID      string
	wantName    string
	wantRot     bool
	wantKMS     bool
	wantNever   bool
	wantDays    *int
	wantOmitted bool // last_rotated_days key absent from JSON
}

func TestCollect_FieldMapping(t *testing.T) {
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	rotated := now.AddDate(0, 0, -10)
	tests := []fieldMappingCase{
		{
			name:     "rotated_with_cmk",
			entry:    smtypes.SecretListEntry{ARN: ptr("arn:aws:secretsmanager:::secret/a"), Name: ptr("a"), RotationEnabled: ptr(true), KmsKeyId: ptr("arn:aws:kms:::key/x"), LastRotatedDate: ptr(rotated)},
			wantID:   "arn:aws:secretsmanager:::secret/a",
			wantName: "a",
			wantRot:  true,
			wantKMS:  true,
			wantDays: ptr(10),
		},
		{
			name:        "never_rotated_no_cmk",
			entry:       smtypes.SecretListEntry{ARN: ptr("arn:aws:secretsmanager:::secret/b"), Name: ptr("b")},
			wantID:      "arn:aws:secretsmanager:::secret/b",
			wantName:    "b",
			wantNever:   true,
			wantOmitted: true,
		},
		{
			name:     "name_fallback_id",
			entry:    smtypes.SecretListEntry{Name: ptr("c"), RotationEnabled: ptr(false), LastRotatedDate: ptr(rotated)},
			wantID:   "c",
			wantName: "c",
			wantDays: ptr(10),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeAPI{pages: [][]smtypes.SecretListEntry{{tc.entry}}}
			p := New(Options{API: fake, Now: func() time.Time { return now }})
			records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("len(records) = %d; want 1", len(records))
			}
			r := &records[0]
			if r.ID != tc.wantID {
				t.Errorf("ID = %q; want %q", r.ID, tc.wantID)
			}
			if r.CollectedAt != now {
				t.Errorf("CollectedAt = %v; want %v", r.CollectedAt, now)
			}
			if r.SourceID != SourceID {
				t.Errorf("SourceID = %q", r.SourceID)
			}
			assertPayload(t, mustPayload(t, r), &tc)
			assertLastRotatedOmitted(t, r, tc.wantOmitted)
		})
	}
}

func assertPayload(t *testing.T, pl secretPayload, tc *fieldMappingCase) {
	t.Helper()
	if pl.Name != tc.wantName {
		t.Errorf("Name = %q; want %q", pl.Name, tc.wantName)
	}
	if pl.Provider != "aws" {
		t.Errorf("Provider = %q; want aws", pl.Provider)
	}
	if pl.RotationEnabled != tc.wantRot {
		t.Errorf("RotationEnabled = %v; want %v", pl.RotationEnabled, tc.wantRot)
	}
	if pl.KMSEncrypted != tc.wantKMS {
		t.Errorf("KMSEncrypted = %v; want %v", pl.KMSEncrypted, tc.wantKMS)
	}
	if pl.NeverRotated != tc.wantNever {
		t.Errorf("NeverRotated = %v; want %v", pl.NeverRotated, tc.wantNever)
	}
	if (pl.LastRotatedDays == nil) != (tc.wantDays == nil) {
		t.Fatalf("LastRotatedDays = %v; want %v", pl.LastRotatedDays, tc.wantDays)
	}
	if tc.wantDays != nil && *pl.LastRotatedDays != *tc.wantDays {
		t.Errorf("LastRotatedDays = %d; want %d", *pl.LastRotatedDays, *tc.wantDays)
	}
}

func assertLastRotatedOmitted(t *testing.T, r *core.EvidenceRecord, wantOmitted bool) {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal(r.Payload, &raw); err != nil {
		t.Fatalf("Unmarshal raw: %v", err)
	}
	if _, present := raw["last_rotated_days"]; present == wantOmitted {
		t.Errorf("last_rotated_days present=%v; wantOmitted=%v", present, wantOmitted)
	}
}

func TestCollect_SortsByID(t *testing.T) {
	fake := &fakeAPI{pages: [][]smtypes.SecretListEntry{{
		{ARN: ptr("zeta")},
		{ARN: ptr("alpha")},
	}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 || records[0].ID != "alpha" || records[1].ID != "zeta" {
		t.Errorf("records not sorted by ID: %v", []string{records[0].ID, records[1].ID})
	}
}

func TestCollect_PagesViaNextToken(t *testing.T) {
	fake := &fakeAPI{pages: [][]smtypes.SecretListEntry{
		{{ARN: ptr("a")}},
		{{ARN: ptr("b")}},
		{{ARN: ptr("c")}},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 3 {
		t.Errorf("len(records) = %d; want 3", len(records))
	}
	if fake.count != 3 {
		t.Errorf("ListSecrets calls = %d; want 3", fake.count)
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"directory_user"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_ListError(t *testing.T) {
	p := New(Options{API: &fakeAPI{err: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "list secrets") {
		t.Errorf("want list error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	fake := &fakeAPI{pages: [][]smtypes.SecretListEntry{{{ARN: ptr("a")}}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero")
	}
}

func TestCollect_SkipsSecretWithEmptyID(t *testing.T) {
	fake := &fakeAPI{pages: [][]smtypes.SecretListEntry{{
		{},
		{ARN: ptr("ok")},
	}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].ID != "ok" {
		t.Errorf("records = %v", records)
	}
}

func TestCollect_KISSNoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{pages: [][]smtypes.SecretListEntry{{{ARN: ptr("a")}}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.count != 3 {
		t.Errorf("count = %d; want 3", fake.count)
	}
}

func TestSafeHelpers_NilSafe(t *testing.T) {
	if secretID(nil) != "" {
		t.Errorf("nil secretID not empty")
	}
	if safeString(nil) != "" {
		t.Errorf("nil string not empty")
	}
	if got := safeString(ptr("x")); got != "x" {
		t.Errorf("safeString = %q", got)
	}
	if safeBool(nil) {
		t.Errorf("nil bool not false")
	}
	if !safeBool(ptr(true)) {
		t.Errorf("safeBool(true) = false")
	}
	if lastRotatedDays(nil, time.Now()) != nil {
		t.Errorf("nil lastRotatedDays not nil")
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
