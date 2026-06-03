package backup

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awsbackup "github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

type fakeAPI struct {
	plans []backuptypes.BackupPlansListMember
	err   error

	// rules maps backup plan ID -> the rules returned by GetBackupPlan.
	rules   map[string][]backuptypes.BackupRule
	planErr error

	listCalls int
	getCalls  int
}

func (f *fakeAPI) ListBackupPlans(_ context.Context, _ *awsbackup.ListBackupPlansInput, _ ...func(*awsbackup.Options)) (*awsbackup.ListBackupPlansOutput, error) {
	f.listCalls++
	if f.err != nil {
		return nil, f.err
	}
	return &awsbackup.ListBackupPlansOutput{BackupPlansList: f.plans}, nil
}

func (f *fakeAPI) GetBackupPlan(_ context.Context, in *awsbackup.GetBackupPlanInput, _ ...func(*awsbackup.Options)) (*awsbackup.GetBackupPlanOutput, error) {
	f.getCalls++
	if f.planErr != nil {
		return nil, f.planErr
	}
	id := ""
	if in.BackupPlanId != nil {
		id = *in.BackupPlanId
	}
	rules, ok := f.rules[id]
	if !ok {
		return &awsbackup.GetBackupPlanOutput{}, nil
	}
	return &awsbackup.GetBackupPlanOutput{BackupPlan: &backuptypes.BackupPlan{Rules: rules}}, nil
}

func ptr[T any](v T) *T { return &v }

func member(id, name string) backuptypes.BackupPlansListMember {
	return backuptypes.BackupPlansListMember{BackupPlanId: ptr(id), BackupPlanName: ptr(name)}
}

func ruleWith(days *int64) backuptypes.BackupRule {
	r := backuptypes.BackupRule{RuleName: ptr("r"), ScheduleExpression: ptr("cron(0 5 ? * * *)")}
	if days != nil {
		r.Lifecycle = &backuptypes.Lifecycle{DeleteAfterDays: days}
	}
	return r
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

func TestCollect_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{
		plans: []backuptypes.BackupPlansListMember{
			member("zeta", "Zeta Plan"),
			member("alpha", "Alpha Plan"),
		},
		rules: map[string][]backuptypes.BackupRule{
			"zeta":  {ruleWith(ptr(int64(30)))},
			"alpha": {ruleWith(ptr(int64(7))), ruleWith(ptr(int64(90)))},
		},
	}
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	if records[0].ID != "alpha" || records[1].ID != "zeta" {
		t.Errorf("records not sorted by ID: got %v", []string{records[0].ID, records[1].ID})
	}
	var alpha planPayload
	if err := json.Unmarshal(records[0].Payload, &alpha); err != nil {
		t.Fatalf("Unmarshal alpha: %v", err)
	}
	if alpha.Provider != "aws" || alpha.Name != "Alpha Plan" {
		t.Errorf("alpha provider/name = %q/%q", alpha.Provider, alpha.Name)
	}
	if !alpha.IsActive {
		t.Errorf("alpha.IsActive = false; want true (listed == active)")
	}
	if !alpha.HasRetentionRule {
		t.Errorf("alpha.HasRetentionRule = false; want true")
	}
	if alpha.RetentionDays == nil || *alpha.RetentionDays != 90 {
		t.Errorf("alpha.RetentionDays = %v; want 90 (max across rules)", alpha.RetentionDays)
	}
	for i := range records {
		if records[i].CollectedAt != now {
			t.Errorf("record[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("record[%d].SourceID = %q", i, records[i].SourceID)
		}
	}
}

func TestCollect_RetentionRule_Cases(t *testing.T) {
	tests := []struct {
		name        string
		rules       []backuptypes.BackupRule
		wantHas     bool
		wantDaysPtr *int64
	}{
		{"no rules", nil, false, nil},
		{"rule without lifecycle", []backuptypes.BackupRule{ruleWith(nil)}, false, nil},
		{"single retention rule", []backuptypes.BackupRule{ruleWith(ptr(int64(35)))}, true, ptr(int64(35))},
		{
			"max across mixed rules",
			[]backuptypes.BackupRule{ruleWith(nil), ruleWith(ptr(int64(14))), ruleWith(ptr(int64(60)))},
			true, ptr(int64(60)),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeAPI{
				plans: []backuptypes.BackupPlansListMember{member("plan", "Plan")},
				rules: map[string][]backuptypes.BackupRule{"plan": tc.rules},
			}
			p := New(Options{API: fake})
			records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("len(records) = %d; want 1", len(records))
			}
			var pl planPayload
			if err := json.Unmarshal(records[0].Payload, &pl); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if pl.HasRetentionRule != tc.wantHas {
				t.Errorf("HasRetentionRule = %v; want %v", pl.HasRetentionRule, tc.wantHas)
			}
			if (tc.wantDaysPtr == nil) != (pl.RetentionDays == nil) {
				t.Fatalf("RetentionDays presence = %v; want presence %v", pl.RetentionDays, tc.wantDaysPtr)
			}
			if tc.wantDaysPtr != nil && *pl.RetentionDays != *tc.wantDaysPtr {
				t.Errorf("RetentionDays = %d; want %d", *pl.RetentionDays, *tc.wantDaysPtr)
			}
			// When there is no retention rule, retention_days must be omitted
			// from the JSON entirely (no 0 sentinel).
			var raw map[string]any
			if err := json.Unmarshal(records[0].Payload, &raw); err != nil {
				t.Fatalf("Unmarshal raw: %v", err)
			}
			_, present := raw["retention_days"]
			if present != tc.wantHas {
				t.Errorf("retention_days present = %v; want %v", present, tc.wantHas)
			}
		})
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
	if err == nil || !strings.Contains(err.Error(), "list backup plans") {
		t.Errorf("want list error; got %v", err)
	}
}

func TestCollect_GetPlanError(t *testing.T) {
	fake := &fakeAPI{
		plans:   []backuptypes.BackupPlansListMember{member("p", "P")},
		planErr: errors.New("boom"),
	}
	p := New(Options{API: fake})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "get backup plan") {
		t.Errorf("want get backup plan error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	fake := &fakeAPI{plans: []backuptypes.BackupPlansListMember{member("a", "A")}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero")
	}
}

func TestCollect_SkipsPlanWithEmptyID(t *testing.T) {
	fake := &fakeAPI{plans: []backuptypes.BackupPlansListMember{
		{},
		member("ok", "OK"),
	}}
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
	fake := &fakeAPI{plans: []backuptypes.BackupPlansListMember{member("a", "A")}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.listCalls != 3 {
		t.Errorf("listCalls = %d; want 3", fake.listCalls)
	}
}

func TestSafeString_NilSafe(t *testing.T) {
	if safeString(nil) != "" {
		t.Errorf("nil string not empty")
	}
	if got := safeString(ptr("x")); got != "x" {
		t.Errorf("safeString = %q", got)
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
