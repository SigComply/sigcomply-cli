package dynamodb

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

const (
	tblAlpha = "alpha"
	tblZeta  = "zeta"
)

// fakeAPI drives the plugin without real AWS calls.
type fakeAPI struct {
	names   []string
	listErr error

	// describe maps table name -> DescribeTable output.
	describe map[string]*awsdynamodb.DescribeTableOutput
	descErr  error

	// backups maps table name -> DescribeContinuousBackups output.
	backups   map[string]*awsdynamodb.DescribeContinuousBackupsOutput
	backupErr error

	listCount int

	// pages, when non-empty, makes ListTables paginate across the slices.
	pages   [][]string
	pageIdx int
}

func (f *fakeAPI) ListTables(_ context.Context, _ *awsdynamodb.ListTablesInput, _ ...func(*awsdynamodb.Options)) (*awsdynamodb.ListTablesOutput, error) {
	f.listCount++
	if f.listErr != nil {
		return nil, f.listErr
	}
	if len(f.pages) > 0 {
		page := f.pages[f.pageIdx]
		out := &awsdynamodb.ListTablesOutput{TableNames: page}
		f.pageIdx++
		if f.pageIdx < len(f.pages) {
			last := page[len(page)-1]
			out.LastEvaluatedTableName = &last
		}
		return out, nil
	}
	return &awsdynamodb.ListTablesOutput{TableNames: f.names}, nil
}

func (f *fakeAPI) DescribeTable(_ context.Context, in *awsdynamodb.DescribeTableInput, _ ...func(*awsdynamodb.Options)) (*awsdynamodb.DescribeTableOutput, error) {
	if f.descErr != nil {
		return nil, f.descErr
	}
	if out, ok := f.describe[*in.TableName]; ok {
		return out, nil
	}
	return &awsdynamodb.DescribeTableOutput{Table: &ddbtypes.TableDescription{TableName: in.TableName}}, nil
}

func (f *fakeAPI) DescribeContinuousBackups(_ context.Context, in *awsdynamodb.DescribeContinuousBackupsInput, _ ...func(*awsdynamodb.Options)) (*awsdynamodb.DescribeContinuousBackupsOutput, error) {
	if f.backupErr != nil {
		return nil, f.backupErr
	}
	if out, ok := f.backups[*in.TableName]; ok {
		return out, nil
	}
	return &awsdynamodb.DescribeContinuousBackupsOutput{}, nil
}

func ptr[T any](v T) *T { return &v }

func describeOut(name string, deletionProt bool, sse *ddbtypes.SSEDescription) *awsdynamodb.DescribeTableOutput {
	return &awsdynamodb.DescribeTableOutput{Table: &ddbtypes.TableDescription{
		TableName:                 ptr(name),
		DeletionProtectionEnabled: ptr(deletionProt),
		SSEDescription:            sse,
	}}
}

func backupsOut(status ddbtypes.PointInTimeRecoveryStatus) *awsdynamodb.DescribeContinuousBackupsOutput {
	return &awsdynamodb.DescribeContinuousBackupsOutput{
		ContinuousBackupsDescription: &ddbtypes.ContinuousBackupsDescription{
			PointInTimeRecoveryDescription: &ddbtypes.PointInTimeRecoveryDescription{
				PointInTimeRecoveryStatus: status,
			},
		},
	}
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

func collectByID(t *testing.T, fake *fakeAPI, now time.Time) map[string]tablePayload {
	t.Helper()
	opts := Options{API: fake}
	if !now.IsZero() {
		opts.Now = func() time.Time { return now }
	}
	p := New(opts)
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := map[string]tablePayload{}
	for i := range records {
		var pl tablePayload
		if err := json.Unmarshal(records[i].Payload, &pl); err != nil {
			t.Fatalf("Unmarshal %s: %v", records[i].ID, err)
		}
		byID[records[i].ID] = pl
	}
	return byID
}

func TestCollect_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{names: []string{tblZeta, tblAlpha}}
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	if records[0].ID != tblAlpha || records[1].ID != tblZeta {
		t.Errorf("records not sorted by ID: got %v", []string{records[0].ID, records[1].ID})
	}
	for i := range records {
		if records[i].CollectedAt != now {
			t.Errorf("record[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("record[%d].SourceID = %q", i, records[i].SourceID)
		}
		if records[i].Type != EvidenceTypeID {
			t.Errorf("record[%d].Type = %q", i, records[i].Type)
		}
	}
}

func TestCollect_FieldMapping(t *testing.T) {
	fake := &fakeAPI{
		names: []string{"enc-explicit", "enc-default", "pitr-on", "delprot-on", "all-off"},
		describe: map[string]*awsdynamodb.DescribeTableOutput{
			"enc-explicit": describeOut("enc-explicit", false, &ddbtypes.SSEDescription{Status: ddbtypes.SSEStatusEnabled}),
			"enc-default":  describeOut("enc-default", false, nil),
			"pitr-on":      describeOut("pitr-on", false, &ddbtypes.SSEDescription{Status: ddbtypes.SSEStatusDisabled}),
			"delprot-on":   describeOut("delprot-on", true, nil),
			"all-off":      describeOut("all-off", false, &ddbtypes.SSEDescription{Status: ddbtypes.SSEStatusDisabled}),
		},
		backups: map[string]*awsdynamodb.DescribeContinuousBackupsOutput{
			"pitr-on": backupsOut(ddbtypes.PointInTimeRecoveryStatusEnabled),
			"all-off": backupsOut(ddbtypes.PointInTimeRecoveryStatusDisabled),
		},
	}
	byID := collectByID(t, fake, time.Time{})

	cases := []struct {
		name              string
		gotEnc, wantEnc   bool
		gotPITR, wantPITR bool
		gotDel, wantDel   bool
		gotProvider       string
	}{
		{"enc-explicit", byID["enc-explicit"].EncryptionEnabled, true, byID["enc-explicit"].PointInTimeRecoveryEnabled, false, byID["enc-explicit"].DeletionProtection, false, byID["enc-explicit"].Provider},
		{"enc-default", byID["enc-default"].EncryptionEnabled, true, byID["enc-default"].PointInTimeRecoveryEnabled, false, byID["enc-default"].DeletionProtection, false, byID["enc-default"].Provider},
		{"pitr-on", byID["pitr-on"].EncryptionEnabled, false, byID["pitr-on"].PointInTimeRecoveryEnabled, true, byID["pitr-on"].DeletionProtection, false, byID["pitr-on"].Provider},
		{"delprot-on", byID["delprot-on"].EncryptionEnabled, true, byID["delprot-on"].PointInTimeRecoveryEnabled, false, byID["delprot-on"].DeletionProtection, true, byID["delprot-on"].Provider},
		{"all-off", byID["all-off"].EncryptionEnabled, false, byID["all-off"].PointInTimeRecoveryEnabled, false, byID["all-off"].DeletionProtection, false, byID["all-off"].Provider},
	}
	for _, c := range cases {
		if c.gotEnc != c.wantEnc {
			t.Errorf("%s encryption_enabled = %v; want %v", c.name, c.gotEnc, c.wantEnc)
		}
		if c.gotPITR != c.wantPITR {
			t.Errorf("%s pitr = %v; want %v", c.name, c.gotPITR, c.wantPITR)
		}
		if c.gotDel != c.wantDel {
			t.Errorf("%s deletion_protection = %v; want %v", c.name, c.gotDel, c.wantDel)
		}
		if c.gotProvider != providerAWS {
			t.Errorf("%s provider = %q; want %q", c.name, c.gotProvider, providerAWS)
		}
	}
}

// TestCollect_EmitsAllPolicyReadFields guards the under-emission null-trap:
// every nosql_table field the SOC 2 / ISO 27001 policies read must be present
// in every emitted payload, or the evaluator errors the policy.
func TestCollect_EmitsAllPolicyReadFields(t *testing.T) {
	fake := &fakeAPI{names: []string{tblAlpha}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(records[0].Payload, &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, field := range []string{
		"id", "name", "provider",
		"encryption_enabled", "point_in_time_recovery_enabled", "deletion_protection",
	} {
		if _, ok := m[field]; !ok {
			t.Errorf("emitted payload missing policy-read field %q", field)
		}
	}
}

func TestCollect_Pagination(t *testing.T) {
	fake := &fakeAPI{pages: [][]string{{"a", "b"}, {"c"}}}
	byID := collectByID(t, fake, time.Time{})
	if len(byID) != 3 {
		t.Errorf("want 3 tables across pages; got %d", len(byID))
	}
	if fake.listCount != 2 {
		t.Errorf("listCount = %d; want 2", fake.listCount)
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"directory_user"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_ErrorPaths(t *testing.T) {
	cases := []struct {
		name string
		fake *fakeAPI
		want string
	}{
		{"list", &fakeAPI{listErr: errors.New("boom")}, "list tables"},
		{"describe", &fakeAPI{names: []string{tblAlpha}, descErr: errors.New("boom")}, "describe table"},
		{"backups", &fakeAPI{names: []string{tblAlpha}, backupErr: errors.New("boom")}, "describe continuous backups"},
	}
	for _, c := range cases {
		p := New(Options{API: c.fake})
		_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q error; got %v", c.name, c.want, err)
		}
	}
}

func TestCollect_SkipsEmptyName(t *testing.T) {
	fake := &fakeAPI{names: []string{"", "ok"}}
	byID := collectByID(t, fake, time.Time{})
	if len(byID) != 1 {
		t.Errorf("want 1 table; got %d", len(byID))
	}
	if _, ok := byID["ok"]; !ok {
		t.Errorf("missing table ok: %v", byID)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	fake := &fakeAPI{names: []string{tblAlpha}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero; want default-now")
	}
}

func TestCollect_KISSNoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{names: []string{tblAlpha}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.listCount != 3 {
		t.Errorf("listCount = %d; want 3", fake.listCount)
	}
}

func TestHelpers_NilSafe(t *testing.T) {
	cases := []struct {
		name string
		got  bool
		want bool
	}{
		{"encryption nil table", encryptionEnabled(nil), true},
		{"deletion nil table", deletionProtection(nil), false},
		{"pitr nil desc", pitrEnabled(nil), false},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %v; want %v", c.name, c.got, c.want)
		}
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
