package cloudwatch

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// itoa / atoi are tiny helpers to avoid pulling in strconv just to
// encode page-index tokens in tests.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 4)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

func atoi(s string) int {
	v := 0
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return v
		}
		v = v*10 + int(c-'0')
	}
	return v
}

// fakeAPI lets tests drive the plugin without real AWS calls.
type fakeAPI struct {
	pages [][]cwltypes.LogGroup
	err   error

	calls int
}

func (f *fakeAPI) DescribeLogGroups(_ context.Context, in *cwl.DescribeLogGroupsInput, _ ...func(*cwl.Options)) (*cwl.DescribeLogGroupsOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	page := 0
	if in.NextToken != nil && *in.NextToken != "" {
		page = atoi(*in.NextToken)
	}
	if page >= len(f.pages) {
		return &cwl.DescribeLogGroupsOutput{}, nil
	}
	var next *string
	if page+1 < len(f.pages) {
		s := itoa(page + 1)
		next = &s
	}
	return &cwl.DescribeLogGroupsOutput{LogGroups: f.pages[page], NextToken: next}, nil
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
		pages: [][]cwltypes.LogGroup{
			{
				{LogGroupName: ptr("/aws/zeta"), Arn: ptr("arn:aws:logs:us-east-1:1:log-group:/aws/zeta:*"), RetentionInDays: ptr(int32(180)), StoredBytes: ptr(int64(1234)), MetricFilterCount: ptr(int32(2))},
				{LogGroupName: ptr("/aws/alpha"), Arn: ptr("arn:aws:logs:us-east-1:1:log-group:/aws/alpha:*"), KmsKeyId: ptr("arn:aws:kms:1:key/k")},
			},
		},
	}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID, PolicyID: "p1", SlotName: "logs"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	if !strings.HasSuffix(records[0].ID, "/aws/alpha:*") || !strings.HasSuffix(records[1].ID, "/aws/zeta:*") {
		t.Errorf("records not sorted by ID: got %v", []string{records[0].ID, records[1].ID})
	}
	assertRecordMetadata(t, records, now)
	assertHappyPathPayloads(t, records)
}

func assertRecordMetadata(t *testing.T, records []core.EvidenceRecord, now time.Time) {
	t.Helper()
	for i := range records {
		if records[i].CollectedAt != now {
			t.Errorf("record[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("record[%d].SourceID = %q", i, records[i].SourceID)
		}
	}
}

func assertHappyPathPayloads(t *testing.T, records []core.EvidenceRecord) {
	t.Helper()
	var zeta logGroupPayload
	if err := json.Unmarshal(records[1].Payload, &zeta); err != nil {
		t.Fatalf("Unmarshal zeta: %v", err)
	}
	if zeta.RetentionInDays != 180 || !zeta.RetentionSet || zeta.StoredBytes != 1234 || zeta.MetricFilterUsed != 2 {
		t.Errorf("zeta unexpected: %+v", zeta)
	}
	var alpha logGroupPayload
	if err := json.Unmarshal(records[0].Payload, &alpha); err != nil {
		t.Fatalf("Unmarshal alpha: %v", err)
	}
	if alpha.RetentionSet || alpha.RetentionInDays != 0 {
		t.Errorf("alpha should have no retention: %+v", alpha)
	}
	if alpha.KMSKeyID == "" {
		t.Errorf("alpha KMSKeyID lost")
	}
}

func TestCollect_PaginationFetchesAllPages(t *testing.T) {
	fake := &fakeAPI{
		pages: [][]cwltypes.LogGroup{
			{{LogGroupName: ptr("g1"), Arn: ptr("arn:g1")}},
			{{LogGroupName: ptr("g2"), Arn: ptr("arn:g2")}},
			{{LogGroupName: ptr("g3"), Arn: ptr("arn:g3")}},
		},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 3 {
		t.Errorf("len(records) = %d; want 3", len(records))
	}
	if fake.calls != 3 {
		t.Errorf("DescribeLogGroups calls = %d; want 3 (paginated)", fake.calls)
	}
}

func TestCollect_NoGroups(t *testing.T) {
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

func TestCollect_DescribeError(t *testing.T) {
	p := New(Options{API: &fakeAPI{err: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err == nil || !strings.Contains(err.Error(), "describe log groups") {
		t.Errorf("want describe log groups error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsedWhenNotInjected(t *testing.T) {
	fake := &fakeAPI{pages: [][]cwltypes.LogGroup{{{LogGroupName: ptr("g"), Arn: ptr("arn:g")}}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero; want default-now-injected value")
	}
}

func TestSafeHelpers_NilSafe(t *testing.T) {
	if safeStr(nil) != "" {
		t.Errorf("nil string not empty")
	}
	if safeInt64(nil) != 0 {
		t.Errorf("nil int64 not 0")
	}
	if safeInt32(nil) != 0 {
		t.Errorf("nil int32 not 0")
	}
	if retentionDays(nil) != 0 {
		t.Errorf("nil retention not 0")
	}
	v := int32(42)
	if retentionDays(&v) != 42 {
		t.Errorf("retentionDays nonzero failed")
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

func TestCollect_KISSNoDRY_EachCallReListsGroups(t *testing.T) {
	fake := &fakeAPI{pages: [][]cwltypes.LogGroup{{{LogGroupName: ptr("g"), Arn: ptr("arn:g")}}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.calls != 3 {
		t.Errorf("calls = %d; want 3 (no caching across Collect calls per KISS-no-DRY)", fake.calls)
	}
}

func TestCollect_LogGroupWithoutARNFallsBackToName(t *testing.T) {
	fake := &fakeAPI{pages: [][]cwltypes.LogGroup{{{LogGroupName: ptr("only-name")}}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].ID != "only-name" {
		t.Errorf("expected ID=only-name; got %+v", records)
	}
}
