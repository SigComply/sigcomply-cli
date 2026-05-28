package guardduty

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	gd "github.com/aws/aws-sdk-go-v2/service/guardduty"
	gdtypes "github.com/aws/aws-sdk-go-v2/service/guardduty/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI lets tests drive the plugin without real AWS calls.
type fakeAPI struct {
	listPages [][]string
	detectors map[string]*gd.GetDetectorOutput
	listErr   error
	getErr    error
	listCount int
	getCount  int
}

func (f *fakeAPI) ListDetectors(_ context.Context, in *gd.ListDetectorsInput, _ ...func(*gd.Options)) (*gd.ListDetectorsOutput, error) {
	f.listCount++
	if f.listErr != nil {
		return nil, f.listErr
	}
	page := 0
	if in.NextToken != nil && *in.NextToken != "" {
		page = atoi(*in.NextToken)
	}
	if page >= len(f.listPages) {
		return &gd.ListDetectorsOutput{}, nil
	}
	var next *string
	if page+1 < len(f.listPages) {
		s := itoa(page + 1)
		next = &s
	}
	return &gd.ListDetectorsOutput{DetectorIds: f.listPages[page], NextToken: next}, nil
}

func (f *fakeAPI) GetDetector(_ context.Context, in *gd.GetDetectorInput, _ ...func(*gd.Options)) (*gd.GetDetectorOutput, error) {
	f.getCount++
	if f.getErr != nil {
		return nil, f.getErr
	}
	if in.DetectorId == nil {
		return &gd.GetDetectorOutput{}, nil
	}
	if v, ok := f.detectors[*in.DetectorId]; ok {
		return v, nil
	}
	return &gd.GetDetectorOutput{}, nil
}

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
		listPages: [][]string{{"det-zeta", "det-alpha"}},
		detectors: map[string]*gd.GetDetectorOutput{
			"det-zeta":  {Status: gdtypes.DetectorStatusEnabled, ServiceRole: ptr("arn:role/zeta"), CreatedAt: ptr("2026-01-01")},
			"det-alpha": {Status: gdtypes.DetectorStatusDisabled, ServiceRole: ptr("arn:role/alpha")},
		},
	}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1", SlotName: "detectors"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	if records[0].ID != "det-alpha" || records[1].ID != "det-zeta" {
		t.Errorf("records not sorted: %v", []string{records[0].ID, records[1].ID})
	}
	for i := range records {
		if records[i].CollectedAt != now {
			t.Errorf("record[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("record[%d].SourceID = %q", i, records[i].SourceID)
		}
	}

	var zeta detectorPayload
	if err := json.Unmarshal(records[1].Payload, &zeta); err != nil {
		t.Fatalf("Unmarshal zeta: %v", err)
	}
	if !zeta.IsEnabled || zeta.Status != "ENABLED" {
		t.Errorf("zeta unexpected: %+v", zeta)
	}
	var alpha detectorPayload
	if err := json.Unmarshal(records[0].Payload, &alpha); err != nil {
		t.Fatalf("Unmarshal alpha: %v", err)
	}
	if alpha.IsEnabled || alpha.Status != "DISABLED" {
		t.Errorf("alpha should be disabled: %+v", alpha)
	}
}

func TestCollect_PaginationFetchesAllPages(t *testing.T) {
	fake := &fakeAPI{
		listPages: [][]string{
			{"d1"},
			{"d2"},
		},
		detectors: map[string]*gd.GetDetectorOutput{
			"d1": {Status: gdtypes.DetectorStatusEnabled},
			"d2": {Status: gdtypes.DetectorStatusEnabled},
		},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("len(records) = %d; want 2", len(records))
	}
	if fake.listCount != 2 {
		t.Errorf("ListDetectors calls = %d; want 2 (paginated)", fake.listCount)
	}
}

func TestCollect_NoDetectors(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
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

func TestCollect_ListError(t *testing.T) {
	p := New(Options{API: &fakeAPI{listErr: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "list detectors") {
		t.Errorf("want list detectors error; got %v", err)
	}
}

func TestCollect_GetError(t *testing.T) {
	p := New(Options{API: &fakeAPI{listPages: [][]string{{"d1"}}, getErr: errors.New("forbidden")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "get detector d1") {
		t.Errorf("want get detector error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsedWhenNotInjected(t *testing.T) {
	fake := &fakeAPI{
		listPages: [][]string{{"d1"}},
		detectors: map[string]*gd.GetDetectorOutput{"d1": {Status: gdtypes.DetectorStatusEnabled}},
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

func TestSafeStr_NilSafe(t *testing.T) {
	if safeStr(nil) != "" {
		t.Errorf("nil string not empty")
	}
	s := "x"
	if safeStr(&s) != "x" {
		t.Errorf("safeStr non-nil failed")
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

func TestCollect_KISSNoDRY_EachCallReListsDetectors(t *testing.T) {
	fake := &fakeAPI{
		listPages: [][]string{{"d1"}},
		detectors: map[string]*gd.GetDetectorOutput{"d1": {Status: gdtypes.DetectorStatusEnabled}},
	}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.listCount != 3 {
		t.Errorf("listCount = %d; want 3 (no caching across Collect calls per KISS-no-DRY)", fake.listCount)
	}
}
