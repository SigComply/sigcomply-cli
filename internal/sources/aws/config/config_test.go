package config

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	cfgsvc "github.com/aws/aws-sdk-go-v2/service/configservice"
	cfgtypes "github.com/aws/aws-sdk-go-v2/service/configservice/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI lets tests drive the plugin without real AWS calls.
type fakeAPI struct {
	recorders []cfgtypes.ConfigurationRecorder
	statuses  []cfgtypes.ConfigurationRecorderStatus
	descErr   error
	statusErr error

	descCount   int
	statusCount int
}

func (f *fakeAPI) DescribeConfigurationRecorders(_ context.Context, _ *cfgsvc.DescribeConfigurationRecordersInput, _ ...func(*cfgsvc.Options)) (*cfgsvc.DescribeConfigurationRecordersOutput, error) {
	f.descCount++
	if f.descErr != nil {
		return nil, f.descErr
	}
	return &cfgsvc.DescribeConfigurationRecordersOutput{ConfigurationRecorders: f.recorders}, nil
}

func (f *fakeAPI) DescribeConfigurationRecorderStatus(_ context.Context, _ *cfgsvc.DescribeConfigurationRecorderStatusInput, _ ...func(*cfgsvc.Options)) (*cfgsvc.DescribeConfigurationRecorderStatusOutput, error) {
	f.statusCount++
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return &cfgsvc.DescribeConfigurationRecorderStatusOutput{ConfigurationRecordersStatus: f.statuses}, nil
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
		recorders: []cfgtypes.ConfigurationRecorder{
			{Name: ptr("zeta"), Arn: ptr("arn:aws:config:us-east-1:1:config-recorder/zeta")},
			{Name: ptr("alpha"), Arn: ptr("arn:aws:config:us-east-1:1:config-recorder/alpha")},
		},
		statuses: []cfgtypes.ConfigurationRecorderStatus{
			{Name: ptr("zeta"), Recording: true, LastStatus: cfgtypes.RecorderStatusSuccess},
			{Name: ptr("alpha"), Recording: false, LastStatus: cfgtypes.RecorderStatusFailure, LastErrorCode: ptr("E"), LastErrorMessage: ptr("nope")},
		},
	}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID, PolicyID: "p1", SlotName: "recorders"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	if !strings.HasSuffix(records[0].ID, "config-recorder/alpha") || !strings.HasSuffix(records[1].ID, "config-recorder/zeta") {
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

	var zeta recorderPayload
	if err := json.Unmarshal(records[1].Payload, &zeta); err != nil {
		t.Fatalf("Unmarshal zeta: %v", err)
	}
	if !zeta.Recording || zeta.LastStatus != "Success" {
		t.Errorf("zeta unexpected: %+v", zeta)
	}
	var alpha recorderPayload
	if err := json.Unmarshal(records[0].Payload, &alpha); err != nil {
		t.Fatalf("Unmarshal alpha: %v", err)
	}
	if alpha.Recording || alpha.LastErrorCode != "E" {
		t.Errorf("alpha unexpected: %+v", alpha)
	}
}

func TestCollect_RecorderWithoutStatus(t *testing.T) {
	fake := &fakeAPI{
		recorders: []cfgtypes.ConfigurationRecorder{{Name: ptr("orphan"), Arn: ptr("arn:o")}},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d; want 1", len(records))
	}
	var pl recorderPayload
	if err := json.Unmarshal(records[0].Payload, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pl.Recording {
		t.Errorf("missing status should default to recording=false; got %+v", pl)
	}
}

func TestCollect_StatusWithNilNameIsSkipped(t *testing.T) {
	fake := &fakeAPI{
		recorders: []cfgtypes.ConfigurationRecorder{{Name: ptr("r"), Arn: ptr("arn:r")}},
		statuses:  []cfgtypes.ConfigurationRecorderStatus{{Name: nil, Recording: true}},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var pl recorderPayload
	if err := json.Unmarshal(records[0].Payload, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pl.Recording {
		t.Errorf("nil-name status should not be matched; got %+v", pl)
	}
}

func TestCollect_NoRecorders(t *testing.T) {
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
	p := New(Options{API: &fakeAPI{descErr: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err == nil || !strings.Contains(err.Error(), "describe recorders") {
		t.Errorf("want describe recorders error; got %v", err)
	}
}

func TestCollect_StatusError(t *testing.T) {
	p := New(Options{API: &fakeAPI{statusErr: errors.New("forbidden")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err == nil || !strings.Contains(err.Error(), "describe recorder status") {
		t.Errorf("want status error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsedWhenNotInjected(t *testing.T) {
	fake := &fakeAPI{recorders: []cfgtypes.ConfigurationRecorder{{Name: ptr("r"), Arn: ptr("arn:r")}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero; want default-now-injected value")
	}
}

func TestCollect_RecorderWithoutARNFallsBackToName(t *testing.T) {
	fake := &fakeAPI{recorders: []cfgtypes.ConfigurationRecorder{{Name: ptr("only-name")}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].ID != "only-name" {
		t.Errorf("expected ID=only-name; got %+v", records)
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

func TestCollect_KISSNoDRY_EachCallReListsRecorders(t *testing.T) {
	fake := &fakeAPI{recorders: []cfgtypes.ConfigurationRecorder{{Name: ptr("r"), Arn: ptr("arn:r")}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.descCount != 3 || fake.statusCount != 3 {
		t.Errorf("descCount = %d, statusCount = %d; want both 3 (no caching across Collect calls per KISS-no-DRY)", fake.descCount, fake.statusCount)
	}
}
