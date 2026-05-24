package cloudtrail

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awsct "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI lets tests drive the plugin without real AWS calls.
type fakeAPI struct {
	trails        []cttypes.Trail
	loggingByName map[string]bool
	loggingByARN  map[string]bool
	err           error

	describeCount int
	statusCount   int
}

func (f *fakeAPI) DescribeTrails(_ context.Context, _ *awsct.DescribeTrailsInput, _ ...func(*awsct.Options)) (*awsct.DescribeTrailsOutput, error) {
	f.describeCount++
	if f.err != nil {
		return nil, f.err
	}
	return &awsct.DescribeTrailsOutput{TrailList: f.trails}, nil
}

func (f *fakeAPI) GetTrailStatus(_ context.Context, in *awsct.GetTrailStatusInput, _ ...func(*awsct.Options)) (*awsct.GetTrailStatusOutput, error) {
	f.statusCount++
	if in.Name == nil {
		return &awsct.GetTrailStatusOutput{}, nil
	}
	if v, ok := f.loggingByARN[*in.Name]; ok {
		return &awsct.GetTrailStatusOutput{IsLogging: &v}, nil
	}
	if v, ok := f.loggingByName[*in.Name]; ok {
		return &awsct.GetTrailStatusOutput{IsLogging: &v}, nil
	}
	return &awsct.GetTrailStatusOutput{}, nil
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
		trails: []cttypes.Trail{
			{
				Name:                       ptr("zeta"),
				TrailARN:                   ptr("arn:aws:cloudtrail:us-east-1:1:trail/zeta"),
				HomeRegion:                 ptr("us-east-1"),
				IsMultiRegionTrail:         ptr(true),
				LogFileValidationEnabled:   ptr(true),
				IncludeGlobalServiceEvents: ptr(true),
				S3BucketName:               ptr("logs"),
			},
			{
				Name:                       ptr("alpha"),
				TrailARN:                   ptr("arn:aws:cloudtrail:us-east-1:1:trail/alpha"),
				HomeRegion:                 ptr("us-east-1"),
				IsMultiRegionTrail:         ptr(false),
				LogFileValidationEnabled:   ptr(false),
				IncludeGlobalServiceEvents: ptr(true),
			},
		},
		loggingByARN: map[string]bool{
			"arn:aws:cloudtrail:us-east-1:1:trail/zeta":  true,
			"arn:aws:cloudtrail:us-east-1:1:trail/alpha": false,
		},
	}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID, PolicyID: "p1", SlotName: "trails"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	// Sorted by ID lexicographically: alpha < zeta.
	if !strings.HasSuffix(records[0].ID, "trail/alpha") || !strings.HasSuffix(records[1].ID, "trail/zeta") {
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

	var zeta trailPayload
	if err := json.Unmarshal(records[1].Payload, &zeta); err != nil {
		t.Fatalf("Unmarshal zeta: %v", err)
	}
	if !zeta.IsMultiRegionTrail || !zeta.IsLogging || !zeta.LogFileValidationEnabled {
		t.Errorf("zeta unexpected: %+v", zeta)
	}
	var alpha trailPayload
	if err := json.Unmarshal(records[0].Payload, &alpha); err != nil {
		t.Fatalf("Unmarshal alpha: %v", err)
	}
	if alpha.IsMultiRegionTrail || alpha.IsLogging {
		t.Errorf("alpha should be single-region + not logging: %+v", alpha)
	}
}

func TestCollect_NoTrails(t *testing.T) {
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
	if err == nil || !strings.Contains(err.Error(), "describe trails") {
		t.Errorf("want describe trails error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsedWhenNotInjected(t *testing.T) {
	fake := &fakeAPI{trails: []cttypes.Trail{{Name: ptr("t1"), TrailARN: ptr("arn:1")}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero; want default-now-injected value")
	}
}

func TestCollect_StatusErrorIsReturned(t *testing.T) {
	fake := &statusErrAPI{trails: []cttypes.Trail{{Name: ptr("t1"), TrailARN: ptr("arn:1")}}}
	p := New(Options{API: fake})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err == nil || !strings.Contains(err.Error(), "status for trail t1") {
		t.Errorf("want status error; got %v", err)
	}
}

func TestCollect_TrailWithoutARNFallsBackToName(t *testing.T) {
	fake := &fakeAPI{
		trails:        []cttypes.Trail{{Name: ptr("only-name"), IsMultiRegionTrail: ptr(true)}},
		loggingByName: map[string]bool{"only-name": true},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].ID != "only-name" {
		t.Errorf("expected ID=only-name; got %+v", records)
	}
}

func TestSafeHelpers_NilSafe(t *testing.T) {
	if safeTrailName(nil) != "" {
		t.Errorf("nil Name not empty")
	}
	if safeTrailARN(nil) != "" {
		t.Errorf("nil ARN not empty")
	}
	if safeStr(nil) != "" {
		t.Errorf("nil string not empty")
	}
	if safeBool(nil) {
		t.Errorf("nil bool not false")
	}
}

func TestTrailIsLogging_NoRefReturnsFalse(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	got, err := p.trailIsLogging(context.Background(), &cttypes.Trail{})
	if err != nil {
		t.Fatalf("trailIsLogging: %v", err)
	}
	if got {
		t.Errorf("unnamed trail reported logging on")
	}
}

func TestTrailIsLogging_NilIsLoggingReturnsFalse(t *testing.T) {
	fake := &nilLoggingAPI{}
	p := New(Options{API: fake})
	got, err := p.trailIsLogging(context.Background(), &cttypes.Trail{Name: ptr("x"), TrailARN: ptr("arn:x")})
	if err != nil {
		t.Fatalf("trailIsLogging: %v", err)
	}
	if got {
		t.Errorf("nil IsLogging treated as true")
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

func TestCollect_KISSNoDRY_EachCallReListsTrails(t *testing.T) {
	fake := &fakeAPI{
		trails: []cttypes.Trail{{Name: ptr("t1"), TrailARN: ptr("arn:1")}},
	}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.describeCount != 3 {
		t.Errorf("describeCount = %d; want 3 (no caching across Collect calls per KISS-no-DRY)", fake.describeCount)
	}
}

// statusErrAPI is a fake whose GetTrailStatus errors.
type statusErrAPI struct {
	trails []cttypes.Trail
}

func (f *statusErrAPI) DescribeTrails(_ context.Context, _ *awsct.DescribeTrailsInput, _ ...func(*awsct.Options)) (*awsct.DescribeTrailsOutput, error) {
	return &awsct.DescribeTrailsOutput{TrailList: f.trails}, nil
}

func (f *statusErrAPI) GetTrailStatus(_ context.Context, _ *awsct.GetTrailStatusInput, _ ...func(*awsct.Options)) (*awsct.GetTrailStatusOutput, error) {
	return nil, errors.New("forbidden")
}

// nilLoggingAPI returns an output where IsLogging is nil.
type nilLoggingAPI struct{}

func (f *nilLoggingAPI) DescribeTrails(_ context.Context, _ *awsct.DescribeTrailsInput, _ ...func(*awsct.Options)) (*awsct.DescribeTrailsOutput, error) {
	return &awsct.DescribeTrailsOutput{}, nil
}

func (f *nilLoggingAPI) GetTrailStatus(_ context.Context, _ *awsct.GetTrailStatusInput, _ ...func(*awsct.Options)) (*awsct.GetTrailStatusOutput, error) {
	return &awsct.GetTrailStatusOutput{}, nil
}
