package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	gcs "cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI lets tests drive the plugin without real GCS calls.
type fakeAPI struct {
	buckets []*gcs.BucketAttrs
	err     error

	listCount int
}

func (f *fakeAPI) ListBuckets(_ context.Context, _ string) ([]*gcs.BucketAttrs, error) {
	f.listCount++
	if f.err != nil {
		return nil, f.err
	}
	return f.buckets, nil
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
	fake := &fakeAPI{buckets: []*gcs.BucketAttrs{
		{Name: "zeta-logs", Location: "US", StorageClass: "STANDARD"},
		{Name: "alpha-data", Location: "EU", StorageClass: "NEARLINE",
			UniformBucketLevelAccess: gcs.UniformBucketLevelAccess{Enabled: true},
			VersioningEnabled:        true},
	}}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "p1", Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID, PolicyID: "p1", SlotName: "buckets"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	// Sorted by ID: alpha-data before zeta-logs.
	if records[0].ID != "alpha-data" || records[1].ID != "zeta-logs" {
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

	var alpha bucketPayload
	if err := json.Unmarshal(records[0].Payload, &alpha); err != nil {
		t.Fatalf("Unmarshal alpha: %v", err)
	}
	if !alpha.UniformBucketLevelAccess {
		t.Errorf("alpha.UniformBucketLevelAccess = false; want true")
	}
	if !alpha.VersioningEnabled {
		t.Errorf("alpha.VersioningEnabled = false; want true")
	}
	if alpha.Location != "EU" {
		t.Errorf("alpha.Location = %q", alpha.Location)
	}

	var zeta bucketPayload
	if err := json.Unmarshal(records[1].Payload, &zeta); err != nil {
		t.Fatalf("Unmarshal zeta: %v", err)
	}
	if zeta.UniformBucketLevelAccess {
		t.Errorf("zeta.UniformBucketLevelAccess = true; want false (uniform access disabled)")
	}
}

func TestCollect_NoBuckets(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("len(records) = %d; want 0", len(records))
	}
}

func TestCollect_NilBucketsSkipped(t *testing.T) {
	fake := &fakeAPI{buckets: []*gcs.BucketAttrs{nil, {Name: "a"}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("len(records) = %d; want 1", len(records))
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: "s3_bucket"})
	if err == nil || !strings.Contains(err.Error(), "unsupported evidence type") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_ListBucketsError(t *testing.T) {
	p := New(Options{API: &fakeAPI{err: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err == nil || !strings.Contains(err.Error(), "list buckets") {
		t.Errorf("want list buckets error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsedWhenNotInjected(t *testing.T) {
	fake := &fakeAPI{buckets: []*gcs.BucketAttrs{{Name: "a"}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero; want default-now-injected value")
	}
}

func TestDrainBucketIterator_HappyPath(t *testing.T) {
	buckets := []*gcs.BucketAttrs{{Name: "a"}, {Name: "b"}}
	i := 0
	next := func() (*gcs.BucketAttrs, error) {
		if i >= len(buckets) {
			return nil, iterator.Done
		}
		b := buckets[i]
		i++
		return b, nil
	}
	got, err := drainBucketIterator(next)
	if err != nil {
		t.Fatalf("drainBucketIterator: %v", err)
	}
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "b" {
		t.Errorf("got = %+v", got)
	}
}

func TestDrainBucketIterator_PropagatesError(t *testing.T) {
	next := func() (*gcs.BucketAttrs, error) { return nil, errors.New("kaboom") }
	if _, err := drainBucketIterator(next); err == nil || !strings.Contains(err.Error(), "kaboom") {
		t.Errorf("want propagated error; got %v", err)
	}
}

func TestNewFromGCP_SmokeTest(t *testing.T) {
	// Smoke test only — constructor may succeed or fail depending on
	// ambient ADC. Either outcome is acceptable.
	p, err := NewFromGCP(context.Background(), "proj-1")
	if err != nil {
		t.Logf("NewFromGCP errored (acceptable in CI without ADC): %v", err)
		return
	}
	if p.ID() != SourceID {
		t.Errorf("ID = %q", p.ID())
	}
}

func TestCollect_KISSNoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{buckets: []*gcs.BucketAttrs{{Name: "a"}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.listCount != 3 {
		t.Errorf("listCount = %d; want 3 (no caching across Collect calls per KISS-no-DRY)", fake.listCount)
	}
}
