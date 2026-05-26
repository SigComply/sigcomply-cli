package s3

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

type fakeAPI struct {
	buckets         []s3types.Bucket
	enc             map[string]*s3types.ServerSideEncryptionConfiguration
	encErr          map[string]error
	publicAccess    map[string]*s3types.PublicAccessBlockConfiguration
	publicAccessErr map[string]error
	versioning      map[string]s3types.BucketVersioningStatus
	versioningErr   map[string]error
	listErr         error

	listCount int
	encCount  int
}

func (f *fakeAPI) ListBuckets(_ context.Context, _ *awss3.ListBucketsInput, _ ...func(*awss3.Options)) (*awss3.ListBucketsOutput, error) {
	f.listCount++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &awss3.ListBucketsOutput{Buckets: f.buckets}, nil
}

func (f *fakeAPI) GetBucketEncryption(_ context.Context, in *awss3.GetBucketEncryptionInput, _ ...func(*awss3.Options)) (*awss3.GetBucketEncryptionOutput, error) {
	f.encCount++
	if in.Bucket == nil {
		return &awss3.GetBucketEncryptionOutput{}, nil
	}
	if err, ok := f.encErr[*in.Bucket]; ok {
		return nil, err
	}
	cfg := f.enc[*in.Bucket]
	return &awss3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: cfg}, nil
}

func (f *fakeAPI) GetPublicAccessBlock(_ context.Context, in *awss3.GetPublicAccessBlockInput, _ ...func(*awss3.Options)) (*awss3.GetPublicAccessBlockOutput, error) {
	if in.Bucket == nil {
		return &awss3.GetPublicAccessBlockOutput{}, nil
	}
	if err, ok := f.publicAccessErr[*in.Bucket]; ok {
		return nil, err
	}
	cfg := f.publicAccess[*in.Bucket]
	return &awss3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: cfg}, nil
}

func (f *fakeAPI) GetBucketVersioning(_ context.Context, in *awss3.GetBucketVersioningInput, _ ...func(*awss3.Options)) (*awss3.GetBucketVersioningOutput, error) {
	if in.Bucket == nil {
		return &awss3.GetBucketVersioningOutput{}, nil
	}
	if err, ok := f.versioningErr[*in.Bucket]; ok {
		return nil, err
	}
	return &awss3.GetBucketVersioningOutput{Status: f.versioning[*in.Bucket]}, nil
}

type notFoundError struct{ code string }

func (e notFoundError) Error() string {
	if e.code == "" {
		return "not found"
	}
	return e.code
}
func (e notFoundError) ErrorCode() string {
	if e.code == "" {
		return "ServerSideEncryptionConfigurationNotFoundError"
	}
	return e.code
}
func (notFoundError) ErrorMessage() string          { return "" }
func (notFoundError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

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
	created := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	fake := &fakeAPI{
		buckets: []s3types.Bucket{
			{Name: ptr("zeta"), BucketRegion: ptr("us-east-1"), CreationDate: &created},
			{Name: ptr("alpha"), BucketRegion: ptr("us-east-1"), CreationDate: &created},
		},
		enc: map[string]*s3types.ServerSideEncryptionConfiguration{
			"alpha": {Rules: []s3types.ServerSideEncryptionRule{{
				ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
					SSEAlgorithm:   s3types.ServerSideEncryptionAes256,
					KMSMasterKeyID: ptr("arn:aws:kms:us-east-1:1:key/abc"),
				},
			}}},
		},
	}
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Region: "us-east-1", Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1", SlotName: "buckets"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	if records[0].ID != "alpha" || records[1].ID != "zeta" {
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
	if !alpha.EncryptionAtRestEnabled {
		t.Errorf("alpha.EncryptionAtRestEnabled = false; want true")
	}
	if alpha.KMSKeyID == "" {
		t.Errorf("alpha.KMSKeyID empty")
	}
	var zeta bucketPayload
	if err := json.Unmarshal(records[1].Payload, &zeta); err != nil {
		t.Fatalf("Unmarshal zeta: %v", err)
	}
	if zeta.EncryptionAtRestEnabled {
		t.Errorf("zeta.EncryptionAtRestEnabled = true; want false (no encryption config)")
	}
}

func TestCollect_EncryptionNotFound_TreatedAsDisabled(t *testing.T) {
	fake := &fakeAPI{
		buckets: []s3types.Bucket{{Name: ptr("plain")}},
		encErr:  map[string]error{"plain": notFoundError{}},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d", len(records))
	}
	var pl bucketPayload
	if err := json.Unmarshal(records[0].Payload, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pl.EncryptionAtRestEnabled {
		t.Errorf("EncryptionAtRestEnabled = true; want false for not-found")
	}
}

func TestCollect_EncryptionUnexpectedError_Propagates(t *testing.T) {
	fake := &fakeAPI{
		buckets: []s3types.Bucket{{Name: ptr("b1")}},
		encErr:  map[string]error{"b1": errors.New("boom")},
	}
	p := New(Options{API: fake})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "encryption for bucket b1") {
		t.Errorf("want encryption error; got %v", err)
	}
}

func TestCollect_ListError(t *testing.T) {
	p := New(Options{API: &fakeAPI{listErr: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "list buckets") {
		t.Errorf("want list error; got %v", err)
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"directory_user"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsedWhenNotInjected(t *testing.T) {
	fake := &fakeAPI{buckets: []s3types.Bucket{{Name: ptr("a")}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero; want default-now-injected value")
	}
}

func TestCollect_KISSNoDRY_EachCallReListsBuckets(t *testing.T) {
	fake := &fakeAPI{buckets: []s3types.Bucket{{Name: ptr("a")}}}
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

func TestCollect_SkipsBucketWithEmptyName(t *testing.T) {
	fake := &fakeAPI{buckets: []s3types.Bucket{
		{Name: ptr("")},
		{Name: nil},
		{Name: ptr("ok")},
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

func TestSafeHelpers_NilSafe(t *testing.T) {
	if safeBucketName(nil) != "" {
		t.Errorf("nil name not empty")
	}
	if safeBucketRegion(nil, "us-east-1") != "us-east-1" {
		t.Errorf("nil region didn't fall back")
	}
	if !safeCreatedAt(nil).IsZero() {
		t.Errorf("nil createdAt not zero")
	}
	// Region populated → wins over fallback.
	if got := safeBucketRegion(&s3types.Bucket{BucketRegion: ptr("eu-west-1")}, "us-east-1"); got != "eu-west-1" {
		t.Errorf("region = %q", got)
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
