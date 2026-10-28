package s3

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// testRegion is the AWS region used by this file's fixtures.
const testRegion = "us-east-1"

type fakeAPI struct {
	buckets         []s3types.Bucket
	pages           [][]s3types.Bucket
	enc             map[string]*s3types.ServerSideEncryptionConfiguration
	encErr          map[string]error
	publicAccess    map[string]*s3types.PublicAccessBlockConfiguration
	publicAccessErr map[string]error
	versioning      map[string]s3types.BucketVersioningStatus
	versioningErr   map[string]error
	listErr         error
	location        map[string]s3types.BucketLocationConstraint
	locationErr     map[string]error

	listCount int
	encCount  int
	// lastListInput and callRegions record what the plugin asked for, so
	// tests can assert the region each per-bucket call is routed to.
	lastListInput *awss3.ListBucketsInput
	callRegions   map[string][]string
	locationCalls int
}

// recordRegion applies the per-call option functions to an empty
// Options and keeps the region the plugin chose for this bucket call.
func (f *fakeAPI) recordRegion(bucket *string, optFns []func(*awss3.Options)) {
	var o awss3.Options
	for _, fn := range optFns {
		fn(&o)
	}
	if f.callRegions == nil {
		f.callRegions = map[string][]string{}
	}
	name := ""
	if bucket != nil {
		name = *bucket
	}
	f.callRegions[name] = append(f.callRegions[name], o.Region)
}

func (f *fakeAPI) GetBucketLocation(_ context.Context, in *awss3.GetBucketLocationInput, optFns ...func(*awss3.Options)) (*awss3.GetBucketLocationOutput, error) {
	f.locationCalls++
	if err, ok := f.locationErr[*in.Bucket]; ok {
		return nil, err
	}
	return &awss3.GetBucketLocationOutput{LocationConstraint: f.location[*in.Bucket]}, nil
}

func (f *fakeAPI) ListBuckets(_ context.Context, in *awss3.ListBucketsInput, _ ...func(*awss3.Options)) (*awss3.ListBucketsOutput, error) {
	f.listCount++
	f.lastListInput = in
	if f.listErr != nil {
		return nil, f.listErr
	}
	// When pages is set, serve one page per call keyed by the incoming
	// ContinuationToken so the pagination loop is exercised end to end.
	if len(f.pages) > 0 {
		idx := 0
		if in.ContinuationToken != nil {
			idx, _ = strconv.Atoi(*in.ContinuationToken) //nolint:errcheck // test token is always a valid int
		}
		out := &awss3.ListBucketsOutput{Buckets: f.pages[idx]}
		if idx+1 < len(f.pages) {
			next := strconv.Itoa(idx + 1)
			out.ContinuationToken = &next
		}
		return out, nil
	}
	return &awss3.ListBucketsOutput{Buckets: f.buckets}, nil
}

func (f *fakeAPI) GetBucketEncryption(_ context.Context, in *awss3.GetBucketEncryptionInput, optFns ...func(*awss3.Options)) (*awss3.GetBucketEncryptionOutput, error) {
	f.encCount++
	f.recordRegion(in.Bucket, optFns)
	if in.Bucket == nil {
		return &awss3.GetBucketEncryptionOutput{}, nil
	}
	if err, ok := f.encErr[*in.Bucket]; ok {
		return nil, err
	}
	cfg := f.enc[*in.Bucket]
	return &awss3.GetBucketEncryptionOutput{ServerSideEncryptionConfiguration: cfg}, nil
}

func (f *fakeAPI) GetPublicAccessBlock(_ context.Context, in *awss3.GetPublicAccessBlockInput, optFns ...func(*awss3.Options)) (*awss3.GetPublicAccessBlockOutput, error) {
	f.recordRegion(in.Bucket, optFns)
	if in.Bucket == nil {
		return &awss3.GetPublicAccessBlockOutput{}, nil
	}
	if err, ok := f.publicAccessErr[*in.Bucket]; ok {
		return nil, err
	}
	cfg := f.publicAccess[*in.Bucket]
	return &awss3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: cfg}, nil
}

func (f *fakeAPI) GetBucketVersioning(_ context.Context, in *awss3.GetBucketVersioningInput, optFns ...func(*awss3.Options)) (*awss3.GetBucketVersioningOutput, error) {
	f.recordRegion(in.Bucket, optFns)
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

func TestCollect_PaginatesAllBuckets(t *testing.T) {
	created := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	fake := &fakeAPI{
		pages: [][]s3types.Bucket{
			{{Name: ptr("page0-a"), BucketRegion: ptr(testRegion), CreationDate: &created}},
			{{Name: ptr("page1-a"), BucketRegion: ptr(testRegion), CreationDate: &created}},
			{{Name: ptr("page2-a"), BucketRegion: ptr(testRegion), CreationDate: &created}},
		},
	}
	p := New(Options{API: fake, Region: testRegion})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	// All three pages must be collected — not just the first.
	if len(records) != 3 {
		t.Fatalf("len(records) = %d; want 3 (buckets across all pages)", len(records))
	}
	if fake.listCount != 3 {
		t.Errorf("listCount = %d; want 3 (one call per page)", fake.listCount)
	}
}

func TestCollect_HappyPath_SortsByID(t *testing.T) {
	created := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	fake := &fakeAPI{
		buckets: []s3types.Bucket{
			{Name: ptr("zeta"), BucketRegion: ptr(testRegion), CreationDate: &created},
			{Name: ptr("alpha"), BucketRegion: ptr(testRegion), CreationDate: &created},
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
	p := New(Options{API: fake, Region: testRegion, Now: func() time.Time { return now }})
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
	if safeBucketRegion(nil, testRegion) != testRegion {
		t.Errorf("nil region didn't fall back")
	}
	if !safeCreatedAt(nil).IsZero() {
		t.Errorf("nil createdAt not zero")
	}
	// Region populated → wins over fallback.
	if got := safeBucketRegion(&s3types.Bucket{BucketRegion: ptr("eu-west-1")}, testRegion); got != "eu-west-1" {
		t.Errorf("region = %q", got)
	}
}

// An unversioned bucket must say so: the versioning policies read
// versioning_enabled unguarded, so an omitted false turns a plain
// failure into a policy error (exit 2) on every run.
func TestCollect_UnversionedBucketEmitsFalse(t *testing.T) {
	fake := &fakeAPI{buckets: []s3types.Bucket{{Name: ptr("logs"), BucketRegion: ptr(testRegion)}}}
	records, err := New(Options{API: fake, Region: testRegion}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(records[0].Payload, &raw); err != nil {
		t.Fatal(err)
	}
	v, ok := raw["versioning_enabled"]
	if !ok || v != false {
		t.Errorf("versioning_enabled = %v (present=%v); want false present", v, ok)
	}
}

// ListBuckets returns every bucket in the account, in every region. Each
// per-bucket call must go to the bucket's own region: S3 answers a call
// sent to another regional endpoint with 301 PermanentRedirect, which
// the SDK does not follow.
func TestCollect_RoutesEachBucketToItsRegion(t *testing.T) {
	fake := &fakeAPI{
		buckets: []s3types.Bucket{
			{Name: ptr("home"), BucketRegion: ptr(testRegion)},
			{Name: ptr("eu"), BucketRegion: ptr("eu-west-2")},
			{Name: ptr("legacy")},    // no BucketRegion: resolved via GetBucketLocation
			{Name: ptr("legacy-us")}, // LocationConstraint "" means us-east-1
			{Name: ptr("legacy-eu")}, // LocationConstraint "EU" means eu-west-1
		},
		location: map[string]s3types.BucketLocationConstraint{
			"legacy":    "ap-south-1",
			"legacy-us": "",
			"legacy-eu": "EU",
		},
	}
	records, err := New(Options{API: fake, Region: "us-west-2"}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.lastListInput == nil || fake.lastListInput.MaxBuckets == nil {
		t.Errorf("ListBuckets sent without MaxBuckets; S3 omits BucketRegion unless a parameter is set")
	}
	want := map[string]string{"home": testRegion, "eu": "eu-west-2", "legacy": "ap-south-1", "legacy-us": "us-east-1", "legacy-eu": "eu-west-1"}
	for name, region := range want {
		got := fake.callRegions[name]
		if len(got) != 3 {
			t.Fatalf("%s: %d per-bucket calls, want 3", name, len(got))
		}
		for _, r := range got {
			if r != region {
				t.Errorf("%s: call routed to %q, want %q", name, r, region)
			}
		}
	}
	if fake.locationCalls != 3 {
		t.Errorf("GetBucketLocation calls = %d, want 3 (only buckets without BucketRegion)", fake.locationCalls)
	}
	for i := range records {
		var pl bucketPayload
		if err := json.Unmarshal(records[i].Payload, &pl); err != nil {
			t.Fatal(err)
		}
		if pl.RegionOrLocation != want[records[i].ID] {
			t.Errorf("%s region_or_location = %q, want %q", records[i].ID, pl.RegionOrLocation, want[records[i].ID])
		}
	}
}

func TestCollect_BucketLocationErrorPropagates(t *testing.T) {
	fake := &fakeAPI{
		buckets:     []s3types.Bucket{{Name: ptr("b1")}},
		locationErr: map[string]error{"b1": errors.New("AccessDenied")},
	}
	_, err := New(Options{API: fake, Region: testRegion}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "region for bucket b1") {
		t.Errorf("want region error; got %v", err)
	}
}

func TestNewFromAWS_SmokeTest(t *testing.T) {
	p, err := NewFromAWS(context.Background(), testRegion)
	if err != nil {
		t.Logf("NewFromAWS errored (acceptable in CI): %v", err)
		return
	}
	if p.ID() != SourceID {
		t.Errorf("ID = %q", p.ID())
	}
}
