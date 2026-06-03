package ecr

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

type fakeAPI struct {
	repos []ecrtypes.Repository
	err   error

	count int
}

func (f *fakeAPI) DescribeRepositories(_ context.Context, _ *awsecr.DescribeRepositoriesInput, _ ...func(*awsecr.Options)) (*awsecr.DescribeRepositoriesOutput, error) {
	f.count++
	if f.err != nil {
		return nil, f.err
	}
	return &awsecr.DescribeRepositoriesOutput{Repositories: f.repos}, nil
}

func ptr[T any](v T) *T { return &v }

// repo builds an encrypted Repository with the common attributes used
// across tests (ECR always encrypts at rest).
func repo(name string, scanOnPush bool, mutability string) ecrtypes.Repository {
	return ecrtypes.Repository{
		RepositoryName:             ptr(name),
		RepositoryArn:              ptr("arn:aws:ecr:us-east-1:123456789012:repository/" + name),
		RepositoryUri:              ptr("123456789012.dkr.ecr.us-east-1.amazonaws.com/" + name),
		ImageScanningConfiguration: &ecrtypes.ImageScanningConfiguration{ScanOnPush: scanOnPush},
		ImageTagMutability:         ecrtypes.ImageTagMutability(mutability),
		EncryptionConfiguration:    &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionTypeAes256},
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

func collectByID(t *testing.T, fake *fakeAPI) map[string]registryPayload {
	t.Helper()
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := map[string]registryPayload{}
	for _, r := range records {
		var pl registryPayload
		if err := json.Unmarshal(r.Payload, &pl); err != nil {
			t.Fatalf("Unmarshal %s: %v", r.ID, err)
		}
		byID[r.ID] = pl
	}
	return byID
}

func TestCollect_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{
		repos: []ecrtypes.Repository{
			repo("zeta", false, "MUTABLE"),
			repo("alpha", true, "IMMUTABLE"),
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

func TestCollect_PayloadFieldMapping(t *testing.T) {
	tests := []struct {
		name       string
		repo       ecrtypes.Repository
		wantScan   bool
		wantImmut  bool
		wantEncr   bool
		wantPublic bool
	}{
		{
			name:      "scan-on, immutable, encrypted",
			repo:      repo("a", true, "IMMUTABLE"),
			wantScan:  true,
			wantImmut: true,
			wantEncr:  true,
		},
		{
			name:      "scan-off, mutable, encrypted",
			repo:      repo("b", false, "MUTABLE"),
			wantScan:  false,
			wantImmut: false,
			wantEncr:  true,
		},
		{
			name:     "no scanning config => scan off",
			repo:     ecrtypes.Repository{RepositoryName: ptr("c"), EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{}},
			wantScan: false,
			wantEncr: true,
		},
		{
			name:     "no encryption config => not encrypted",
			repo:     ecrtypes.Repository{RepositoryName: ptr("d")},
			wantEncr: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			byID := collectByID(t, &fakeAPI{repos: []ecrtypes.Repository{tc.repo}})
			pl := byID[*tc.repo.RepositoryName]
			if pl.Provider != providerName {
				t.Errorf("Provider = %q; want %q", pl.Provider, providerName)
			}
			if pl.ScanOnPushEnabled != tc.wantScan {
				t.Errorf("ScanOnPushEnabled = %v; want %v", pl.ScanOnPushEnabled, tc.wantScan)
			}
			if pl.ImageImmutabilityEnabled != tc.wantImmut {
				t.Errorf("ImageImmutabilityEnabled = %v; want %v", pl.ImageImmutabilityEnabled, tc.wantImmut)
			}
			if pl.EncryptionEnabled != tc.wantEncr {
				t.Errorf("EncryptionEnabled = %v; want %v", pl.EncryptionEnabled, tc.wantEncr)
			}
			if pl.IsPublic != tc.wantPublic {
				t.Errorf("IsPublic = %v; want %v", pl.IsPublic, tc.wantPublic)
			}
		})
	}
}

// TestCollect_AlwaysEmitsRequiredFields guards that every policy-read and
// schema-required field is present on every record (the evaluator errors
// on referenced-but-absent fields).
func TestCollect_AlwaysEmitsRequiredFields(t *testing.T) {
	fake := &fakeAPI{repos: []ecrtypes.Repository{{RepositoryName: ptr("bare")}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(records[0].Payload, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, field := range []string{"id", "name", "scan_on_push_enabled", "is_public", "encryption_enabled", "image_immutability_enabled", "provider"} {
		if _, present := raw[field]; !present {
			t.Errorf("payload missing required field %q", field)
		}
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"directory_user"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_DescribeError(t *testing.T) {
	p := New(Options{API: &fakeAPI{err: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "describe repositories") {
		t.Errorf("want describe error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	fake := &fakeAPI{repos: []ecrtypes.Repository{{RepositoryName: ptr("a")}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero")
	}
}

func TestCollect_SkipsRepositoryWithEmptyName(t *testing.T) {
	fake := &fakeAPI{repos: []ecrtypes.Repository{
		{},
		{RepositoryName: ptr("ok")},
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
	fake := &fakeAPI{repos: []ecrtypes.Repository{{RepositoryName: ptr("a")}}}
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
	if safeRepositoryName(nil) != "" {
		t.Errorf("nil repository name not empty")
	}
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
