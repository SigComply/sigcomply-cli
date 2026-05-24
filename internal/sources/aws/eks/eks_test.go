package eks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awseks "github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

type fakeAPI struct {
	clusters    []string
	descByName  map[string]*ekstypes.Cluster
	descErrByID map[string]error
	listErr     error

	listCount int
	descCount int
}

func (f *fakeAPI) ListClusters(_ context.Context, _ *awseks.ListClustersInput, _ ...func(*awseks.Options)) (*awseks.ListClustersOutput, error) {
	f.listCount++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &awseks.ListClustersOutput{Clusters: f.clusters}, nil
}

func (f *fakeAPI) DescribeCluster(_ context.Context, in *awseks.DescribeClusterInput, _ ...func(*awseks.Options)) (*awseks.DescribeClusterOutput, error) {
	f.descCount++
	if in.Name == nil {
		return &awseks.DescribeClusterOutput{}, nil
	}
	if err, ok := f.descErrByID[*in.Name]; ok {
		return nil, err
	}
	return &awseks.DescribeClusterOutput{Cluster: f.descByName[*in.Name]}, nil
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
		clusters: []string{"zeta", "alpha"},
		descByName: map[string]*ekstypes.Cluster{
			"alpha": {
				Name:    ptr("alpha"),
				Arn:     ptr("arn:aws:eks::1:cluster/alpha"),
				Status:  ekstypes.ClusterStatusActive,
				Version: ptr("1.30"),
				EncryptionConfig: []ekstypes.EncryptionConfig{{
					Resources: []string{"secrets"},
					Provider:  &ekstypes.Provider{KeyArn: ptr("arn:aws:kms:::key/abc")},
				}},
			},
			"zeta": {
				Name:    ptr("zeta"),
				Arn:     ptr("arn:aws:eks::1:cluster/zeta"),
				Status:  ekstypes.ClusterStatusActive,
				Version: ptr("1.30"),
			},
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
	var alpha clusterPayload
	if err := json.Unmarshal(records[0].Payload, &alpha); err != nil {
		t.Fatalf("Unmarshal alpha: %v", err)
	}
	if !alpha.SecretsEncryptionEnabled {
		t.Errorf("alpha.SecretsEncryptionEnabled = false; want true")
	}
	if alpha.SecretsEncryptionKMSKeyARN == "" {
		t.Errorf("alpha.SecretsEncryptionKMSKeyARN empty")
	}
	var zeta clusterPayload
	if err := json.Unmarshal(records[1].Payload, &zeta); err != nil {
		t.Fatalf("Unmarshal zeta: %v", err)
	}
	if zeta.SecretsEncryptionEnabled {
		t.Errorf("zeta.SecretsEncryptionEnabled = true; want false")
	}
	for i := range records {
		if records[i].CollectedAt != now {
			t.Errorf("record[%d].CollectedAt = %v", i, records[i].CollectedAt)
		}
	}
}

func TestCollect_EncryptionConfigWithoutSecretsResource_TreatedAsDisabled(t *testing.T) {
	fake := &fakeAPI{
		clusters: []string{"c1"},
		descByName: map[string]*ekstypes.Cluster{
			"c1": {EncryptionConfig: []ekstypes.EncryptionConfig{{
				Resources: []string{"configmaps"},
				Provider:  &ekstypes.Provider{KeyArn: ptr("arn:aws:kms:::key/abc")},
			}}},
		},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var pl clusterPayload
	if err := json.Unmarshal(records[0].Payload, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pl.SecretsEncryptionEnabled {
		t.Errorf("SecretsEncryptionEnabled = true; want false (no 'secrets' resource)")
	}
}

func TestCollect_EncryptionConfigWithSecretsButMissingProvider_TreatedAsDisabled(t *testing.T) {
	fake := &fakeAPI{
		clusters: []string{"c1"},
		descByName: map[string]*ekstypes.Cluster{
			"c1": {EncryptionConfig: []ekstypes.EncryptionConfig{{
				Resources: []string{"secrets"},
			}}},
		},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var pl clusterPayload
	if err := json.Unmarshal(records[0].Payload, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pl.SecretsEncryptionEnabled {
		t.Errorf("SecretsEncryptionEnabled = true; want false (no provider)")
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"user_record"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_ListError(t *testing.T) {
	p := New(Options{API: &fakeAPI{listErr: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "list clusters") {
		t.Errorf("want list error; got %v", err)
	}
}

func TestCollect_DescribeError(t *testing.T) {
	fake := &fakeAPI{
		clusters:    []string{"c1"},
		descErrByID: map[string]error{"c1": errors.New("denied")},
	}
	p := New(Options{API: fake})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "describe cluster c1") {
		t.Errorf("want describe error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	fake := &fakeAPI{clusters: []string{"c1"}, descByName: map[string]*ekstypes.Cluster{"c1": {}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero")
	}
}

func TestCollect_SkipsEmptyClusterName(t *testing.T) {
	fake := &fakeAPI{clusters: []string{"", "ok"}, descByName: map[string]*ekstypes.Cluster{"ok": {}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].ID != "ok" {
		t.Errorf("records = %v", records)
	}
}

func TestCollect_KISSNoDRY_EachCallReLists(t *testing.T) {
	fake := &fakeAPI{clusters: []string{"c1"}, descByName: map[string]*ekstypes.Cluster{"c1": {}}}
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

func TestSafeHelpers_NilSafe(t *testing.T) {
	if safeCluster(nil) != nil {
		t.Errorf("nil cluster not nil")
	}
	if safeARN(nil) != "" {
		t.Errorf("nil arn not empty")
	}
	if safeStatus(nil) != "" {
		t.Errorf("nil status not empty")
	}
	if safeVersion(nil) != "" {
		t.Errorf("nil version not empty")
	}
	c := &ekstypes.Cluster{Arn: ptr("a"), Status: ekstypes.ClusterStatusActive, Version: ptr("1.30")}
	if safeARN(c) != "a" || safeStatus(c) == "" || safeVersion(c) != "1.30" {
		t.Errorf("safe helpers returned unexpected values")
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
