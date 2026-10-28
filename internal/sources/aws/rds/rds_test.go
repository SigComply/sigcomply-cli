package rds

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awsrds "github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// paramForceSSL is the PostgreSQL TLS parameter the fixtures set.
const paramForceSSL = "rds.force_ssl"

type fakeAPI struct {
	instances []rdstypes.DBInstance
	err       error

	// params maps parameter-group name -> parameter name -> value, used to
	// drive ssl_required detection.
	params   map[string]map[string]string
	paramErr error

	clusters      map[string]rdstypes.DBCluster
	clusterParams map[string]map[string]string

	count        int
	paramCalls   int
	clusterCalls int
}

func (f *fakeAPI) DescribeDBClusters(_ context.Context, in *awsrds.DescribeDBClustersInput, _ ...func(*awsrds.Options)) (*awsrds.DescribeDBClustersOutput, error) {
	f.clusterCalls++
	cl, ok := f.clusters[*in.DBClusterIdentifier]
	if !ok {
		return nil, errors.New("DBClusterNotFoundFault")
	}
	return &awsrds.DescribeDBClustersOutput{DBClusters: []rdstypes.DBCluster{cl}}, nil
}

func (f *fakeAPI) DescribeDBClusterParameters(_ context.Context, in *awsrds.DescribeDBClusterParametersInput, _ ...func(*awsrds.Options)) (*awsrds.DescribeDBClusterParametersOutput, error) {
	var out awsrds.DescribeDBClusterParametersOutput
	for name, val := range f.clusterParams[*in.DBClusterParameterGroupName] {
		out.Parameters = append(out.Parameters, rdstypes.Parameter{ParameterName: ptr(name), ParameterValue: ptr(val)})
	}
	return &out, nil
}

func (f *fakeAPI) DescribeDBInstances(_ context.Context, _ *awsrds.DescribeDBInstancesInput, _ ...func(*awsrds.Options)) (*awsrds.DescribeDBInstancesOutput, error) {
	f.count++
	if f.err != nil {
		return nil, f.err
	}
	return &awsrds.DescribeDBInstancesOutput{DBInstances: f.instances}, nil
}

func (f *fakeAPI) DescribeDBParameters(_ context.Context, in *awsrds.DescribeDBParametersInput, _ ...func(*awsrds.Options)) (*awsrds.DescribeDBParametersOutput, error) {
	f.paramCalls++
	if f.paramErr != nil {
		return nil, f.paramErr
	}
	var out awsrds.DescribeDBParametersOutput
	group := ""
	if in.DBParameterGroupName != nil {
		group = *in.DBParameterGroupName
	}
	for name, val := range f.params[group] {
		out.Parameters = append(out.Parameters, rdstypes.Parameter{
			ParameterName:  ptr(name),
			ParameterValue: ptr(val),
		})
	}
	return &out, nil
}

// pgGroups builds the DBParameterGroups slice for an instance.
func pgGroups(name string) []rdstypes.DBParameterGroupStatus {
	return []rdstypes.DBParameterGroupStatus{{DBParameterGroupName: ptr(name)}}
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
		instances: []rdstypes.DBInstance{
			{DBInstanceIdentifier: ptr("zeta"), Engine: ptr("postgres"), StorageEncrypted: ptr(false), PubliclyAccessible: ptr(true)},
			{DBInstanceIdentifier: ptr("alpha"), Engine: ptr("mysql"), StorageEncrypted: ptr(true), KmsKeyId: ptr("arn:aws:kms:::key/abc")},
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
	var alpha instancePayload
	if err := json.Unmarshal(records[0].Payload, &alpha); err != nil {
		t.Fatalf("Unmarshal alpha: %v", err)
	}
	if !alpha.StorageEncrypted {
		t.Errorf("alpha.StorageEncrypted = false; want true")
	}
	if alpha.KMSKeyID == "" {
		t.Errorf("alpha.KMSKeyID empty")
	}
	var zeta instancePayload
	if err := json.Unmarshal(records[1].Payload, &zeta); err != nil {
		t.Fatalf("Unmarshal zeta: %v", err)
	}
	if zeta.StorageEncrypted {
		t.Errorf("zeta.StorageEncrypted = true; want false")
	}
	if !zeta.PubliclyAccessible {
		t.Errorf("zeta.PubliclyAccessible = false; want true")
	}
	for i := range records {
		if records[i].CollectedAt != now {
			t.Errorf("record[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("record[%d].SourceID = %q", i, records[i].SourceID)
		}
	}
}

func TestCollect_SSLRequired_MeasuredFromParameterGroup(t *testing.T) {
	fake := &fakeAPI{
		instances: []rdstypes.DBInstance{
			{DBInstanceIdentifier: ptr("pg-on"), Engine: ptr("postgres"), DBParameterGroups: pgGroups("pg1")},
			{DBInstanceIdentifier: ptr("my-off"), Engine: ptr("mysql"), DBParameterGroups: pgGroups("my1")},
			{DBInstanceIdentifier: ptr("oracle-unknown"), Engine: ptr("oracle-ee"), DBParameterGroups: pgGroups("or1")},
		},
		params: map[string]map[string]string{
			"pg1": {paramForceSSL: "1"},
			"my1": {"require_secure_transport": "OFF"},
		},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := map[string]instancePayload{}
	for _, r := range records {
		var pl instancePayload
		if err := json.Unmarshal(r.Payload, &pl); err != nil {
			t.Fatalf("Unmarshal %s: %v", r.ID, err)
		}
		byID[r.ID] = pl
	}
	if v := byID["pg-on"].SSLRequired; v == nil || !*v {
		t.Errorf("pg-on ssl_required = %v; want true", v)
	}
	if v := byID["my-off"].SSLRequired; v == nil || *v {
		t.Errorf("my-off ssl_required = %v; want false", v)
	}
	// Oracle is not introspectable via parameter group -> omitted (nil).
	if v := byID["oracle-unknown"].SSLRequired; v != nil {
		t.Errorf("oracle ssl_required = %v; want nil (omitted)", v)
	}
	// The "oracle-unknown" payload must not carry the key at all.
	var raw map[string]any
	for _, r := range records {
		if r.ID == "oracle-unknown" {
			if err := json.Unmarshal(r.Payload, &raw); err != nil {
				t.Fatalf("Unmarshal oracle: %v", err)
			}
		}
	}
	if _, present := raw["ssl_required"]; present {
		t.Errorf("oracle payload should omit ssl_required, got present")
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
	if err == nil || !strings.Contains(err.Error(), "describe db instances") {
		t.Errorf("want describe error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	fake := &fakeAPI{instances: []rdstypes.DBInstance{{DBInstanceIdentifier: ptr("a")}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero")
	}
}

func TestCollect_SkipsInstanceWithEmptyID(t *testing.T) {
	fake := &fakeAPI{instances: []rdstypes.DBInstance{
		{},
		{DBInstanceIdentifier: ptr("ok")},
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
	fake := &fakeAPI{instances: []rdstypes.DBInstance{{DBInstanceIdentifier: ptr("a")}}}
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
	if safeIdentifier(nil) != "" {
		t.Errorf("nil identifier not empty")
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

// A denied DescribeDBParameters used to omit ssl_required, which the
// policy reads as "undeterminable" and skips: the database passed
// database_ssl_required without being judged.
func TestCollect_ParameterReadErrorPropagates(t *testing.T) {
	fake := &fakeAPI{
		instances: []rdstypes.DBInstance{{DBInstanceIdentifier: ptr("pg"), Engine: ptr("postgres"), DBParameterGroups: pgGroups("custom-pg")}},
		paramErr:  errors.New("AccessDenied"),
	}
	if _, err := New(Options{API: fake}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err == nil {
		t.Fatal("Collect = nil error; want the DescribeDBParameters failure returned")
	}
}

// An Aurora instance reports its cluster's deletion protection, Multi-AZ
// and backup settings (AWS returns them as false on the instance), and
// its TLS parameter from the cluster parameter group.
func TestCollect_AuroraReadsTheCluster(t *testing.T) {
	fake := &fakeAPI{
		instances: []rdstypes.DBInstance{
			{DBInstanceIdentifier: ptr("aurora-1"), Engine: ptr("aurora-postgresql"), DBClusterIdentifier: ptr("c1"),
				DeletionProtection: ptr(false), MultiAZ: ptr(false), BackupRetentionPeriod: ptr(int32(1)),
				DBParameterGroups: pgGroups("default.aurora-postgresql16")},
			{DBInstanceIdentifier: ptr("aurora-2"), Engine: ptr("aurora-mysql"), DBClusterIdentifier: ptr("c2"),
				DBParameterGroups: pgGroups("default.aurora-mysql8.0")},
		},
		params: map[string]map[string]string{"default.aurora-postgresql16": {paramForceSSL: "0"}},
		clusters: map[string]rdstypes.DBCluster{
			"c1": {DeletionProtection: ptr(true), MultiAZ: ptr(true), StorageEncrypted: ptr(true),
				BackupRetentionPeriod: ptr(int32(7)), DBClusterParameterGroup: ptr("cpg-1")},
			"c2": {DeletionProtection: ptr(false), MultiAZ: ptr(false), DBClusterParameterGroup: ptr("cpg-2")},
		},
		clusterParams: map[string]map[string]string{
			"cpg-1": {paramForceSSL: "1"},
			"cpg-2": {"require_secure_transport": "OFF"},
		},
	}
	recs, err := New(Options{API: fake}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	got := map[string]instancePayload{}
	for _, r := range recs {
		var pl instancePayload
		if err := json.Unmarshal(r.Payload, &pl); err != nil {
			t.Fatal(err)
		}
		got[r.ID] = pl
	}
	a1, a2 := got["aurora-1"], got["aurora-2"]
	if !a1.DeletionProtection || !a1.MultiAZ || !a1.StorageEncrypted || !a1.BackupEnabled || a1.SSLRequired == nil || !*a1.SSLRequired {
		t.Errorf("aurora-1 = %+v; want the cluster's protection, multi-AZ, encryption, backup and force_ssl=1", a1)
	}
	if a2.DeletionProtection || a2.SSLRequired == nil || *a2.SSLRequired {
		t.Errorf("aurora-2 = %+v; want no deletion protection and ssl_required false", a2)
	}
	if fake.paramCalls != 0 {
		t.Errorf("DescribeDBParameters calls = %d; want 0 (Aurora TLS lives in the cluster group)", fake.paramCalls)
	}
}
