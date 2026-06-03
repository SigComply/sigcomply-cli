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

type fakeAPI struct {
	instances []rdstypes.DBInstance
	err       error

	// params maps parameter-group name -> parameter name -> value, used to
	// drive ssl_required detection.
	params map[string]map[string]string

	count      int
	paramCalls int
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
			"pg1": {"rds.force_ssl": "1"},
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
