package vpc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awsec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

type fakeAPI struct {
	vpcs     []ec2types.Vpc
	flowLogs []ec2types.FlowLog
	vpcErr   error
	flowErr  error

	vpcCount  int
	flowCount int
}

func (f *fakeAPI) DescribeVpcs(_ context.Context, _ *awsec2.DescribeVpcsInput, _ ...func(*awsec2.Options)) (*awsec2.DescribeVpcsOutput, error) {
	f.vpcCount++
	if f.vpcErr != nil {
		return nil, f.vpcErr
	}
	return &awsec2.DescribeVpcsOutput{Vpcs: f.vpcs}, nil
}

func (f *fakeAPI) DescribeFlowLogs(_ context.Context, _ *awsec2.DescribeFlowLogsInput, _ ...func(*awsec2.Options)) (*awsec2.DescribeFlowLogsOutput, error) {
	f.flowCount++
	if f.flowErr != nil {
		return nil, f.flowErr
	}
	return &awsec2.DescribeFlowLogsOutput{FlowLogs: f.flowLogs}, nil
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

// TestCollect_HappyPath covers: two VPCs (one default w/o flow logs, one
// non-default with an active flow log), Name-tag resolution, flow-log
// matching by ResourceId + ACTIVE status, deterministic sorting, and that
// the four required fields are emitted on every record.
func TestCollect_HappyPath(t *testing.T) {
	fake := &fakeAPI{
		vpcs: []ec2types.Vpc{
			// non-default, has an active flow log, Name tag present
			{
				VpcId:     ptr("vpc-zzz"),
				IsDefault: ptr(false),
				CidrBlock: ptr("10.0.0.0/16"),
				Tags:      []ec2types.Tag{{Key: ptr("Name"), Value: ptr("prod-net")}},
			},
			// default, no flow log, no Name tag
			{
				VpcId:     ptr("vpc-aaa"),
				IsDefault: ptr(true),
				CidrBlock: ptr("172.31.0.0/16"),
			},
		},
		flowLogs: []ec2types.FlowLog{
			{ResourceId: ptr("vpc-zzz"), FlowLogStatus: ptr("ACTIVE")},
			// inactive flow log on vpc-aaa must NOT count
			{ResourceId: ptr("vpc-aaa"), FlowLogStatus: ptr("FAILED")},
		},
	}
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Region: "us-east-1", Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	// Sorted by ID: vpc-aaa before vpc-zzz.
	if records[0].ID != "vpc-aaa" || records[1].ID != "vpc-zzz" {
		t.Fatalf("order = [%q %q]; want [vpc-aaa vpc-zzz]", records[0].ID, records[1].ID)
	}
	assertRecordMeta(t, records, now)

	// vpc-aaa: default, no active flow log, name falls back to VPC ID.
	var aaa networkPayload
	if err := json.Unmarshal(records[0].Payload, &aaa); err != nil {
		t.Fatalf("Unmarshal aaa: %v", err)
	}
	// vpc-zzz: non-default, active flow log, Name tag wins.
	var zzz networkPayload
	if err := json.Unmarshal(records[1].Payload, &zzz); err != nil {
		t.Fatalf("Unmarshal zzz: %v", err)
	}

	checks := []struct {
		name      string
		got, want any
	}{
		{"aaa.IsDefault", aaa.IsDefault, true},
		{"aaa.FlowLogsEnabled", aaa.FlowLogsEnabled, false}, // FAILED status
		{"aaa.Name", aaa.Name, "vpc-aaa"},                   // falls back to VPC ID
		{"aaa.Provider", aaa.Provider, "aws"},
		{"aaa.Region", aaa.Region, "us-east-1"},
		{"zzz.IsDefault", zzz.IsDefault, false},
		{"zzz.FlowLogsEnabled", zzz.FlowLogsEnabled, true}, // ACTIVE flow log
		{"zzz.Name", zzz.Name, "prod-net"},                 // Name tag wins
		{"zzz.CIDRBlock", zzz.CIDRBlock, "10.0.0.0/16"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v; want %v", c.name, c.got, c.want)
		}
	}
}

// assertRecordMeta verifies per-record metadata and that the four required
// fields are emitted on every record.
func assertRecordMeta(t *testing.T, records []core.EvidenceRecord, now time.Time) {
	t.Helper()
	for i := range records {
		if records[i].CollectedAt != now {
			t.Errorf("records[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].Type != EvidenceTypeID {
			t.Errorf("records[%d].Type = %q; want %q", i, records[i].Type, EvidenceTypeID)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("records[%d].SourceID = %q; want %q", i, records[i].SourceID, SourceID)
		}
		// Required fields always present on the wire.
		var m map[string]any
		if err := json.Unmarshal(records[i].Payload, &m); err != nil {
			t.Fatalf("Unmarshal records[%d]: %v", i, err)
		}
		for _, k := range []string{"id", "name", "flow_logs_enabled", "is_default"} {
			if _, ok := m[k]; !ok {
				t.Errorf("records[%d] missing required field %q", i, k)
			}
		}
	}
}

func TestCollect_SkipsVPCWithEmptyID(t *testing.T) {
	fake := &fakeAPI{vpcs: []ec2types.Vpc{
		{},
		{VpcId: ptr("vpc-ok"), IsDefault: ptr(false)},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].ID != "vpc-ok" {
		t.Errorf("records = %v", records)
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"compute_instance"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_DescribeVpcsError(t *testing.T) {
	p := New(Options{API: &fakeAPI{vpcErr: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "describe vpcs") {
		t.Errorf("want describe vpcs error; got %v", err)
	}
}

func TestCollect_DescribeFlowLogsError(t *testing.T) {
	p := New(Options{API: &fakeAPI{flowErr: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "describe flow logs") {
		t.Errorf("want describe flow logs error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	fake := &fakeAPI{vpcs: []ec2types.Vpc{{VpcId: ptr("vpc-1")}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero")
	}
}

func TestCollect_KISSNoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{vpcs: []ec2types.Vpc{{VpcId: ptr("vpc-1")}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.vpcCount != 3 {
		t.Errorf("vpcCount = %d; want 3", fake.vpcCount)
	}
	if fake.flowCount != 3 {
		t.Errorf("flowCount = %d; want 3", fake.flowCount)
	}
}

func TestVpcName_NilSafeAndFallback(t *testing.T) {
	if vpcName(nil) != "" {
		t.Errorf("nil vpc name not empty")
	}
	// empty Name tag value falls back to VPC ID
	v := &ec2types.Vpc{VpcId: ptr("vpc-9"), Tags: []ec2types.Tag{{Key: ptr("Name"), Value: ptr("")}}}
	if got := vpcName(v); got != "vpc-9" {
		t.Errorf("vpcName empty-tag = %q; want vpc-9", got)
	}
}

func TestSafeString_NilSafe(t *testing.T) {
	if safeString(nil) != "" {
		t.Errorf("nil string not empty")
	}
	if safeString(ptr("x")) != "x" {
		t.Errorf("deref failed")
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
