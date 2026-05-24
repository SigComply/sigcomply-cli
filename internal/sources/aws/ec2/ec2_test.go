package ec2

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
	reservations []ec2types.Reservation
	err          error

	count int
}

func (f *fakeAPI) DescribeInstances(_ context.Context, _ *awsec2.DescribeInstancesInput, _ ...func(*awsec2.Options)) (*awsec2.DescribeInstancesOutput, error) {
	f.count++
	if f.err != nil {
		return nil, f.err
	}
	return &awsec2.DescribeInstancesOutput{Reservations: f.reservations}, nil
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

func TestCollect_HappyPath_FlattensReservationsAndSorts(t *testing.T) {
	fake := &fakeAPI{
		reservations: []ec2types.Reservation{
			{Instances: []ec2types.Instance{
				{InstanceId: ptr("i-zzz"), PublicIpAddress: ptr("1.2.3.4"), PrivateIpAddress: ptr("10.0.0.5"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}, InstanceType: ec2types.InstanceTypeT3Micro, VpcId: ptr("vpc-1")},
				{InstanceId: ptr("i-aaa"), PrivateIpAddress: ptr("10.0.0.6"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped}, VpcId: ptr("vpc-1")},
			}},
			{Instances: []ec2types.Instance{
				{InstanceId: ptr("i-mmm")},
			}},
		},
	}
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("len(records) = %d; want 3", len(records))
	}
	wantOrder := []string{"i-aaa", "i-mmm", "i-zzz"}
	for i, want := range wantOrder {
		if records[i].ID != want {
			t.Errorf("records[%d].ID = %q; want %q", i, records[i].ID, want)
		}
		if records[i].CollectedAt != now {
			t.Errorf("records[%d].CollectedAt = %v", i, records[i].CollectedAt)
		}
	}
	// i-zzz has public IP.
	var zzz instancePayload
	if err := json.Unmarshal(records[2].Payload, &zzz); err != nil {
		t.Fatalf("Unmarshal zzz: %v", err)
	}
	if !zzz.HasPublicIP {
		t.Errorf("zzz.HasPublicIP = false; want true")
	}
	if zzz.PublicIPAddress != "1.2.3.4" {
		t.Errorf("zzz.PublicIPAddress = %q", zzz.PublicIPAddress)
	}
	// i-aaa has no public IP.
	var aaa instancePayload
	if err := json.Unmarshal(records[0].Payload, &aaa); err != nil {
		t.Fatalf("Unmarshal aaa: %v", err)
	}
	if aaa.HasPublicIP {
		t.Errorf("aaa.HasPublicIP = true; want false")
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: "kms_key"})
	if err == nil || !strings.Contains(err.Error(), "unsupported evidence type") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_DescribeError(t *testing.T) {
	p := New(Options{API: &fakeAPI{err: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err == nil || !strings.Contains(err.Error(), "describe instances") {
		t.Errorf("want describe error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	fake := &fakeAPI{reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{{InstanceId: ptr("i-1")}}}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero")
	}
}

func TestCollect_SkipsInstanceWithEmptyID(t *testing.T) {
	fake := &fakeAPI{reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
		{},
		{InstanceId: ptr("i-ok")},
	}}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].ID != "i-ok" {
		t.Errorf("records = %v", records)
	}
}

func TestCollect_KISSNoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{{InstanceId: ptr("i-1")}}}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{EvidenceType: EvidenceTypeID}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.count != 3 {
		t.Errorf("count = %d; want 3", fake.count)
	}
}

func TestSafeHelpers_NilSafe(t *testing.T) {
	if safeInstanceID(nil) != "" {
		t.Errorf("nil id not empty")
	}
	if safeString(nil) != "" {
		t.Errorf("nil string not empty")
	}
	if safeState(nil) != "" {
		t.Errorf("nil state not empty")
	}
	if got := safeState(&ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning}); got != "running" {
		t.Errorf("safeState = %q", got)
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
