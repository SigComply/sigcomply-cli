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
	volumes      []ec2types.Volume
	descErr      error
	volErr       error

	descCount int
	volCount  int
}

func (f *fakeAPI) DescribeInstances(_ context.Context, _ *awsec2.DescribeInstancesInput, _ ...func(*awsec2.Options)) (*awsec2.DescribeInstancesOutput, error) {
	f.descCount++
	if f.descErr != nil {
		return nil, f.descErr
	}
	return &awsec2.DescribeInstancesOutput{Reservations: f.reservations}, nil
}

func (f *fakeAPI) DescribeVolumes(_ context.Context, _ *awsec2.DescribeVolumesInput, _ ...func(*awsec2.Options)) (*awsec2.DescribeVolumesOutput, error) {
	f.volCount++
	if f.volErr != nil {
		return nil, f.volErr
	}
	return &awsec2.DescribeVolumesOutput{Volumes: f.volumes}, nil
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
				{
					InstanceId:      ptr("i-zzz"),
					PublicIpAddress: ptr("1.2.3.4"),
					State:           &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
					InstanceType:    ec2types.InstanceTypeT3Micro,
					VpcId:           ptr("vpc-1"),
					Monitoring:      &ec2types.Monitoring{State: ec2types.MonitoringStateEnabled},
				},
				{
					InstanceId: ptr("i-aaa"),
					State:      &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped},
					VpcId:      ptr("vpc-1"),
				},
			}},
			{Instances: []ec2types.Instance{
				{InstanceId: ptr("i-mmm")},
			}},
		},
	}
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
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
		if records[i].Type != EvidenceTypeID {
			t.Errorf("records[%d].Type = %q; want %q", i, records[i].Type, EvidenceTypeID)
		}
	}
	// i-zzz has public IP and monitoring enabled.
	var zzz instancePayload
	if err := json.Unmarshal(records[2].Payload, &zzz); err != nil {
		t.Fatalf("Unmarshal zzz: %v", err)
	}
	if !zzz.HasPublicIP {
		t.Errorf("zzz.HasPublicIP = false; want true")
	}
	if !zzz.IsRunning {
		t.Errorf("zzz.IsRunning = false; want true")
	}
	if !zzz.MonitoringEnabled {
		t.Errorf("zzz.MonitoringEnabled = false; want true")
	}
	// i-aaa has no public IP, not running.
	var aaa instancePayload
	if err := json.Unmarshal(records[0].Payload, &aaa); err != nil {
		t.Fatalf("Unmarshal aaa: %v", err)
	}
	if aaa.HasPublicIP {
		t.Errorf("aaa.HasPublicIP = true; want false")
	}
	if aaa.IsRunning {
		t.Errorf("aaa.IsRunning = true; want false")
	}
}

func TestCollect_RootVolumeEncryption(t *testing.T) {
	fake := &fakeAPI{
		reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
			{
				InstanceId:     ptr("i-enc"),
				RootDeviceName: ptr("/dev/xvda"),
				BlockDeviceMappings: []ec2types.InstanceBlockDeviceMapping{
					{DeviceName: ptr("/dev/xvda"), Ebs: &ec2types.EbsInstanceBlockDevice{VolumeId: ptr("vol-abc")}},
				},
			},
		}}},
		volumes: []ec2types.Volume{
			{VolumeId: ptr("vol-abc"), Encrypted: ptr(true)},
		},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var payload instancePayload
	if err := json.Unmarshal(records[0].Payload, &payload); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !payload.RootVolumeEncrypted {
		t.Errorf("RootVolumeEncrypted = false; want true")
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"kms_key"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_DescribeError(t *testing.T) {
	p := New(Options{API: &fakeAPI{descErr: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "describe instances") {
		t.Errorf("want describe error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	fake := &fakeAPI{reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{{InstanceId: ptr("i-1")}}}}}
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
	fake := &fakeAPI{reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
		{},
		{InstanceId: ptr("i-ok")},
	}}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
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
		if _, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.descCount != 3 {
		t.Errorf("descCount = %d; want 3", fake.descCount)
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
	if safeMonitoring(nil) {
		t.Errorf("nil monitoring should be false")
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
