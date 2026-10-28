package ec2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	volBatch  [][]string
}

func (f *fakeAPI) DescribeInstances(_ context.Context, _ *awsec2.DescribeInstancesInput, _ ...func(*awsec2.Options)) (*awsec2.DescribeInstancesOutput, error) {
	f.descCount++
	if f.descErr != nil {
		return nil, f.descErr
	}
	return &awsec2.DescribeInstancesOutput{Reservations: f.reservations}, nil
}

// DescribeVolumes behaves like EC2: naming a volume that no longer
// exists in VolumeIds fails the whole call with InvalidVolume.NotFound,
// while a volume-id filter returns only the volumes that exist.
func (f *fakeAPI) DescribeVolumes(_ context.Context, in *awsec2.DescribeVolumesInput, _ ...func(*awsec2.Options)) (*awsec2.DescribeVolumesOutput, error) {
	f.volCount++
	if f.volErr != nil {
		return nil, f.volErr
	}
	exists := map[string]ec2types.Volume{}
	for i := range f.volumes {
		exists[*f.volumes[i].VolumeId] = f.volumes[i]
	}
	var want []string
	for _, id := range in.VolumeIds {
		if _, ok := exists[id]; !ok {
			return nil, errors.New("InvalidVolume.NotFound: The volume '" + id + "' does not exist.")
		}
		want = append(want, id)
	}
	for _, flt := range in.Filters {
		if flt.Name != nil && *flt.Name == "volume-id" {
			want = append(want, flt.Values...)
		}
	}
	f.volBatch = append(f.volBatch, want)
	out := &awsec2.DescribeVolumesOutput{}
	for _, id := range want {
		if v, ok := exists[id]; ok {
			out.Volumes = append(out.Volumes, v)
		}
	}
	return out, nil
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

// A failed DescribeVolumes (missing permission, throttle) must fail the
// collection, not report every instance's root volume as unencrypted.
func TestCollect_DescribeVolumesErrorPropagates(t *testing.T) {
	fake := &fakeAPI{reservations: rootVolumeReservations(1), volErr: errors.New("UnauthorizedOperation")}
	if _, err := New(Options{API: fake}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err == nil {
		t.Fatal("Collect = nil error; want the DescribeVolumes failure returned")
	}
}

func TestCollect_DescribeVolumesIsBatched(t *testing.T) {
	fake := &fakeAPI{reservations: rootVolumeReservations(450)}
	if _, err := New(Options{API: fake}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(fake.volBatch) != 3 {
		t.Fatalf("DescribeVolumes calls = %d; want 3 for 450 volumes", len(fake.volBatch))
	}
	for _, b := range fake.volBatch {
		if len(b) > describeVolumesBatch {
			t.Errorf("batch of %d volume IDs; want <= %d", len(b), describeVolumesBatch)
		}
	}
}

// rootVolumeReservations builds n instances, each with an EBS root volume.
func rootVolumeReservations(n int) []ec2types.Reservation {
	insts := make([]ec2types.Instance, 0, n)
	for i := range n {
		id := fmt.Sprintf("i-%04d", i)
		insts = append(insts, ec2types.Instance{
			InstanceId:     ptr(id),
			RootDeviceName: ptr("/dev/xvda"),
			BlockDeviceMappings: []ec2types.InstanceBlockDeviceMapping{{
				DeviceName: ptr("/dev/xvda"),
				Ebs:        &ec2types.EbsInstanceBlockDevice{VolumeId: ptr("vol-" + id)},
			}},
		})
	}
	return []ec2types.Reservation{{Instances: insts}}
}

// A root volume deleted between DescribeInstances and DescribeVolumes
// (an instance terminating) must not fail every EC2 policy. Shutting-down
// and terminated instances are skipped; any other instance whose root
// volume no longer exists has no readable encryption state, so it is
// left out rather than reported unencrypted.
func TestCollect_VanishedRootVolumeDoesNotFailCollect(t *testing.T) {
	inst := func(id, vol string, state ec2types.InstanceStateName) ec2types.Instance {
		return ec2types.Instance{
			InstanceId:     ptr(id),
			State:          &ec2types.InstanceState{Name: state},
			RootDeviceName: ptr("/dev/xvda"),
			BlockDeviceMappings: []ec2types.InstanceBlockDeviceMapping{
				{DeviceName: ptr("/dev/xvda"), Ebs: &ec2types.EbsInstanceBlockDevice{VolumeId: ptr(vol)}},
			},
		}
	}
	fake := &fakeAPI{
		reservations: []ec2types.Reservation{{Instances: []ec2types.Instance{
			inst("i-ok", "vol-ok", ec2types.InstanceStateNameRunning),
			inst("i-terminating", "vol-gone-1", ec2types.InstanceStateNameShuttingDown),
			inst("i-terminated", "vol-gone-2", ec2types.InstanceStateNameTerminated),
			inst("i-raced", "vol-gone-3", ec2types.InstanceStateNameRunning),
			{InstanceId: ptr("i-terminated-novol"), State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameTerminated}},
		}}},
		volumes: []ec2types.Volume{{VolumeId: ptr("vol-ok"), Encrypted: ptr(true)}},
	}
	recs, err := New(Options{API: fake}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(recs) != 1 || recs[0].ID != "i-ok" {
		ids := make([]string, 0, len(recs))
		for _, r := range recs {
			ids = append(ids, r.ID)
		}
		t.Fatalf("records = %v; want only i-ok", ids)
	}
	var pl instancePayload
	if err := json.Unmarshal(recs[0].Payload, &pl); err != nil {
		t.Fatal(err)
	}
	if !pl.RootVolumeEncrypted {
		t.Error("i-ok root_volume_encrypted = false; want true")
	}
}
