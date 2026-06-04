package sql

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	sqladmin "google.golang.org/api/sqladmin/v1"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI lets tests drive the plugin without real Cloud SQL calls.
type fakeAPI struct {
	instances []*sqladmin.DatabaseInstance
	err       error

	listCount int
}

func (f *fakeAPI) ListInstances(_ context.Context, _ string) ([]*sqladmin.DatabaseInstance, error) {
	f.listCount++
	if f.err != nil {
		return nil, f.err
	}
	return f.instances, nil
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

func TestCollect_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{instances: []*sqladmin.DatabaseInstance{
		{
			Name:            "zeta-db",
			DatabaseVersion: "POSTGRES_15",
			Region:          "us-central1",
			State:           "RUNNABLE",
			Settings: &sqladmin.Settings{
				IpConfiguration:           &sqladmin.IpConfiguration{RequireSsl: false, Ipv4Enabled: true},
				BackupConfiguration:       &sqladmin.BackupConfiguration{Enabled: false},
				AvailabilityType:          "ZONAL",
				DeletionProtectionEnabled: false,
			},
		},
		{
			Name:            "alpha-db",
			DatabaseVersion: "MYSQL_8_0",
			Region:          "europe-west1",
			State:           "RUNNABLE",
			Settings: &sqladmin.Settings{
				IpConfiguration:           &sqladmin.IpConfiguration{RequireSsl: true, SslMode: "ENCRYPTED_ONLY", Ipv4Enabled: false},
				BackupConfiguration:       &sqladmin.BackupConfiguration{Enabled: true, PointInTimeRecoveryEnabled: true},
				AvailabilityType:          "REGIONAL",
				DeletionProtectionEnabled: true,
			},
		},
	}}
	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, ProjectID: "p1", Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}, PolicyID: "p1", SlotName: "instances"})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	// Sorted by ID (= Name): alpha-db before zeta-db.
	if records[0].ID != "alpha-db" || records[1].ID != "zeta-db" {
		t.Errorf("records not sorted by ID: got %v", []string{records[0].ID, records[1].ID})
	}
	assertCommonRecordFields(t, records, now)
	assertAlphaPayload(t, &records[0])
	assertZetaPayload(t, &records[1])
}

func assertCommonRecordFields(t *testing.T, records []core.EvidenceRecord, now time.Time) {
	t.Helper()
	for i := range records {
		if records[i].CollectedAt != now {
			t.Errorf("record[%d].CollectedAt = %v", i, records[i].CollectedAt)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("record[%d].SourceID = %q", i, records[i].SourceID)
		}
	}
}

// TestSSLRequired_SslModeOnly guards the modern Cloud SQL path: an
// instance with the legacy RequireSsl=false but an enforcing SslMode is
// fully TLS-enforced and must report ssl_required=true. Reading only
// RequireSsl would false-fail it.
func TestSSLRequired_SslModeOnly(t *testing.T) {
	cases := []struct {
		mode string
		want bool
	}{
		{"ENCRYPTED_ONLY", true},
		{"TRUSTED_CLIENT_CERTIFICATE_REQUIRED", true},
		{"ALLOW_UNENCRYPTED_AND_ENCRYPTED", false},
		{"", false},
	}
	for _, c := range cases {
		inst := &sqladmin.DatabaseInstance{Settings: &sqladmin.Settings{
			IpConfiguration: &sqladmin.IpConfiguration{RequireSsl: false, SslMode: c.mode},
		}}
		if got := ipCfgRequireSSL(inst); got != c.want {
			t.Errorf("SslMode=%q RequireSsl=false: ssl_required=%v; want %v", c.mode, got, c.want)
		}
	}
}

func assertAlphaPayload(t *testing.T, rec *core.EvidenceRecord) {
	t.Helper()
	var alpha instancePayload
	if err := json.Unmarshal(rec.Payload, &alpha); err != nil {
		t.Fatalf("Unmarshal alpha: %v", err)
	}
	if !alpha.SSLRequired {
		t.Errorf("alpha.SSLRequired = false; want true")
	}
	if alpha.SSLMode != "ENCRYPTED_ONLY" {
		t.Errorf("alpha.SSLMode = %q", alpha.SSLMode)
	}
	if !alpha.BackupEnabled {
		t.Errorf("alpha.BackupEnabled = false; want true")
	}
	if !alpha.PITREnabled {
		t.Errorf("alpha.PITREnabled = false; want true")
	}
	if alpha.AvailabilityType != "REGIONAL" {
		t.Errorf("alpha.AvailabilityType = %q", alpha.AvailabilityType)
	}
	if !alpha.DeletionProtection {
		t.Errorf("alpha.DeletionProtection = false; want true")
	}
}

func assertZetaPayload(t *testing.T, rec *core.EvidenceRecord) {
	t.Helper()
	var zeta instancePayload
	if err := json.Unmarshal(rec.Payload, &zeta); err != nil {
		t.Fatalf("Unmarshal zeta: %v", err)
	}
	if zeta.SSLRequired {
		t.Errorf("zeta.SSLRequired = true; want false")
	}
	if !zeta.PubliclyAccessible {
		t.Errorf("zeta.PubliclyAccessible = false; want true")
	}
	if zeta.BackupEnabled {
		t.Errorf("zeta.BackupEnabled = true; want false")
	}
}

func TestCollect_NoInstances(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("len(records) = %d; want 0", len(records))
	}
}

func TestCollect_NilInstancesSkipped(t *testing.T) {
	fake := &fakeAPI{instances: []*sqladmin.DatabaseInstance{nil, {Name: "a"}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("len(records) = %d; want 1", len(records))
	}
}

func TestCollect_HandlesMissingSettings(t *testing.T) {
	// An instance with nil Settings should still produce a record (with
	// zero-value config fields) — robust against partial API responses.
	fake := &fakeAPI{instances: []*sqladmin.DatabaseInstance{{Name: "bare"}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d", len(records))
	}
	var payload instancePayload
	if err := json.Unmarshal(records[0].Payload, &payload); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if payload.SSLRequired || payload.PubliclyAccessible || payload.BackupEnabled {
		t.Errorf("payload fields = %+v; want all-false", payload)
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"rds_instance"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_ListInstancesError(t *testing.T) {
	p := New(Options{API: &fakeAPI{err: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "list instances") {
		t.Errorf("want list error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsedWhenNotInjected(t *testing.T) {
	fake := &fakeAPI{instances: []*sqladmin.DatabaseInstance{{Name: "a"}}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero; want default-now-injected value")
	}
}

func TestNewFromGCP_SmokeTest(t *testing.T) {
	p, err := NewFromGCP(context.Background(), "proj-1")
	if err != nil {
		t.Logf("NewFromGCP errored (acceptable in CI without ADC): %v", err)
		return
	}
	if p.ID() != SourceID {
		t.Errorf("ID = %q", p.ID())
	}
}

func TestCollect_KISSNoDRY_EachCallReFetches(t *testing.T) {
	fake := &fakeAPI{instances: []*sqladmin.DatabaseInstance{{Name: "a"}}}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.listCount != 3 {
		t.Errorf("listCount = %d; want 3 (no caching across Collect calls per KISS-no-DRY)", fake.listCount)
	}
}
