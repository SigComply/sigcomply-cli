package securityservices

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspectortypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	macietypes "github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	securityhubtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI is a single injectable stand-in for all three service clients.
type fakeAPI struct {
	macieStatus macietypes.MacieStatus
	macieErr    error

	inspectorStatus inspectortypes.Status
	inspectorErr    error

	hubOut *securityhub.DescribeHubOutput
	hubErr error
}

func (f *fakeAPI) GetMacieSession(context.Context, *macie2.GetMacieSessionInput, ...func(*macie2.Options)) (*macie2.GetMacieSessionOutput, error) {
	if f.macieErr != nil {
		return nil, f.macieErr
	}
	return &macie2.GetMacieSessionOutput{Status: f.macieStatus}, nil
}

func (f *fakeAPI) BatchGetAccountStatus(context.Context, *inspector2.BatchGetAccountStatusInput, ...func(*inspector2.Options)) (*inspector2.BatchGetAccountStatusOutput, error) {
	if f.inspectorErr != nil {
		return nil, f.inspectorErr
	}
	return &inspector2.BatchGetAccountStatusOutput{
		Accounts: []inspectortypes.AccountState{
			{State: &inspectortypes.State{Status: f.inspectorStatus}},
		},
	}, nil
}

func (f *fakeAPI) DescribeHub(context.Context, *securityhub.DescribeHubInput, ...func(*securityhub.Options)) (*securityhub.DescribeHubOutput, error) {
	if f.hubErr != nil {
		return nil, f.hubErr
	}
	if f.hubOut != nil {
		return f.hubOut, nil
	}
	return &securityhub.DescribeHubOutput{}, nil
}

func enabledFake() *fakeAPI {
	return &fakeAPI{
		macieStatus:     macietypes.MacieStatusEnabled,
		inspectorStatus: inspectortypes.StatusEnabled,
		hubOut:          &securityhub.DescribeHubOutput{},
	}
}

func unmarshalByID(t *testing.T, records []core.EvidenceRecord) map[string]servicePayload {
	t.Helper()
	byID := map[string]servicePayload{}
	for i := range records {
		var pl servicePayload
		if err := json.Unmarshal(records[i].Payload, &pl); err != nil {
			t.Fatalf("Unmarshal %s: %v", records[i].ID, err)
		}
		byID[records[i].ID] = pl
	}
	return byID
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

func TestCollect_EmitsThreeRecordsSortedByID(t *testing.T) {
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: enabledFake(), Now: func() time.Time { return now }})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("len(records) = %d; want 3", len(records))
	}
	wantOrder := []string{idInspector, idMacie, idSecurityHub}
	for i, want := range wantOrder {
		if records[i].ID != want {
			t.Errorf("records[%d].ID = %q; want %q", i, records[i].ID, want)
		}
		if records[i].Type != EvidenceTypeID {
			t.Errorf("records[%d].Type = %q", i, records[i].Type)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("records[%d].SourceID = %q", i, records[i].SourceID)
		}
		if records[i].CollectedAt != now {
			t.Errorf("records[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
	}
}

func TestCollect_ServiceTypeLiteralsMatchPolicies(t *testing.T) {
	p := New(Options{API: enabledFake()})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	byID := unmarshalByID(t, records)
	cases := []struct {
		id          string
		serviceType string
	}{
		{idMacie, serviceTypeDLP},
		{idInspector, serviceTypeVulnerabilityScanner},
		{idSecurityHub, serviceTypeSIEM},
	}
	for _, c := range cases {
		pl, ok := byID[c.id]
		if !ok {
			t.Fatalf("missing record %q", c.id)
		}
		if pl.ServiceType != c.serviceType {
			t.Errorf("%s service_type = %q; want %q", c.id, pl.ServiceType, c.serviceType)
		}
		if pl.Provider != "aws" {
			t.Errorf("%s provider = %q; want aws", c.id, pl.Provider)
		}
		if pl.Name == "" {
			t.Errorf("%s name empty", c.id)
		}
		if !pl.IsEnabled {
			t.Errorf("%s is_enabled = false; want true", c.id)
		}
	}
}

func TestCollect_EnablementMatrix(t *testing.T) {
	notFoundMacie := &macietypes.AccessDeniedException{}
	notFoundHub := &securityhubtypes.ResourceNotFoundException{}
	invalidHub := &securityhubtypes.InvalidAccessException{}
	deniedInspector := &inspectortypes.AccessDeniedException{}

	tests := []struct {
		name string
		api  *fakeAPI
		want map[string]bool // id -> is_enabled
	}{
		{
			name: "all enabled",
			api:  enabledFake(),
			want: map[string]bool{idMacie: true, idInspector: true, idSecurityHub: true},
		},
		{
			name: "all disabled via status",
			api: &fakeAPI{
				macieStatus:     macietypes.MacieStatusPaused,
				inspectorStatus: inspectortypes.StatusDisabled,
				hubErr:          notFoundHub,
			},
			want: map[string]bool{idMacie: false, idInspector: false, idSecurityHub: false},
		},
		{
			name: "macie not-enabled sentinel (AccessDenied)",
			api: &fakeAPI{
				macieErr:        notFoundMacie,
				inspectorStatus: inspectortypes.StatusEnabled,
				hubOut:          &securityhub.DescribeHubOutput{},
			},
			want: map[string]bool{idMacie: false, idInspector: true, idSecurityHub: true},
		},
		{
			name: "inspector not-enabled sentinel (AccessDenied)",
			api: &fakeAPI{
				macieStatus:  macietypes.MacieStatusEnabled,
				inspectorErr: deniedInspector,
				hubOut:       &securityhub.DescribeHubOutput{},
			},
			want: map[string]bool{idMacie: true, idInspector: false, idSecurityHub: true},
		},
		{
			name: "securityhub invalid-access sentinel",
			api: &fakeAPI{
				macieStatus:     macietypes.MacieStatusEnabled,
				inspectorStatus: inspectortypes.StatusEnabled,
				hubErr:          invalidHub,
			},
			want: map[string]bool{idMacie: true, idInspector: true, idSecurityHub: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(Options{API: tt.api})
			records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}
			byID := unmarshalByID(t, records)
			for id, want := range tt.want {
				if byID[id].IsEnabled != want {
					t.Errorf("%s is_enabled = %v; want %v", id, byID[id].IsEnabled, want)
				}
			}
		})
	}
}

func TestCollect_PropagatesHardErrors(t *testing.T) {
	boom := errors.New("kaboom")
	tests := []struct {
		name    string
		api     *fakeAPI
		wantSub string
	}{
		{
			name:    "macie hard error",
			api:     &fakeAPI{macieErr: boom},
			wantSub: "macie status",
		},
		{
			name:    "inspector hard error",
			api:     &fakeAPI{macieStatus: macietypes.MacieStatusEnabled, inspectorErr: boom},
			wantSub: "inspector status",
		},
		{
			name: "securityhub hard error",
			api: &fakeAPI{
				macieStatus:     macietypes.MacieStatusEnabled,
				inspectorStatus: inspectortypes.StatusEnabled,
				hubErr:          boom,
			},
			wantSub: "securityhub status",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(Options{API: tt.api})
			_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
			if err == nil || !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("want error containing %q; got %v", tt.wantSub, err)
			}
		})
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: enabledFake()})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"directory_user"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want reject error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	p := New(Options{API: enabledFake()})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero")
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
