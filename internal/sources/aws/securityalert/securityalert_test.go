package securityalert

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	cw "github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	cwl "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

func ptr[T any](v T) *T { return &v }

// fakeAPI drives the plugin without real AWS calls.
type fakeAPI struct {
	filters     []cwltypes.MetricFilter
	alarms      []cwtypes.MetricAlarm
	filtersErr  error
	alarmsErr   error
	filterCalls int
	alarmCalls  int
}

func (f *fakeAPI) DescribeMetricFilters(_ context.Context, _ *cwl.DescribeMetricFiltersInput, _ ...func(*cwl.Options)) (*cwl.DescribeMetricFiltersOutput, error) {
	f.filterCalls++
	if f.filtersErr != nil {
		return nil, f.filtersErr
	}
	return &cwl.DescribeMetricFiltersOutput{MetricFilters: f.filters}, nil
}

func (f *fakeAPI) DescribeAlarms(_ context.Context, _ *cw.DescribeAlarmsInput, _ ...func(*cw.Options)) (*cw.DescribeAlarmsOutput, error) {
	f.alarmCalls++
	if f.alarmsErr != nil {
		return nil, f.alarmsErr
	}
	return &cw.DescribeAlarmsOutput{MetricAlarms: f.alarms}, nil
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    string
	}{
		{"unauthorized", "{ ($.errorCode = \"*UnauthorizedOperation\") }", classUnauthorizedAPICalls},
		{"root by name", "{ $.userIdentity.RootAccountUsage = \"Root\" }", classRootAccountUsage},
		{"root by type field", "{ $.userIdentity.type = \"Root\" }", classRootAccountUsage},
		{"iam put group", "{ ($.eventName = PutGroupPolicy) }", classIAMPolicyChanges},
		{"iam attach user", "{ ($.eventName = AttachUserPolicy) }", classIAMPolicyChanges},
		{"trail stop", "{ ($.eventName = StopLogging) }", classCloudTrailConfigChanges},
		{"trail delete", "{ ($.eventName = DeleteTrail) }", classCloudTrailConfigChanges},
		{"console no mfa", "{ ($.eventName = ConsoleLogin) && ($.additionalEventData.MFAUsed != Yes) }", classConsoleLoginNoMFA},
		{"console login only is not no-mfa", "{ ($.eventName = ConsoleLogin) }", classOther},
		{"sg create", "{ ($.eventName = CreateSecurityGroup) }", classSecurityGroupChanges},
		{"sg authorize", "{ ($.eventName = AuthorizeSecurityGroupIngress) }", classSecurityGroupChanges},
		{"vpc modify", "{ ($.eventName = ModifyVpcAttribute) }", classVPCChanges},
		{"kms disable", "{ ($.eventName = DisableKey) }", classKMSKeyDeletion},
		{"kms schedule deletion", "{ ($.eventName = ScheduleKeyDeletion) }", classKMSKeyDeletion},
		{"unrecognized", "{ ($.eventName = SomethingElse) }", classOther},
		{"empty", "", classOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classify(tt.pattern); got != tt.want {
				t.Errorf("classify(%q) = %q; want %q", tt.pattern, got, tt.want)
			}
		})
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

func TestCollect_HappyPath(t *testing.T) {
	fake := &fakeAPI{
		filters: []cwltypes.MetricFilter{
			{
				FilterName:            ptr("root-usage"),
				FilterPattern:         ptr("{ $.userIdentity.type = \"Root\" }"),
				MetricTransformations: []cwltypes.MetricTransformation{{MetricName: ptr("RootUsageMetric")}},
			},
			{
				FilterName:            ptr("unauthorized"),
				FilterPattern:         ptr("{ ($.errorCode = \"*UnauthorizedOperation\") }"),
				MetricTransformations: []cwltypes.MetricTransformation{{MetricName: ptr("UnauthorizedMetric")}},
			},
			{
				// recognized class but no alarm wired -> is_enabled false
				FilterName:            ptr("iam-changes"),
				FilterPattern:         ptr("{ ($.eventName = PutGroupPolicy) }"),
				MetricTransformations: []cwltypes.MetricTransformation{{MetricName: ptr("IAMMetric")}},
			},
			{
				// "other" class -> skipped entirely
				FilterName:            ptr("noise"),
				FilterPattern:         ptr("{ ($.eventName = DescribeInstances) }"),
				MetricTransformations: []cwltypes.MetricTransformation{{MetricName: ptr("NoiseMetric")}},
			},
		},
		alarms: []cwtypes.MetricAlarm{
			{
				AlarmName:    ptr("root-alarm"),
				MetricName:   ptr("RootUsageMetric"),
				AlarmActions: []string{"arn:aws:sns:us-east-1:1:secops"},
				StateValue:   cwtypes.StateValueOk,
			},
			{
				// alarm exists but has NO notification target
				AlarmName:  ptr("unauth-alarm"),
				MetricName: ptr("UnauthorizedMetric"),
			},
		},
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	p := New(Options{API: fake, Now: func() time.Time { return now }})

	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("len(records) = %d; want 3 (other class skipped)", len(records))
	}
	assertSortedByID(t, records)
	assertRecordMetadata(t, records, now)

	byClass := decodeByClass(t, records)

	root := byClass[classRootAccountUsage]
	if !root.IsEnabled || !root.HasNotificationTarget {
		t.Errorf("root: want enabled+notify; got %+v", root)
	}
	if root.ID != classRootAccountUsage+":root-usage" || root.Provider != providerAWS {
		t.Errorf("root id/provider wrong: %+v", root)
	}

	unauth := byClass[classUnauthorizedAPICalls]
	if !unauth.IsEnabled || unauth.HasNotificationTarget {
		t.Errorf("unauth: want enabled but no notify target; got %+v", unauth)
	}

	iam := byClass[classIAMPolicyChanges]
	if iam.IsEnabled || iam.HasNotificationTarget {
		t.Errorf("iam: want disabled (no alarm wired); got %+v", iam)
	}
}

func assertSortedByID(t *testing.T, records []core.EvidenceRecord) {
	t.Helper()
	for i := 1; i < len(records); i++ {
		if records[i-1].ID > records[i].ID {
			t.Errorf("records not sorted by ID: %q before %q", records[i-1].ID, records[i].ID)
		}
	}
}

func assertRecordMetadata(t *testing.T, records []core.EvidenceRecord, now time.Time) {
	t.Helper()
	for i := range records {
		if records[i].Type != EvidenceTypeID {
			t.Errorf("record[%d].Type = %q", i, records[i].Type)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("record[%d].SourceID = %q", i, records[i].SourceID)
		}
		if records[i].CollectedAt != now {
			t.Errorf("record[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
	}
}

func decodeByClass(t *testing.T, records []core.EvidenceRecord) map[string]securityAlertPayload {
	t.Helper()
	out := map[string]securityAlertPayload{}
	for i := range records {
		var pl securityAlertPayload
		if err := json.Unmarshal(records[i].Payload, &pl); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		out[pl.EventClass] = pl
	}
	return out
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"s3_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_MetricFiltersError(t *testing.T) {
	p := New(Options{API: &fakeAPI{filtersErr: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "describe metric filters") {
		t.Errorf("want describe metric filters error; got %v", err)
	}
}

func TestCollect_AlarmsError(t *testing.T) {
	p := New(Options{API: &fakeAPI{alarmsErr: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "describe alarms") {
		t.Errorf("want describe alarms error; got %v", err)
	}
}

func TestCollect_NoFilters(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("len(records) = %d; want 0", len(records))
	}
}

func TestCollect_DefaultNowInjected(t *testing.T) {
	fake := &fakeAPI{
		filters: []cwltypes.MetricFilter{{
			FilterName:    ptr("x"),
			FilterPattern: ptr("{ $.userIdentity.type = \"Root\" }"),
		}},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].CollectedAt.IsZero() {
		t.Errorf("default-now not injected: %+v", records)
	}
}

func TestSafeStr_NilSafe(t *testing.T) {
	if safeStr(nil) != "" {
		t.Errorf("nil string not empty")
	}
	if safeStr(ptr("v")) != "v" {
		t.Errorf("safeStr deref failed")
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
