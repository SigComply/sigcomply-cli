package inspector

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	inspector2 "github.com/aws/aws-sdk-go-v2/service/inspector2"
	inspector2types "github.com/aws/aws-sdk-go-v2/service/inspector2/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// fakeAPI returns a fixed set of findings, optionally split across pages via
// pageTokens to exercise NextToken pagination.
type fakeAPI struct {
	findings []inspector2types.Finding
	err      error

	// pages, when non-nil, overrides findings: each page is returned in
	// sequence, with a NextToken set on every page but the last.
	pages [][]inspector2types.Finding

	count int
}

func (f *fakeAPI) ListFindings(_ context.Context, in *inspector2.ListFindingsInput, _ ...func(*inspector2.Options)) (*inspector2.ListFindingsOutput, error) {
	f.count++
	if f.err != nil {
		return nil, f.err
	}
	if f.pages == nil {
		return &inspector2.ListFindingsOutput{Findings: f.findings}, nil
	}
	idx := 0
	if in.NextToken != nil && *in.NextToken != "" {
		idx = int((*in.NextToken)[0] - '0')
	}
	out := &inspector2.ListFindingsOutput{Findings: f.pages[idx]}
	if idx < len(f.pages)-1 {
		out.NextToken = ptr(string(rune('0' + idx + 1)))
	}
	return out, nil
}

func ptr[T any](v T) *T { return &v }

// finding builds a minimal Finding with the most-commonly-asserted fields.
func finding(arn, sev string, status inspector2types.FindingStatus) inspector2types.Finding {
	return inspector2types.Finding{
		FindingArn: ptr(arn),
		Severity:   inspector2types.Severity(sev),
		Status:     status,
		Resources:  []inspector2types.Resource{{Id: ptr("res-" + arn), Type: inspector2types.ResourceTypeAwsEc2Instance}},
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

// decodePayloads unmarshals every record's payload, keyed by record ID.
func decodePayloads(t *testing.T, records []core.EvidenceRecord) map[string]findingPayload {
	t.Helper()
	out := make(map[string]findingPayload, len(records))
	for _, r := range records {
		var pl findingPayload
		if err := json.Unmarshal(r.Payload, &pl); err != nil {
			t.Fatalf("Unmarshal %s: %v", r.ID, err)
		}
		out[r.ID] = pl
	}
	return out
}

func TestCollect_HappyPath_SortsByIDAndMapsFields(t *testing.T) {
	score := 9.8
	fake := &fakeAPI{
		findings: []inspector2types.Finding{
			{
				FindingArn: ptr("arn:z"),
				Title:      ptr("Zeta vuln"),
				Severity:   inspector2types.SeverityHigh,
				Status:     inspector2types.FindingStatusActive,
				Resources:  []inspector2types.Resource{{Id: ptr("i-zzz"), Type: inspector2types.ResourceTypeAwsEc2Instance}},
				PackageVulnerabilityDetails: &inspector2types.PackageVulnerabilityDetails{
					VulnerabilityId: ptr("CVE-2026-0001"),
				},
				InspectorScore: &score,
				Remediation: &inspector2types.Remediation{
					Recommendation: &inspector2types.Recommendation{Text: ptr("Update the package")},
				},
			},
			{
				FindingArn: ptr("arn:a"),
				Severity:   inspector2types.SeverityCritical,
				Status:     inspector2types.FindingStatusClosed,
				Resources:  []inspector2types.Resource{{Id: ptr("i-aaa"), Type: inspector2types.ResourceTypeAwsEcrContainerImage}},
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
	if records[0].ID != "arn:a" || records[1].ID != "arn:z" {
		t.Fatalf("records not sorted by ID: got %v", []string{records[0].ID, records[1].ID})
	}

	want := map[string]findingPayload{
		"arn:a": {ID: "arn:a", ResourceID: "i-aaa", ResourceType: "AWS_ECR_CONTAINER_IMAGE", Severity: severityCritical, Status: statusResolved, RemediationAvailable: false, Provider: "aws"},
		"arn:z": {ID: "arn:z", ResourceID: "i-zzz", ResourceType: "AWS_EC2_INSTANCE", Title: "Zeta vuln", Severity: severityHigh, Status: statusActive, CVEID: "CVE-2026-0001", Score: &score, RemediationAvailable: true, Provider: "aws"},
	}
	got := decodePayloads(t, records)
	for id, w := range want {
		if g := got[id]; !reflect.DeepEqual(g, w) {
			t.Errorf("%s payload = %+v; want %+v", id, g, w)
		}
	}

	for i := range records {
		assertEnvelope(t, &records[i], now)
	}
}

// assertEnvelope verifies the record-level metadata (timestamp/source/type).
func assertEnvelope(t *testing.T, r *core.EvidenceRecord, now time.Time) {
	t.Helper()
	if r.CollectedAt != now {
		t.Errorf("%s CollectedAt = %v; want %v", r.ID, r.CollectedAt, now)
	}
	if r.SourceID != SourceID || r.Type != EvidenceTypeID {
		t.Errorf("%s SourceID/Type = %q/%q", r.ID, r.SourceID, r.Type)
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := []struct {
		in   inspector2types.Severity
		want string
	}{
		{inspector2types.SeverityCritical, severityCritical},
		{inspector2types.SeverityHigh, severityHigh},
		{inspector2types.SeverityMedium, severityMedium},
		{inspector2types.SeverityLow, severityLow},
		{inspector2types.SeverityInformational, severityInformational},
		{inspector2types.SeverityUntriaged, severityInformational},
		{inspector2types.Severity("BOGUS"), severityInformational},
	}
	for _, c := range cases {
		if got := normalizeSeverity(c.in); got != c.want {
			t.Errorf("normalizeSeverity(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeStatus(t *testing.T) {
	cases := []struct {
		in   inspector2types.FindingStatus
		want string
	}{
		{inspector2types.FindingStatusActive, statusActive},
		{inspector2types.FindingStatusSuppressed, statusSuppressed},
		{inspector2types.FindingStatusClosed, statusResolved},
		{inspector2types.FindingStatus("BOGUS"), statusActive},
	}
	for _, c := range cases {
		if got := normalizeStatus(c.in); got != c.want {
			t.Errorf("normalizeStatus(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

// TestCollect_EnumValuesMatchSchema asserts every emitted severity/status lands
// in the schema's enum vocabulary (the literals consuming policies match on).
func TestCollect_EnumValuesMatchSchema(t *testing.T) {
	validSeverity := map[string]bool{
		severityCritical: true, severityHigh: true, severityMedium: true,
		severityLow: true, severityInformational: true,
	}
	validStatus := map[string]bool{
		statusActive: true, statusSuppressed: true, statusResolved: true,
	}
	fake := &fakeAPI{findings: []inspector2types.Finding{
		finding("arn:1", "CRITICAL", inspector2types.FindingStatusActive),
		finding("arn:2", "UNTRIAGED", inspector2types.FindingStatusClosed),
		finding("arn:3", "MEDIUM", inspector2types.FindingStatusSuppressed),
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	for _, r := range records {
		var pl findingPayload
		if err := json.Unmarshal(r.Payload, &pl); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if !validSeverity[pl.Severity] {
			t.Errorf("%s severity %q not in schema enum", r.ID, pl.Severity)
		}
		if !validStatus[pl.Status] {
			t.Errorf("%s status %q not in schema enum", r.ID, pl.Status)
		}
	}
}

func TestCollect_OmitsOptionalFieldsWhenAbsent(t *testing.T) {
	fake := &fakeAPI{findings: []inspector2types.Finding{
		finding("arn:1", "LOW", inspector2types.FindingStatusActive),
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(records[0].Payload, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, k := range []string{"cve_id", "score", "title"} {
		if _, present := raw[k]; present {
			t.Errorf("expected %q omitted, got present", k)
		}
	}
	for _, k := range []string{"id", "resource_id", "resource_type", "severity", "status"} {
		if _, present := raw[k]; !present {
			t.Errorf("required field %q missing", k)
		}
	}
}

func TestCollect_Paginates(t *testing.T) {
	fake := &fakeAPI{pages: [][]inspector2types.Finding{
		{finding("arn:1", "LOW", inspector2types.FindingStatusActive)},
		{finding("arn:2", "HIGH", inspector2types.FindingStatusActive)},
		{finding("arn:3", "MEDIUM", inspector2types.FindingStatusActive)},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("len(records) = %d; want 3", len(records))
	}
	if fake.count != 3 {
		t.Errorf("ListFindings calls = %d; want 3", fake.count)
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"directory_user"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_ListError(t *testing.T) {
	p := New(Options{API: &fakeAPI{err: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "list findings") {
		t.Errorf("want list error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	fake := &fakeAPI{findings: []inspector2types.Finding{finding("arn:1", "LOW", inspector2types.FindingStatusActive)}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero")
	}
}

func TestCollect_SkipsFindingWithEmptyARN(t *testing.T) {
	fake := &fakeAPI{findings: []inspector2types.Finding{
		{Severity: inspector2types.SeverityLow, Status: inspector2types.FindingStatusActive},
		finding("arn:ok", "LOW", inspector2types.FindingStatusActive),
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].ID != "arn:ok" {
		t.Errorf("records = %v", records)
	}
}

func TestCollect_NoResourcesYieldsEmptyResourceFields(t *testing.T) {
	fake := &fakeAPI{findings: []inspector2types.Finding{
		{FindingArn: ptr("arn:1"), Severity: inspector2types.SeverityLow, Status: inspector2types.FindingStatusActive},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var pl findingPayload
	if err := json.Unmarshal(records[0].Payload, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pl.ResourceID != "" || pl.ResourceType != "" {
		t.Errorf("resource fields = %q/%q; want empty", pl.ResourceID, pl.ResourceType)
	}
}

func TestSafeString_NilSafe(t *testing.T) {
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
