package lambda

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awslambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

type fakeAPI struct {
	// pages is returned one page per ListFunctions call; the last page must
	// have an empty NextMarker to terminate paging.
	pages []awslambda.ListFunctionsOutput
	err   error

	count int
}

func (f *fakeAPI) ListFunctions(_ context.Context, _ *awslambda.ListFunctionsInput, _ ...func(*awslambda.Options)) (*awslambda.ListFunctionsOutput, error) {
	if f.err != nil {
		f.count++
		return nil, f.err
	}
	idx := f.count
	f.count++
	if idx >= len(f.pages) {
		return &awslambda.ListFunctionsOutput{}, nil
	}
	page := f.pages[idx]
	return &page, nil
}

func ptr[T any](v T) *T { return &v }

func onePage(fns ...lambdatypes.FunctionConfiguration) []awslambda.ListFunctionsOutput {
	return []awslambda.ListFunctionsOutput{{Functions: fns}}
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

func TestCollect_HappyPath_SortsByIDAndMapsFields(t *testing.T) {
	fake := &fakeAPI{pages: onePage(
		lambdatypes.FunctionConfiguration{
			FunctionName: ptr("zeta"),
			Runtime:      lambdatypes.RuntimePython311,
		},
		lambdatypes.FunctionConfiguration{
			FunctionName:  ptr("alpha"),
			Runtime:       lambdatypes.RuntimeNodejs18x,
			VpcConfig:     &lambdatypes.VpcConfigResponse{SubnetIds: []string{"subnet-1"}},
			TracingConfig: &lambdatypes.TracingConfigResponse{Mode: lambdatypes.TracingModeActive},
			KMSKeyArn:     ptr("arn:aws:kms:::key/abc"),
		},
	)}
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

	var alpha functionPayload
	if err := json.Unmarshal(records[0].Payload, &alpha); err != nil {
		t.Fatalf("Unmarshal alpha: %v", err)
	}
	cases := []struct {
		name string
		got  any
		want any
	}{
		{"provider", alpha.Provider, "aws"},
		{"name", alpha.Name, "alpha"},
		{"runtime", alpha.Runtime, "nodejs18.x"},
		{"is_in_vpc", alpha.IsInVPC, true},
		{"tracing_enabled", alpha.TracingEnabled, true},
		{"env_encrypted", alpha.EnvironmentVariablesEncrypted, true},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("alpha.%s = %v; want %v", c.name, c.got, c.want)
		}
	}

	var zeta functionPayload
	if err := json.Unmarshal(records[1].Payload, &zeta); err != nil {
		t.Fatalf("Unmarshal zeta: %v", err)
	}
	zCases := []struct {
		name string
		got  bool
	}{
		{"is_in_vpc", zeta.IsInVPC},
		{"tracing_enabled", zeta.TracingEnabled},
		{"env_encrypted", zeta.EnvironmentVariablesEncrypted},
	}
	for _, c := range zCases {
		if c.got {
			t.Errorf("zeta.%s = true; want false", c.name)
		}
	}
	if zeta.Runtime != "python3.11" {
		t.Errorf("zeta.Runtime = %q; want python3.11", zeta.Runtime)
	}

	assertRecordInvariants(t, records, now)
}

// assertRecordInvariants checks the per-record envelope fields shared by
// every emitted record.
func assertRecordInvariants(t *testing.T, records []core.EvidenceRecord, now time.Time) {
	t.Helper()
	for i := range records {
		if records[i].CollectedAt != now {
			t.Errorf("record[%d].CollectedAt = %v; want %v", i, records[i].CollectedAt, now)
		}
		if records[i].SourceID != SourceID {
			t.Errorf("record[%d].SourceID = %q", i, records[i].SourceID)
		}
		if records[i].Type != EvidenceTypeID {
			t.Errorf("record[%d].Type = %q", i, records[i].Type)
		}
	}
}

func TestCollect_EmitsEveryPolicyReadFieldOnEveryRecord(t *testing.T) {
	fake := &fakeAPI{pages: onePage(
		lambdatypes.FunctionConfiguration{FunctionName: ptr("bare")},
	)}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(records[0].Payload, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{"id", "name", "provider", "runtime", "is_in_vpc", "tracing_enabled", "environment_variables_encrypted"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("payload missing required field %q", key)
		}
	}
	// reserved_concurrency_set is intentionally not emitted.
	if _, ok := raw["reserved_concurrency_set"]; ok {
		t.Errorf("payload should NOT emit reserved_concurrency_set")
	}
}

func TestCollect_VPCWithoutSubnetsIsNotInVPC(t *testing.T) {
	fake := &fakeAPI{pages: onePage(
		lambdatypes.FunctionConfiguration{
			FunctionName: ptr("fn"),
			VpcConfig:    &lambdatypes.VpcConfigResponse{SubnetIds: nil},
		},
	)}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var pl functionPayload
	if err := json.Unmarshal(records[0].Payload, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pl.IsInVPC {
		t.Errorf("is_in_vpc = true; want false for empty subnets")
	}
}

func TestCollect_TracingPassThroughIsNotEnabled(t *testing.T) {
	fake := &fakeAPI{pages: onePage(
		lambdatypes.FunctionConfiguration{
			FunctionName:  ptr("fn"),
			TracingConfig: &lambdatypes.TracingConfigResponse{Mode: lambdatypes.TracingModePassThrough},
		},
	)}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var pl functionPayload
	if err := json.Unmarshal(records[0].Payload, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pl.TracingEnabled {
		t.Errorf("tracing_enabled = true; want false for PassThrough")
	}
}

func TestCollect_Paginates(t *testing.T) {
	fake := &fakeAPI{pages: []awslambda.ListFunctionsOutput{
		{Functions: []lambdatypes.FunctionConfiguration{{FunctionName: ptr("a")}}, NextMarker: ptr("m1")},
		{Functions: []lambdatypes.FunctionConfiguration{{FunctionName: ptr("b")}}},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("len(records) = %d; want 2", len(records))
	}
	if fake.count != 2 {
		t.Errorf("ListFunctions calls = %d; want 2", fake.count)
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
	if err == nil || !strings.Contains(err.Error(), "list functions") {
		t.Errorf("want list error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	fake := &fakeAPI{pages: onePage(lambdatypes.FunctionConfiguration{FunctionName: ptr("a")})}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero")
	}
}

func TestCollect_SkipsFunctionWithEmptyID(t *testing.T) {
	fake := &fakeAPI{pages: onePage(
		lambdatypes.FunctionConfiguration{},
		lambdatypes.FunctionConfiguration{FunctionName: ptr("ok")},
	)}
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
	fake := &fakeAPI{pages: onePage(lambdatypes.FunctionConfiguration{FunctionName: ptr("a")})}
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
