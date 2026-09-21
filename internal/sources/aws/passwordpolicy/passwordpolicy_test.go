package passwordpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	awsiam "github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

type fakeAPI struct {
	out *awsiam.GetAccountPasswordPolicyOutput
	err error

	count int
}

func (f *fakeAPI) GetAccountPasswordPolicy(_ context.Context, _ *awsiam.GetAccountPasswordPolicyInput, _ ...func(*awsiam.Options)) (*awsiam.GetAccountPasswordPolicyOutput, error) {
	f.count++
	if f.err != nil {
		return nil, f.err
	}
	return f.out, nil
}

func ptr[T any](v T) *T { return &v }

func det() func() time.Time {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return now }
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
	fake := &fakeAPI{out: &awsiam.GetAccountPasswordPolicyOutput{
		PasswordPolicy: &iamtypes.PasswordPolicy{
			MinimumPasswordLength:      ptr(int32(14)),
			MaxPasswordAge:             ptr(int32(90)),
			PasswordReusePrevention:    ptr(int32(24)),
			RequireUppercaseCharacters: true,
			RequireLowercaseCharacters: true,
			RequireNumbers:             true,
			RequireSymbols:             true,
		},
	}}
	now := det()
	p := New(Options{API: fake, Now: now})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d; want 1 (singleton)", len(records))
	}
	r := records[0]
	meta := []struct {
		name      string
		got, want any
	}{
		{"ID", r.ID, singletonID},
		{"Type", r.Type, EvidenceTypeID},
		{"SourceID", r.SourceID, SourceID},
		{"CollectedAt", r.CollectedAt, now()},
	}
	for _, c := range meta {
		if c.got != c.want {
			t.Errorf("record.%s = %v; want %v", c.name, c.got, c.want)
		}
	}
	var pl passwordPolicyPayload
	if err := json.Unmarshal(r.Payload, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	assertHappyPayload(t, &pl)
	// mfa_required must be omitted entirely for AWS.
	var raw map[string]any
	if err := json.Unmarshal(r.Payload, &raw); err != nil {
		t.Fatalf("Unmarshal raw: %v", err)
	}
	if _, present := raw["mfa_required"]; present {
		t.Errorf("mfa_required should be omitted for AWS")
	}
}

// assertHappyPayload checks the decoded payload for TestCollect_HappyPath.
func assertHappyPayload(t *testing.T, pl *passwordPolicyPayload) {
	t.Helper()
	if pl.Provider != "aws" {
		t.Errorf("provider = %q; want aws", pl.Provider)
	}
	// An IAM password policy governs every user in the account and has no
	// sibling to be ranked against, so the scope pair is fixed.
	if pl.Scope != scopeAccount || pl.Precedence != 1 {
		t.Errorf("scope/precedence = %q/%d; want %q/1", pl.Scope, pl.Precedence, scopeAccount)
	}
	if pl.MinLength != 14 || pl.MaxAgeDays != 90 || pl.ReusePreventionCount != 24 {
		t.Errorf("ints = %d/%d/%d; want 14/90/24", pl.MinLength, pl.MaxAgeDays, pl.ReusePreventionCount)
	}
	// The canonical reuse answer is derived from the depth IAM discloses,
	// so both travel together.
	if !pl.ReusePrevented {
		t.Errorf("reuse_prevented = false at depth %d; want true", pl.ReusePreventionCount)
	}
	if pl.ComplexityModel != complexityPerClass {
		t.Errorf("complexity_model = %q; want %q — IAM states complexity as character classes", pl.ComplexityModel, complexityPerClass)
	}
	if !classRequired(pl.RequiresUppercase) || !classRequired(pl.RequiresLowercase) ||
		!classRequired(pl.RequiresNumbers) || !classRequired(pl.RequiresSymbols) {
		t.Errorf("char-class flags not all true: %+v", pl)
	}
}

// classRequired reads an optional character-class flag. Absent is not a
// requirement.
func classRequired(v *bool) bool { return v != nil && *v }

func TestCollect_NilPointersBecomeZero(t *testing.T) {
	// MaxPasswordAge / PasswordReusePrevention absent => nil => 0.
	fake := &fakeAPI{out: &awsiam.GetAccountPasswordPolicyOutput{
		PasswordPolicy: &iamtypes.PasswordPolicy{
			MinimumPasswordLength: ptr(int32(8)),
		},
	}}
	p := New(Options{API: fake, Now: det()})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var pl passwordPolicyPayload
	if err := json.Unmarshal(records[0].Payload, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pl.MinLength != 8 || pl.MaxAgeDays != 0 || pl.ReusePreventionCount != 0 {
		t.Errorf("ints = %d/%d/%d; want 8/0/0", pl.MinLength, pl.MaxAgeDays, pl.ReusePreventionCount)
	}
	// A policy exists and keeps no history: reuse is genuinely not
	// prevented, which is a read rather than an omission.
	if pl.ReusePrevented {
		t.Errorf("reuse_prevented = true at depth 0; want false")
	}
}

func TestCollect_NoSuchEntity_WeakestPosture(t *testing.T) {
	fake := &fakeAPI{err: &iamtypes.NoSuchEntityException{}}
	p := New(Options{API: fake, Now: det()})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: unexpected error for missing policy: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("len(records) = %d; want 1", len(records))
	}
	var pl passwordPolicyPayload
	if err := json.Unmarshal(records[0].Payload, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pl.ID != singletonID || pl.Provider != "aws" {
		t.Errorf("id/provider = %q/%q", pl.ID, pl.Provider)
	}
	if pl.MinLength != 0 || pl.MaxAgeDays != 0 || pl.ReusePreventionCount != 0 {
		t.Errorf("ints not all zero: %d/%d/%d", pl.MinLength, pl.MaxAgeDays, pl.ReusePreventionCount)
	}
	// No policy at all is an observed absence of any strength requirement
	// — complexity_model "none", not a per-class answer of four noes that
	// nobody gave. The four booleans are omitted for exactly that reason.
	if pl.ComplexityModel != complexityNone {
		t.Errorf("complexity_model = %q; want %q", pl.ComplexityModel, complexityNone)
	}
	if pl.RequiresUppercase != nil || pl.RequiresLowercase != nil || pl.RequiresNumbers != nil || pl.RequiresSymbols != nil {
		t.Errorf("char-class flags present under complexity_model %q: %+v", complexityNone, pl)
	}
}

func TestCollect_NoSuchEntity_Wrapped(t *testing.T) {
	// errors.As must see the NoSuchEntityException even when wrapped — the
	// real SDK returns it inside an *smithy.OperationError chain.
	fake := &fakeAPI{err: fmt.Errorf("operation error IAM: %w", &iamtypes.NoSuchEntityException{})}
	p := New(Options{API: fake, Now: det()})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("wrapped NoSuchEntity should be treated as no-policy, got: %v", err)
	}
	var pl passwordPolicyPayload
	if err := json.Unmarshal(records[0].Payload, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pl.MinLength != 0 || pl.ComplexityModel != complexityNone {
		t.Errorf("wrapped NoSuchEntity not mapped to weakest posture: %+v", pl)
	}
}

func TestCollect_OtherErrorPropagates(t *testing.T) {
	p := New(Options{API: &fakeAPI{err: errors.New("kaboom")}, Now: det()})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "get account password policy") {
		t.Errorf("want propagated error; got %v", err)
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"directory_user"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	fake := &fakeAPI{err: &iamtypes.NoSuchEntityException{}}
	p := New(Options{API: fake})
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
