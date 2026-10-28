package kms

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// keySym is the rotatable key in the rotation-support test.
const keySym = "sym"

// keyAAA is the KMS key ID shared by this file's fixtures.
const keyAAA = "aaa-key"

type fakeAPI struct {
	keys     []kmstypes.KeyListEntry
	metadata map[string]*kmstypes.KeyMetadata
	rotation map[string]bool
	listErr  error
	descErr  map[string]error
	rotErr   map[string]error

	listCount int
	descCount int
	rotCount  int
}

func (f *fakeAPI) ListKeys(_ context.Context, _ *awskms.ListKeysInput, _ ...func(*awskms.Options)) (*awskms.ListKeysOutput, error) {
	f.listCount++
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &awskms.ListKeysOutput{Keys: f.keys}, nil
}

func (f *fakeAPI) DescribeKey(_ context.Context, in *awskms.DescribeKeyInput, _ ...func(*awskms.Options)) (*awskms.DescribeKeyOutput, error) {
	f.descCount++
	if in.KeyId == nil {
		return &awskms.DescribeKeyOutput{}, nil
	}
	if err, ok := f.descErr[*in.KeyId]; ok {
		return nil, err
	}
	return &awskms.DescribeKeyOutput{KeyMetadata: f.metadata[*in.KeyId]}, nil
}

func (f *fakeAPI) GetKeyRotationStatus(_ context.Context, in *awskms.GetKeyRotationStatusInput, _ ...func(*awskms.Options)) (*awskms.GetKeyRotationStatusOutput, error) {
	f.rotCount++
	if in.KeyId == nil {
		return &awskms.GetKeyRotationStatusOutput{}, nil
	}
	if err, ok := f.rotErr[*in.KeyId]; ok {
		return nil, err
	}
	return &awskms.GetKeyRotationStatusOutput{KeyRotationEnabled: f.rotation[*in.KeyId]}, nil
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

func TestCollect_HappyPath_SortsByID(t *testing.T) {
	fake := &fakeAPI{
		keys: []kmstypes.KeyListEntry{
			{KeyId: ptr("zzz-key")},
			{KeyId: ptr(keyAAA)},
		},
		metadata: map[string]*kmstypes.KeyMetadata{
			keyAAA:    {KeyId: ptr(keyAAA), Arn: ptr("arn:a"), KeyManager: kmstypes.KeyManagerTypeCustomer, Enabled: true},
			"zzz-key": {KeyId: ptr("zzz-key"), Arn: ptr("arn:z"), KeyManager: kmstypes.KeyManagerTypeAws, Enabled: true},
		},
		rotation: map[string]bool{keyAAA: true},
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
	if records[0].ID != keyAAA || records[1].ID != "zzz-key" {
		t.Errorf("records not sorted by ID: got %v", []string{records[0].ID, records[1].ID})
	}
	var aaa keyPayload
	if err := json.Unmarshal(records[0].Payload, &aaa); err != nil {
		t.Fatalf("Unmarshal aaa: %v", err)
	}
	if !aaa.IsCustomerManaged {
		t.Errorf("aaa.IsCustomerManaged = false; want true")
	}
	if !aaa.RotationEnabled {
		t.Errorf("aaa.RotationEnabled = false; want true")
	}
	var zzz keyPayload
	if err := json.Unmarshal(records[1].Payload, &zzz); err != nil {
		t.Fatalf("Unmarshal zzz: %v", err)
	}
	if zzz.IsCustomerManaged {
		t.Errorf("zzz.IsCustomerManaged = true; want false (AWS-managed)")
	}
	// AWS-managed keys do not call GetKeyRotationStatus.
	if fake.rotCount != 1 {
		t.Errorf("rotCount = %d; want 1 (only customer-managed key)", fake.rotCount)
	}
}

func TestCollect_CustomerManagedRotationOff(t *testing.T) {
	fake := &fakeAPI{
		keys: []kmstypes.KeyListEntry{{KeyId: ptr("k1")}},
		metadata: map[string]*kmstypes.KeyMetadata{
			"k1": {KeyId: ptr("k1"), KeyManager: kmstypes.KeyManagerTypeCustomer},
		},
		rotation: map[string]bool{"k1": false},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var pl keyPayload
	if err := json.Unmarshal(records[0].Payload, &pl); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if pl.RotationEnabled {
		t.Errorf("RotationEnabled = true; want false")
	}
}

func TestCollect_ListError(t *testing.T) {
	p := New(Options{API: &fakeAPI{listErr: errors.New("kaboom")}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "list keys") {
		t.Errorf("want list error; got %v", err)
	}
}

func TestCollect_DescribeError(t *testing.T) {
	fake := &fakeAPI{
		keys:    []kmstypes.KeyListEntry{{KeyId: ptr("k1")}},
		descErr: map[string]error{"k1": errors.New("denied")},
	}
	p := New(Options{API: fake})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "describe key k1") {
		t.Errorf("want describe error; got %v", err)
	}
}

func TestCollect_RotationError(t *testing.T) {
	fake := &fakeAPI{
		keys: []kmstypes.KeyListEntry{{KeyId: ptr("k1")}},
		metadata: map[string]*kmstypes.KeyMetadata{
			"k1": {KeyId: ptr("k1"), KeyManager: kmstypes.KeyManagerTypeCustomer},
		},
		rotErr: map[string]error{"k1": errors.New("denied")},
	}
	p := New(Options{API: fake})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err == nil || !strings.Contains(err.Error(), "rotation status for k1") {
		t.Errorf("want rotation error; got %v", err)
	}
}

func TestCollect_RejectsWrongEvidenceType(t *testing.T) {
	p := New(Options{API: &fakeAPI{}})
	_, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{"s3_bucket"}})
	if err == nil || !strings.Contains(err.Error(), "does not include") {
		t.Errorf("want error; got %v", err)
	}
}

func TestCollect_DefaultNowIsUsed(t *testing.T) {
	fake := &fakeAPI{
		keys:     []kmstypes.KeyListEntry{{KeyId: ptr("k1")}},
		metadata: map[string]*kmstypes.KeyMetadata{"k1": {KeyId: ptr("k1"), KeyManager: kmstypes.KeyManagerTypeAws}},
	}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if records[0].CollectedAt.IsZero() {
		t.Errorf("CollectedAt zero")
	}
}

func TestCollect_SkipsKeyWithEmptyID(t *testing.T) {
	fake := &fakeAPI{keys: []kmstypes.KeyListEntry{{}, {KeyId: ptr("ok")}}, metadata: map[string]*kmstypes.KeyMetadata{
		"ok": {KeyId: ptr("ok"), KeyManager: kmstypes.KeyManagerTypeAws},
	}}
	p := New(Options{API: fake})
	records, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].ID != "ok" {
		t.Errorf("records = %v", records)
	}
}

func TestCollect_KISSNoDRY_EachCallReListsKeys(t *testing.T) {
	fake := &fakeAPI{
		keys:     []kmstypes.KeyListEntry{{KeyId: ptr("k1")}},
		metadata: map[string]*kmstypes.KeyMetadata{"k1": {KeyId: ptr("k1"), KeyManager: kmstypes.KeyManagerTypeAws}},
	}
	p := New(Options{API: fake})
	for range 3 {
		if _, err := p.Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}}); err != nil {
			t.Fatalf("Collect: %v", err)
		}
	}
	if fake.listCount != 3 {
		t.Errorf("listCount = %d; want 3", fake.listCount)
	}
}

func TestSafeHelpers_NilSafe(t *testing.T) {
	if safeKeyID(nil) != "" {
		t.Errorf("nil keyID not empty")
	}
	if safeKeyMetadata(nil) != nil {
		t.Errorf("nil metadata not nil")
	}
	if safeARN(nil) != "" {
		t.Errorf("nil arn not empty")
	}
	if safeKeyManager(nil) != "" {
		t.Errorf("nil keyManager not empty")
	}
	// Non-nil with arn populated.
	if got := safeARN(&kmstypes.KeyMetadata{Arn: ptr("arn:x")}); got != "arn:x" {
		t.Errorf("safeARN = %q", got)
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

// KMS supports automatic rotation only on symmetric keys with KMS-made
// key material outside a custom key store. GetKeyRotationStatus is not
// asked for the others (an unsupported-operation error there used to
// abort the whole collection); their rotation_enabled is false, which is
// what KMS does with them.
func TestCollect_SkipsRotationStatusForKeysThatCannotRotate(t *testing.T) {
	cmk := func(id string, spec kmstypes.KeySpec, origin kmstypes.OriginType, store *string) *kmstypes.KeyMetadata {
		return &kmstypes.KeyMetadata{KeyId: ptr(id), KeyManager: kmstypes.KeyManagerTypeCustomer, Enabled: true,
			KeySpec: spec, Origin: origin, CustomKeyStoreId: store}
	}
	fake := &fakeAPI{
		keys: []kmstypes.KeyListEntry{{KeyId: ptr(keySym)}, {KeyId: ptr("rsa")}, {KeyId: ptr("hmac")}, {KeyId: ptr("imported")}, {KeyId: ptr("hsm")}},
		metadata: map[string]*kmstypes.KeyMetadata{
			keySym:     cmk(keySym, kmstypes.KeySpecSymmetricDefault, kmstypes.OriginTypeAwsKms, nil),
			"rsa":      cmk("rsa", kmstypes.KeySpecRsa2048, kmstypes.OriginTypeAwsKms, nil),
			"hmac":     cmk("hmac", kmstypes.KeySpecHmac256, kmstypes.OriginTypeAwsKms, nil),
			"imported": cmk("imported", kmstypes.KeySpecSymmetricDefault, kmstypes.OriginTypeExternal, nil),
			"hsm":      cmk("hsm", kmstypes.KeySpecSymmetricDefault, kmstypes.OriginTypeAwsCloudhsm, ptr("cks-1")),
		},
		rotation: map[string]bool{keySym: true},
		rotErr: map[string]error{
			"rsa":      errors.New("UnsupportedOperationException"),
			"hmac":     errors.New("UnsupportedOperationException"),
			"imported": errors.New("UnsupportedOperationException"),
			"hsm":      errors.New("UnsupportedOperationException"),
		},
	}
	recs, err := New(Options{API: fake}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if fake.rotCount != 1 {
		t.Errorf("GetKeyRotationStatus calls = %d; want 1 (only the symmetric KMS-origin key)", fake.rotCount)
	}
	for _, r := range recs {
		var p keyPayload
		if err := json.Unmarshal(r.Payload, &p); err != nil {
			t.Fatal(err)
		}
		if want := r.ID == keySym; p.RotationEnabled != want {
			t.Errorf("%s rotation_enabled = %v; want %v", r.ID, p.RotationEnabled, want)
		}
		// rotation_supported lets the rotation policies leave out keys
		// KMS cannot rotate instead of failing them.
		var raw map[string]any
		if err := json.Unmarshal(r.Payload, &raw); err != nil {
			t.Fatal(err)
		}
		if got, want := raw["rotation_supported"], r.ID == keySym; got != want {
			t.Errorf("%s rotation_supported = %v; want %v", r.ID, got, want)
		}
	}
}

// Without key metadata the plugin cannot tell whether the key can
// rotate, so rotation_supported is omitted rather than guessed.
func TestCollect_RotationSupportedOmittedWithoutMetadata(t *testing.T) {
	fake := &fakeAPI{keys: []kmstypes.KeyListEntry{{KeyId: ptr(keyAAA)}}}
	recs, err := New(Options{API: fake}).Collect(context.Background(), core.SlotRequest{AcceptedTypes: []string{EvidenceTypeID}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(recs[0].Payload, &raw); err != nil {
		t.Fatal(err)
	}
	if v, ok := raw["rotation_supported"]; ok {
		t.Errorf("rotation_supported = %v; want omitted when metadata is missing", v)
	}
}
