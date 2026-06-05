package local_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
	"github.com/sigcomply/sigcomply-cli/internal/vault/local"
	"github.com/sigcomply/sigcomply-cli/internal/vault/vaulttest"
)

func TestLocalVault_Contract(t *testing.T) {
	vaulttest.RunContractSuite(t, func(t *testing.T) core.Vault {
		t.Helper()
		v := local.New(t.TempDir())
		if err := v.Init(context.Background()); err != nil {
			t.Fatalf("Init: %v", err)
		}
		return v
	})
}

func TestLocalVault_RejectsEscapingKey(t *testing.T) {
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	bad := []string{
		"../escape.txt",
		"foo/../../escape.txt",
		"/absolute.txt",
	}
	for _, k := range bad {
		if err := v.PutBinary(context.Background(), k, []byte("x"), nil); err == nil {
			t.Errorf("PutBinary(%q) = nil; expected escape error", k)
		}
	}
}

func TestLocalVault_InitRejectsEmptyRoot(t *testing.T) {
	v := local.New("")
	if err := v.Init(context.Background()); err == nil {
		t.Error("Init on empty Root returned nil error")
	}
}

func TestLocalVault_ListOnMissingPrefix(t *testing.T) {
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	keys, err := v.List(context.Background(), "no-such-dir/")
	if err != nil {
		t.Fatalf("List on missing prefix returned error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("List on missing prefix returned %v; want empty", keys)
	}
}

func TestLocalVault_ListOnSingleFile(t *testing.T) {
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := v.PutBinary(context.Background(), "solo.bin", []byte("x"), nil); err != nil {
		t.Fatalf("PutBinary: %v", err)
	}
	keys, err := v.List(context.Background(), "solo.bin")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || !strings.HasSuffix(keys[0], "solo.bin") {
		t.Errorf("List(solo.bin) = %v; want [solo.bin]", keys)
	}
}

func TestLocalVault_PutJSON_MarshalError(t *testing.T) {
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	// json.Marshal fails on channels.
	err := v.PutJSON(context.Background(), "bad.json", make(chan int))
	if err == nil {
		t.Error("PutJSON with unmarshalable value: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "marshal json") {
		t.Errorf("PutJSON error %q does not mention 'marshal json'", err)
	}
}

func TestLocalVault_PutEnvelope_SignedSucceeds(t *testing.T) {
	// Verify that a properly signed envelope round-trips through PutEnvelope.
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	env := core.Envelope{
		FormatVersion: "envelope.v1",
		ProducedAt:    time.Date(2026, 5, 23, 14, 0, 0, 0, time.UTC),
		Records: []core.EvidenceRecord{
			{
				Type:        "user_record",
				ID:          "alice",
				IdentityKey: "alice@acme.com",
				Payload:     json.RawMessage(`{"mfa_enabled":true}`),
				SourceID:    "aws.iam",
				CollectedAt: time.Date(2026, 5, 23, 14, 0, 0, 0, time.UTC),
			},
		},
	}
	if err := sign.Envelope(&env); err != nil {
		t.Fatalf("sign.Envelope: %v", err)
	}
	if err := v.PutEnvelope(context.Background(), "run/e.json", &env); err != nil {
		t.Fatalf("PutEnvelope (signed): %v", err)
	}
}

func TestLocalVault_PutEnvelope_UnsignedErrors(t *testing.T) {
	// sign.EncodeEnvelope rejects unsigned envelopes; PutEnvelope must
	// propagate that error rather than writing garbage bytes.
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	env := core.Envelope{FormatVersion: "envelope.v1"} // no signature
	err := v.PutEnvelope(context.Background(), "run/e.json", &env)
	if err == nil {
		t.Error("PutEnvelope (unsigned): expected error, got nil")
	}
	if !strings.Contains(err.Error(), "encode envelope") {
		t.Errorf("PutEnvelope error %q does not mention 'encode envelope'", err)
	}
}

func TestLocalVault_GetBinary_ResolveErrorWhenRootEmpty(t *testing.T) {
	// GetBinary should propagate the resolve error when Root is empty (not initialized).
	v := local.New("") // deliberately skip Init
	_, err := v.GetBinary(context.Background(), "some/key.bin")
	if err == nil {
		t.Error("GetBinary on uninitialized vault: expected error, got nil")
	}
}

func TestLocalVault_List_ResolveErrorWhenRootEmpty(t *testing.T) {
	// List should propagate the resolve error when Root is empty.
	v := local.New("")
	_, err := v.List(context.Background(), "prefix/")
	if err == nil {
		t.Error("List on uninitialized vault: expected error, got nil")
	}
}

func TestLocalVault_PutBinary_ResolveErrorWhenRootEmpty(t *testing.T) {
	v := local.New("")
	err := v.PutBinary(context.Background(), "k.bin", []byte("x"), nil)
	if err == nil {
		t.Error("PutBinary on uninitialized vault: expected error, got nil")
	}
}

// TestLocalVault_List_ResolveErrorOnAbsolutePrefix verifies that List
// rejects an absolute key via resolve() rather than silently leaking.
func TestLocalVault_List_ResolveErrorOnAbsolutePrefix(t *testing.T) {
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	_, err := v.List(context.Background(), "/absolute")
	if err == nil {
		t.Error("List with absolute prefix: expected error, got nil")
	}
}

func TestLocalVault_GetBinary_ResolveErrorOnAbsoluteKey(t *testing.T) {
	v := local.New(t.TempDir())
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	_, err := v.GetBinary(context.Background(), "/absolute")
	if err == nil {
		t.Error("GetBinary with absolute key: expected error, got nil")
	}
}
