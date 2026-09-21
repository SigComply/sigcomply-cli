package plugin_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/manual"
	"github.com/sigcomply/sigcomply-cli/internal/vault"
	"github.com/sigcomply/sigcomply-cli/plugin"
)

// This file is the drift guard for the public façade.
//
// Everything below is written the way a project-local extension is
// written: every type it names comes from the public plugin package and
// nothing from internal/. The assertions at the bottom then hand those
// values to the INTERNAL interfaces and factory types the CLI actually
// dispatches on. Because every re-export in plugin/plugin.go is a type
// alias rather than a wrapper, those assignments must compile with no
// conversion — and they stop compiling the moment an alias is dropped,
// renamed, or turned into a distinct named type. That is the whole
// point: the façade cannot silently drift from what it claims to
// re-export.
//
// The companion test in external_module_test.go proves the other half —
// that a package OUTSIDE this module can import the façade at all. The
// two together are what the old build_test.go fixtures (empty packages
// with no sigcomply import) never checked.

const (
	testSourceID = "acme.test_source"
	testVaultID  = "acme.test_vault"
	testReaderID = "acme.test_reader"
	testTypeID   = "directory_user"
)

// --- Axis C: a source plugin written against the public API ---------

type testSource struct{ endpoint string }

func (s *testSource) ID() string      { return testSourceID }
func (s *testSource) Emits() []string { return []string{testTypeID} }

func (s *testSource) Init(_ context.Context, cfg map[string]any) error {
	ep, ok := cfg["endpoint"].(string)
	if !ok || ep == "" {
		return errors.New(testSourceID + ": endpoint is required")
	}
	s.endpoint = ep
	return nil
}

func (s *testSource) Collect(_ context.Context, req plugin.SlotRequest) ([]plugin.EvidenceRecord, error) {
	if !req.Accepts(testTypeID) {
		return nil, nil
	}
	payload, err := json.Marshal(map[string]any{"id": "u-1", "mfa_enabled": true})
	if err != nil {
		return nil, err
	}
	return []plugin.EvidenceRecord{{
		Type:        testTypeID,
		ID:          "u-1",
		IdentityKey: "alice@example.com",
		SourceID:    testSourceID,
		CollectedAt: time.Unix(0, 0).UTC(),
		Payload:     payload,
		Scope:       &plugin.RecordScope{Account: "acme", Region: "eu-west-1"},
	}}, nil
}

// Caveats exercises the optional-interface half of the surface: a
// plugin that implements it must be seen as a core.CaveatedSource by
// the planner, which only holds if plugin.SourceCaveat is the same type.
func (s *testSource) Caveats() []plugin.SourceCaveat {
	return []plugin.SourceCaveat{{
		EvidenceType: testTypeID,
		Field:        "mfa_enabled",
		Detail:       "the test endpoint publishes no MFA field; the value is a fixed default",
	}}
}

func newTestSource(ctx context.Context, env plugin.Env) (plugin.SourcePlugin, error) {
	s := &testSource{}
	if err := s.Init(ctx, env.Config); err != nil {
		return nil, err
	}
	return s, nil
}

// --- Axis B: a vault backend written against the public API ---------

type testVault struct{ backend string }

func (v *testVault) Init(_ context.Context) error                                      { return nil }
func (v *testVault) PutEnvelope(_ context.Context, _ string, _ *plugin.Envelope) error { return nil }
func (v *testVault) PutJSON(_ context.Context, _ string, _ any) error                  { return nil }
func (v *testVault) PutBinary(_ context.Context, _ string, _ []byte, _ map[string]string) error {
	return nil
}
func (v *testVault) GetBinary(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func (v *testVault) List(_ context.Context, _ string) ([]string, error)    { return nil, nil }

func newTestVault(_ context.Context, cfg *plugin.VaultConfig) (plugin.Vault, error) {
	if cfg.Backend == "" {
		return nil, errors.New(testVaultID + ": backend is required")
	}
	return &testVault{backend: cfg.Backend}, nil
}

// --- Axis A: a manual-evidence reader written against the public API -

type testReader struct{ files map[string][]byte }

func (r *testReader) Get(_ context.Context, key string) ([]byte, time.Time, error) {
	data, ok := r.files[key]
	if !ok {
		return nil, time.Time{}, plugin.ErrManualNotFound
	}
	return data, time.Unix(0, 0).UTC(), nil
}

func (r *testReader) List(_ context.Context, prefix string) ([]plugin.ManualFileInfo, error) {
	out := make([]plugin.ManualFileInfo, 0, len(r.files))
	for key := range r.files {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			out = append(out, plugin.ManualFileInfo{Key: key, UploadedAt: time.Unix(0, 0).UTC()})
		}
	}
	return out, nil
}

func newTestReader(raw map[string]any) (reader plugin.ManualReader, scheme, bucket, prefix string, err error) {
	bucket, ok := raw["bucket"].(string)
	if !ok || bucket == "" {
		return nil, "", "", "", errors.New(testReaderID + `: "bucket" required`)
	}
	return &testReader{files: map[string][]byte{}}, "test", bucket, "manual/", nil
}

// --- The drift guard ------------------------------------------------
//
// Every assignment here crosses the façade: the left-hand side is the
// internal type the CLI dispatches on, the right-hand side was written
// naming only public types.

var (
	_ core.SourcePlugin    = (*testSource)(nil)
	_ core.CaveatedSource  = (*testSource)(nil)
	_ sources.Factory      = newTestSource
	_ core.Vault           = (*testVault)(nil)
	_ vault.Factory        = newTestVault
	_ manual.Reader        = (*testReader)(nil)
	_ manual.ReaderFactory = newTestReader
)

// TestRegisterSource_ReachesTheInternalRegistry checks the other
// direction: a registration made through the public forwarder must be
// visible to — and buildable by — the internal registry the orchestrator
// reads. A forwarder that wrote into its own map would satisfy the type
// assertions above and still leave the plugin unreachable at run time.
func TestRegisterSource_ReachesTheInternalRegistry(t *testing.T) {
	plugin.RegisterSource(testSourceID, newTestSource, "endpoint")

	if _, ok := sources.Lookup(testSourceID); !ok {
		t.Fatalf("sources.Lookup(%q) = false; public registration did not reach the internal registry", testSourceID)
	}
	if got := sources.ConfigKeys(testSourceID); len(got) != 1 || got[0] != "endpoint" {
		t.Errorf("sources.ConfigKeys(%q) = %v; want [endpoint]", testSourceID, got)
	}

	built, err := sources.Build(context.Background(), testSourceID, sources.Env{
		Config: map[string]any{"endpoint": "https://auth.example.internal"},
	})
	if err != nil {
		t.Fatalf("sources.Build: %v", err)
	}
	if built.ID() != testSourceID {
		t.Errorf("built.ID() = %q; want %q", built.ID(), testSourceID)
	}
	caveated, ok := built.(core.CaveatedSource)
	if !ok {
		t.Fatalf("built plugin does not satisfy core.CaveatedSource")
	}
	if len(caveated.Caveats()) != 1 {
		t.Errorf("Caveats() = %v; want one caveat", caveated.Caveats())
	}

	records, err := built.Collect(context.Background(), core.SlotRequest{
		PolicyID:      "test.policy",
		SlotName:      "evidence",
		AcceptedTypes: []string{testTypeID},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(records) != 1 || records[0].Type != testTypeID {
		t.Fatalf("Collect returned %+v; want one %s record", records, testTypeID)
	}
}

// TestRegisterVaultBackend_ReachesTheInternalRegistry mirrors the source
// check for Axis B, and goes through vault.FromConfig — the production
// call site — rather than the registry lookup alone.
func TestRegisterVaultBackend_ReachesTheInternalRegistry(t *testing.T) {
	plugin.RegisterVaultBackend(testVaultID, newTestVault)

	built, err := vault.FromConfig(context.Background(), &plugin.VaultConfig{
		Backend: testVaultID,
		Config:  map[string]any{"path": "/mnt/sigcomply"},
	})
	if err != nil {
		t.Fatalf("vault.FromConfig: %v", err)
	}
	if _, ok := built.(*testVault); !ok {
		t.Errorf("vault.FromConfig returned %T; want *testVault", built)
	}
}

// TestRegisterManualReader_ReachesTheInternalRegistry mirrors the check
// for Axis A.
func TestRegisterManualReader_ReachesTheInternalRegistry(t *testing.T) {
	plugin.RegisterManualReader(testReaderID, newTestReader)

	factory, ok := manual.LookupReader(testReaderID)
	if !ok {
		t.Fatalf("manual.LookupReader(%q) = false; public registration did not reach the internal registry", testReaderID)
	}
	reader, scheme, bucket, prefix, err := factory(map[string]any{"bucket": "acme-manual"})
	if err != nil {
		t.Fatalf("reader factory: %v", err)
	}
	if scheme != "test" || bucket != "acme-manual" || prefix != "manual/" {
		t.Errorf("factory returned (%q, %q, %q); want (test, acme-manual, manual/)", scheme, bucket, prefix)
	}
	if _, _, err := reader.Get(context.Background(), "missing"); !errors.Is(err, manual.ErrNotFound) {
		t.Errorf("Get(missing) error = %v; want manual.ErrNotFound — plugin.ErrManualNotFound must be the same sentinel", err)
	}
}
