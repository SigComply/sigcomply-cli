package orchestrator_test

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/frameworks/soc2"
	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/orchestrator"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
	"github.com/sigcomply/sigcomply-cli/internal/vault/local"
)

const (
	mfaPolicyID       = "soc2.cc6.1.mfa_enforced_all_users"
	vaultBackendLocal = "local"
	srcIdentityCenter = "aws.identity_center"
)

// caveatedFakeSource is a rosterFakeSource that also declares a caveat —
// modeling aws.identity_center, which emits mfa_enabled it cannot observe.
type caveatedFakeSource struct {
	rosterFakeSource
}

func (c *caveatedFakeSource) Caveats() []core.SourceCaveat {
	return []core.SourceCaveat{{
		EvidenceType: "directory_user",
		Field:        fieldMFAEnabled,
		Detail:       "no per-user MFA API",
	}}
}

// runCaveatCheck runs a real orchestrator pass over the shipped MFA policy
// and returns what the operator would see in the log.
func runCaveatCheck(t *testing.T, sources ...core.SourcePlugin) string {
	t.Helper()
	regs := bootstrapWithRegistries(nil)
	if err := soc2.Register(regs); err != nil {
		t.Fatalf("register soc2: %v", err)
	}
	cfg := &spec.ProjectConfig{Framework: testFramework, Sources: map[string]map[string]any{}}
	for _, s := range sources {
		if err := regs.Sources.Register(s); err != nil {
			t.Fatalf("register %s: %v", s.ID(), err)
		}
		cfg.Sources[s.ID()] = map[string]any{}
	}
	vaultDir := filepath.Join(t.TempDir(), "vault")
	cfg.Vault = localVault(vaultDir)
	v := local.New(vaultDir)
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("vault init: %v", err)
	}
	var logBuf bytes.Buffer
	if _, err := orchestrator.Run(context.Background(), &orchestrator.Options{
		Config: cfg, Registries: regs, Vault: v,
		Stdout: &bytes.Buffer{}, Logger: log.New(&logBuf, false),
		Now:    func() time.Time { return time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC) },
		Filter: planner.Filter{Policies: []string{mfaPolicyID}},
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	return logBuf.String()
}

// localVault is the on-disk vault config every orchestrator e2e run uses.
func localVault(dir string) spec.VaultConfig {
	return spec.VaultConfig{Backend: vaultBackendLocal, Config: map[string]any{"path": dir}}
}

func mfaFake(t *testing.T, id string, mfa bool) rosterFakeSource {
	t.Helper()
	return rosterFakeSource{id: id, records: []core.EvidenceRecord{
		fakeRecord(t, id, "directory_user", map[string]any{
			"id": id + "-u1", fieldEmail: "jane@acme.com", fieldMFAEnabled: mfa,
		}),
	}}
}

// The case the caveat exists for, end to end: an identity source that cannot
// observe MFA is unioned into the same slot as one that can, and the operator
// is told — with the pin that fixes it.
func TestE2E_SourceCaveat_WarnsAndNamesThePin(t *testing.T) {
	sso := &caveatedFakeSource{mfaFake(t, srcIdentityCenter, false)}
	idp := mfaFake(t, sourceOkta, true)

	got := runCaveatCheck(t, sso, &idp)

	for _, want := range []string{
		"source-caveat: " + srcIdentityCenter + " cannot verify directory_user.mfa_enabled",
		"no per-user MFA API",
		mfaPolicyID,
		"okta also bound to slot \"evidence\"",
		"evidence: [okta]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("log missing %q; got:\n%s", want, got)
		}
	}
}

// The accepted residue: with no other identity source, the MFA control
// genuinely cannot be demonstrated. Do not offer a pin that does not exist.
func TestE2E_SourceCaveat_SoleSourceIsARealFinding(t *testing.T) {
	sso := &caveatedFakeSource{mfaFake(t, srcIdentityCenter, false)}

	got := runCaveatCheck(t, sso)

	if !strings.Contains(got, "real finding rather than a binding mistake") {
		t.Errorf("log = %q; want the honest-residue wording", got)
	}
	if strings.Contains(got, "bindings:") {
		t.Errorf("log suggested a pin with nothing to pin to:\n%s", got)
	}
}

// An estate with no caveated source must see nothing — a warning that fires
// on every clean run is a warning operators learn to skip.
func TestE2E_SourceCaveat_SilentOnACleanEstate(t *testing.T) {
	idp := mfaFake(t, sourceOkta, true)

	if got := runCaveatCheck(t, &idp); strings.Contains(got, "source-caveat:") {
		t.Errorf("clean estate produced a caveat warning:\n%s", got)
	}
}
