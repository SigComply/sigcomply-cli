package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/sign"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// inMemVault is a tiny core.Vault used by the unit tests to exercise
// the recordingVault wrapper without touching the filesystem.
type inMemVault struct {
	envelopes map[string]*core.Envelope
	jsons     map[string][]byte
	bins      map[string][]byte
	initErr   error
	getErr    error
	listErr   error
}

func newInMem() *inMemVault {
	return &inMemVault{
		envelopes: map[string]*core.Envelope{},
		jsons:     map[string][]byte{},
		bins:      map[string][]byte{},
	}
}

func (v *inMemVault) Init(context.Context) error { return v.initErr }
func (v *inMemVault) PutEnvelope(_ context.Context, k string, e *core.Envelope) error {
	v.envelopes[k] = e
	return nil
}
func (v *inMemVault) PutJSON(_ context.Context, k string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	v.jsons[k] = b
	return nil
}
func (v *inMemVault) PutBinary(_ context.Context, k string, body []byte, _ map[string]string) error {
	v.bins[k] = body
	return nil
}
func (v *inMemVault) GetBinary(_ context.Context, k string) ([]byte, error) {
	if v.getErr != nil {
		return nil, v.getErr
	}
	if b, ok := v.bins[k]; ok {
		return b, nil
	}
	return nil, errors.New("not found")
}
func (v *inMemVault) List(_ context.Context, _ string) ([]string, error) {
	return nil, v.listErr
}

func TestBuildRunRoot_FormatsBasicISO8601(t *testing.T) {
	got := buildRunRoot("soc2", "2026-Q1", time.Date(2026, 2, 15, 14, 0, 0, 0, time.UTC), "a3f8b2c1-9d4e-4b23-8f7a-1e5c2d8a9b0f")
	want := "soc2/2026-Q1/run_20260215T140000Z_a3f8b2c1"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
	// Short run IDs are accepted verbatim.
	got = buildRunRoot("soc2", "2026-Q1", time.Date(2026, 2, 15, 14, 0, 0, 0, time.UTC), "abc")
	if !strings.HasSuffix(got, "_abc") {
		t.Errorf("short id suffix: %q", got)
	}
}

func TestRecordingVault_DelegatesAndHashesAllPaths(t *testing.T) {
	inner := newInMem()
	v := newRecordingVault(inner)

	if err := v.Init(context.Background()); err != nil {
		t.Errorf("Init: %v", err)
	}

	env := &core.Envelope{FormatVersion: "envelope.v1", Records: []core.EvidenceRecord{{ID: "x"}}}
	// Sign so EncodeEnvelope works.
	if err := signTestEnvelope(env); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := v.PutEnvelope(context.Background(), "run/a.json", env); err != nil {
		t.Fatalf("PutEnvelope: %v", err)
	}
	if err := v.PutJSON(context.Background(), "run/b.json", map[string]string{"k": "v"}); err != nil {
		t.Fatalf("PutJSON: %v", err)
	}
	if err := v.PutBinary(context.Background(), "run/c.bin", []byte("hello"), map[string]string{"key": "val"}); err != nil {
		t.Fatalf("PutBinary: %v", err)
	}

	hashes := v.FileHashes("run")
	if len(hashes) != 3 {
		t.Errorf("hashes len = %d; want 3", len(hashes))
	}
	for _, key := range []string{"a.json", "b.json", "c.bin"} {
		if _, ok := hashes[key]; !ok {
			t.Errorf("hash missing for %s", key)
		}
	}

	// GetBinary and List delegate to the inner vault.
	if _, err := v.GetBinary(context.Background(), "run/c.bin"); err != nil {
		t.Errorf("GetBinary: %v", err)
	}
	if _, err := v.List(context.Background(), "run/"); err != nil {
		t.Errorf("List: %v", err)
	}
}

func TestRecordingVault_ExcludesManifestFromFileHashes(t *testing.T) {
	v := newRecordingVault(newInMem())
	v.record("run/policies/p1/result.json", []byte("x"))
	v.record("run/manifest.json", []byte("y"))
	got := v.FileHashes("run")
	if _, present := got["manifest.json"]; present {
		t.Errorf("FileHashes leaked manifest.json")
	}
	if _, present := got["policies/p1/result.json"]; !present {
		t.Errorf("FileHashes missing policies/p1/result.json")
	}
}

func TestDetectRepository_PrefersGitHubEnv(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "acme/infra")
	t.Setenv("CI_PROJECT_PATH", "")
	r := detectRepository()
	if r.Provider != "github" || r.NameSlug != "acme/infra" {
		t.Errorf("got %+v", r)
	}
}

func TestDetectRepository_GitLabFallback(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("CI_PROJECT_PATH", "acme/repo")
	t.Setenv("CI_PROJECT_URL", "https://gitlab.com/acme/repo")
	r := detectRepository()
	if r.Provider != "gitlab" || r.NameSlug != "acme/repo" {
		t.Errorf("got %+v", r)
	}
}

func TestDetectRepository_LocalDefault(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "")
	t.Setenv("CI_PROJECT_PATH", "")
	r := detectRepository()
	if r.Provider != "local" {
		t.Errorf("got %+v", r)
	}
}

func TestDetectCIEnvironment_GitHub(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "acme/infra")
	t.Setenv("GITHUB_RUN_ID", "9999")
	t.Setenv("GITHUB_WORKFLOW", "compliance.yml")
	t.Setenv("GITLAB_CI", "")
	env := detectCIEnvironment()
	if env.Provider != "github" {
		t.Errorf("Provider = %q", env.Provider)
	}
	if !strings.Contains(env.RunURL, "/runs/9999") {
		t.Errorf("RunURL = %q", env.RunURL)
	}
}

func TestDetectCIEnvironment_GitLab(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_JOB_URL", "https://gitlab.com/.../jobs/1")
	t.Setenv("CI_JOB_NAME", "compliance")
	env := detectCIEnvironment()
	if env.Provider != "gitlab" {
		t.Errorf("Provider = %q", env.Provider)
	}
	if env.RunURL != "https://gitlab.com/.../jobs/1" {
		t.Errorf("RunURL = %q", env.RunURL)
	}
}

func TestDetectCIEnvironment_LocalDefault(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITLAB_CI", "")
	env := detectCIEnvironment()
	if env.Provider != "local" {
		t.Errorf("Provider = %q", env.Provider)
	}
}

func TestWriteCapturedPayload_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "p.json")
	payload := &core.SubmissionPayload{Schema: "sigcomply.cloud.v1", RunID: "r1"}
	if err := writeCapturedPayload(path, payload); err != nil {
		t.Fatalf("writeCapturedPayload: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(body, []byte("sigcomply.cloud.v1")) {
		t.Errorf("captured does not contain schema: %s", body)
	}
}

func TestShouldFail_DefaultTrue(t *testing.T) {
	if !shouldFail(spec.CIConfig{}) {
		t.Errorf("default should be fail-on-violation = true")
	}
	v := false
	if shouldFail(spec.CIConfig{FailOnViolation: &v}) {
		t.Errorf("explicit false should disable fail-on-violation")
	}
	v = true
	if !shouldFail(spec.CIConfig{FailOnViolation: &v}) {
		t.Errorf("explicit true should enable fail-on-violation")
	}
}

func TestBootstrap_LoadsConfigAndEmptyRegistries(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, ".sigcomply.yaml")
	if err := os.WriteFile(cfgPath, []byte(`schema_version: project.v1
framework: soc2
vault:
  backend: local
  path: ./v
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, regs, err := Bootstrap(cfgPath)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if cfg.Framework != "soc2" {
		t.Errorf("Framework = %q", cfg.Framework)
	}
	if regs == nil || regs.Sources == nil {
		t.Errorf("registries not constructed")
	}
}

func TestBootstrap_MissingFile(t *testing.T) {
	_, _, err := Bootstrap(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Errorf("want error on missing config")
	}
}

func TestBootstrap_ParseError(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, ".sigcomply.yaml")
	if err := os.WriteFile(cfgPath, []byte("not valid yaml: : :"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, _, err := Bootstrap(cfgPath)
	if err == nil {
		t.Errorf("want parse error")
	}
}

// signTestEnvelope signs an envelope via the public sign package.
func signTestEnvelope(env *core.Envelope) error { return sign.Envelope(env) }
