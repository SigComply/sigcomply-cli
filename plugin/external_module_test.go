package plugin_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This file compiles a project-local extension the way a customer's
// repo does: from a SEPARATE Go module, at a `.sigcomply/plugins/...`
// path, importing the public façade. It is the test the repo never had
// — every existing build_test.go fixture is an empty package with no
// sigcomply import, so nothing ever proved a real extension compiles,
// and the `internal/` import wall went unnoticed until it was read out
// of the docs.
//
// Two halves, and both matter:
//
//   - the positive case must build, which is only true if the façade
//     lives outside internal/;
//   - the negative control must FAIL with "use of internal package",
//     which is what proves the fixture really is external. Without it a
//     mistake in the harness (a fixture accidentally placed inside this
//     module, a workspace that flattened the boundary) would make the
//     positive case pass for the wrong reason and prove nothing.
//
// The fixture module is wired to this repo with a go.work workspace
// rather than a `replace` + copied go.sum: workspace mode resolves the
// CLI module from disk and reuses this repo's own go.sum for the whole
// dependency graph, so the test needs no network and no synthesized
// requirements. GOPROXY=off makes that hermeticity explicit — if a
// module is missing from the local cache we skip rather than fail, since
// that is an environment problem, not a regression in the façade.

// externalPluginSrc is the source-plugin half of the fixture: the
// worked example from docs/architecture/07-extensibility.md §Authoring a
// custom source plugin, with its imports pointed at the public package.
// Keeping it byte-for-byte in the shape the docs teach is deliberate —
// if the docs stop compiling, this test is where we find out.
const externalPluginSrc = `package acme_internal_iam

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sigcomply/sigcomply-cli/plugin"
)

const SourceID = "acme.internal_iam"

type Plugin struct {
	endpoint string
}

func (p *Plugin) ID() string      { return SourceID }
func (p *Plugin) Emits() []string { return []string{"directory_user"} }

func (p *Plugin) Init(_ context.Context, cfg map[string]any) error {
	endpoint, ok := cfg["endpoint"].(string)
	if !ok || endpoint == "" {
		return fmt.Errorf("%s: endpoint is required", SourceID)
	}
	p.endpoint = endpoint
	return nil
}

func (p *Plugin) Collect(_ context.Context, req plugin.SlotRequest) ([]plugin.EvidenceRecord, error) {
	if !req.Accepts("directory_user") {
		return nil, nil
	}
	payload, err := json.Marshal(map[string]any{"id": "u-1", "mfa_enabled": true})
	if err != nil {
		return nil, err
	}
	return []plugin.EvidenceRecord{{
		Type:        "directory_user",
		ID:          "u-1",
		IdentityKey: "alice@acme.example",
		SourceID:    SourceID,
		Payload:     payload,
		Scope:       &plugin.RecordScope{Account: "acme"},
	}}, nil
}

func (p *Plugin) Caveats() []plugin.SourceCaveat {
	return []plugin.SourceCaveat{{
		EvidenceType: "directory_user",
		Field:        "mfa_enabled",
		Detail:       "Acme internal IAM publishes no MFA field; the value emitted is a fixed default",
	}}
}

var (
	_ plugin.SourcePlugin   = (*Plugin)(nil)
	_ plugin.CaveatedSource = (*Plugin)(nil)
)

func init() {
	plugin.RegisterSource(SourceID, func(ctx context.Context, env plugin.Env) (plugin.SourcePlugin, error) {
		p := &Plugin{}
		if err := p.Init(ctx, env.Config); err != nil {
			return nil, err
		}
		return p, nil
	}, "endpoint")
}
`

// externalBackendsSrc is the Axis A + Axis B half of the fixture: a
// vault backend and a manual-evidence reader, also from the worked
// examples. Both registries are part of the compatibility promise, so
// both get compiled from outside the module too.
const externalBackendsSrc = `package acme_internal_iam

import (
	"context"
	"fmt"
	"time"

	"github.com/sigcomply/sigcomply-cli/plugin"
)

type NFSVault struct {
	root string
}

func (v *NFSVault) Init(_ context.Context) error { return nil }
func (v *NFSVault) PutEnvelope(_ context.Context, _ string, _ *plugin.Envelope) error { return nil }
func (v *NFSVault) PutJSON(_ context.Context, _ string, _ any) error { return nil }
func (v *NFSVault) PutBinary(_ context.Context, _ string, _ []byte, _ map[string]string) error {
	return nil
}
func (v *NFSVault) GetBinary(_ context.Context, _ string) ([]byte, error) { return nil, nil }
func (v *NFSVault) List(_ context.Context, _ string) ([]string, error)    { return nil, nil }

type SFTPReader struct {
	host string
}

func (r *SFTPReader) Get(_ context.Context, _ string) ([]byte, time.Time, error) {
	return nil, time.Time{}, plugin.ErrManualNotFound
}

func (r *SFTPReader) List(_ context.Context, _ string) ([]plugin.ManualFileInfo, error) {
	return nil, nil
}

var (
	_ plugin.Vault        = (*NFSVault)(nil)
	_ plugin.ManualReader = (*SFTPReader)(nil)
)

func init() {
	plugin.RegisterVaultBackend("acme.nfs", func(_ context.Context, cfg *plugin.VaultConfig) (plugin.Vault, error) {
		root := cfg.Str("path")
		if root == "" {
			return nil, fmt.Errorf("acme.nfs: \"path\" required")
		}
		return &NFSVault{root: root}, nil
	})

	plugin.RegisterManualReader("acme.sftp", func(raw map[string]any) (plugin.ManualReader, string, string, string, error) {
		host, ok := raw["host"].(string)
		if !ok || host == "" {
			return nil, "", "", "", fmt.Errorf("manual.pdf.acme.sftp: \"host\" required")
		}
		bucket, _ := raw["bucket"].(string)
		prefix, _ := raw["prefix"].(string)
		if prefix == "" {
			prefix = "manual/"
		}
		return &SFTPReader{host: host}, "sftp", bucket, prefix, nil
	})
}
`

// internalImportSrc is the negative control: the same extension path,
// importing internal/core the way every worked example used to.
const internalImportSrc = `package acme_internal_iam

import (
	"github.com/sigcomply/sigcomply-cli/internal/core"
)

var _ = core.SourcePlugin(nil)
`

// pluginDirRel is where `sigcomply build` expects a project-local
// plugin. The leading-dot element is load-bearing for this test: an
// import path like example.com/acme-project/.sigcomply/plugins/... is
// unusual enough to be worth proving the toolchain resolves it, because
// if it did not, a public façade alone would not unblock the walkthrough.
const pluginDirRel = ".sigcomply/plugins/acme.internal_iam"

// repoRoot locates this module's root from the test file's own path:
// <root>/plugin/external_module_test.go.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate the repo root")
	}
	return filepath.Dir(filepath.Dir(file))
}

// writeExternalProject lays out a customer-shaped module: its own
// go.mod, a go.work tying it to this repo, and one project-local plugin
// package holding the given files.
func writeExternalProject(t *testing.T, files map[string]string) string {
	t.Helper()
	// EvalSymlinks matters here: on macOS t.TempDir() hands back a
	// /var/folders path that is a symlink to /private/var/folders, and
	// the go command resolves the two differently — the workspace's
	// `use .` would then name a directory the toolchain does not believe
	// holds the module it is compiling.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	pluginDir := filepath.Join(dir, filepath.FromSlash(pluginDirRel))
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		t.Fatalf("mkdir plugin dir: %v", err)
	}
	write := func(path, body string) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write(filepath.Join(dir, "go.mod"), "module example.com/acme-project\n\ngo 1.27.0\n")
	write(filepath.Join(dir, "go.work"), "go 1.27.0\n\nuse (\n\t.\n\t"+repoRoot(t)+"\n)\n")
	for name, body := range files {
		write(filepath.Join(pluginDir, name), body)
	}
	return dir
}

// goBuildExternal compiles the fixture's plugin package and returns the
// combined tool output.
func goBuildExternal(t *testing.T, dir string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "go", "build", "./"+pluginDirRel) //nolint:gosec // fixed args over a t.TempDir path
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GOWORK="+filepath.Join(dir, "go.work"),
		// No network: every dependency must already be in the local
		// module cache, which this repo's own build populates.
		"GOPROXY=off",
	)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// skipIfEnvironmentCannotResolveModules distinguishes "the façade is
// broken" from "this machine has a cold module cache and no network".
func skipIfEnvironmentCannotResolveModules(t *testing.T, out string) {
	t.Helper()
	for _, marker := range []string{
		"module lookup disabled by GOPROXY=off",
		"missing go.sum entry",
		"cannot query module",
	} {
		if strings.Contains(out, marker) {
			t.Skip("module cache cannot resolve the CLI's dependencies offline: " + out)
		}
	}
}

func requireGoToolchain(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skips invocation of `go build` under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable: " + err.Error())
	}
}

// TestPublicAPI_CompilesFromAnExternalModule is the positive half: a
// project-local extension in a customer module, importing only the
// public package, must compile.
func TestPublicAPI_CompilesFromAnExternalModule(t *testing.T) {
	requireGoToolchain(t)

	dir := writeExternalProject(t, map[string]string{
		"plugin.go":   externalPluginSrc,
		"backends.go": externalBackendsSrc,
	})
	out, err := goBuildExternal(t, dir)
	if err != nil {
		skipIfEnvironmentCannotResolveModules(t, out)
		t.Fatalf("project-local extension failed to compile against the public API: %v\n%s", err, out)
	}
}

// TestInternalPackages_StayUnreachableFromAnExternalModule is the
// negative control described at the top of this file, and doubles as the
// regression test for the defect itself: if someone ever moves a plugin
// interface back behind internal/ and repoints the docs at it, the
// walkthrough breaks exactly here.
func TestInternalPackages_StayUnreachableFromAnExternalModule(t *testing.T) {
	requireGoToolchain(t)

	dir := writeExternalProject(t, map[string]string{"plugin.go": internalImportSrc})
	out, err := goBuildExternal(t, dir)
	if err == nil {
		t.Fatal("importing internal/core from an external module compiled; the fixture is not really external, so the positive test proves nothing")
	}
	skipIfEnvironmentCannotResolveModules(t, out)
	if !strings.Contains(out, "use of internal package") {
		t.Fatalf("want a `use of internal package` rejection; got: %s", out)
	}
}
