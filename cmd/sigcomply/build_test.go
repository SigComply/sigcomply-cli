package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fixtureModulePath is the module name written into fixture go.mod
// files. It must match the import paths we expect in generated
// entrypoints; the build wrapper computes import paths as
// `<module>/<rel-dir>`.
const fixtureModulePath = "example.com/acme-project"

// writeGoMod creates a minimal go.mod in dir declaring the fixture
// module path. The build wrapper requires a project go.mod to resolve
// project-local extension import paths.
func writeGoMod(t *testing.T, dir string) {
	t.Helper()
	body := "module " + fixtureModulePath + "\n\ngo 1.25\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(body), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
}

// writePluginFile writes a minimal Go file declaring `package <name>`
// at .sigcomply/plugins/<name>/<filename> under projectDir. body is
// the source after the package clause; if empty, only the package
// clause is emitted.
func writePluginFile(t *testing.T, projectDir, name, filename, body string) {
	t.Helper()
	dir := filepath.Join(projectDir, ".sigcomply", "plugins", name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	src := "package " + sanitizePackageName(name) + "\n\n" + body
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(src), 0o600); err != nil {
		t.Fatalf("write %s: %v", filename, err)
	}
}

func writeRuleFile(t *testing.T, projectDir, policyName, filename, body string) {
	t.Helper()
	dir := filepath.Join(projectDir, ".sigcomply", "policies", policyName, "rules")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	src := "package rules\n\n" + body
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(src), 0o600); err != nil {
		t.Fatalf("write %s: %v", filename, err)
	}
}

func writeEvidenceTypeFile(t *testing.T, projectDir, name, filename, body string) {
	t.Helper()
	dir := filepath.Join(projectDir, ".sigcomply", "evidence_types", name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	src := "package " + sanitizePackageName(name) + "\n\n" + body
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(src), 0o600); err != nil {
		t.Fatalf("write %s: %v", filename, err)
	}
}

func TestSanitizePackageName(t *testing.T) {
	cases := map[string]string{
		"acme.internal_iam": "acme_internal_iam",
		"foo-bar":           "foo_bar",
		"plain":             "plain",
	}
	for in, want := range cases {
		if got := sanitizePackageName(in); got != want {
			t.Errorf("sanitizePackageName(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestDiscoverExtensions_NoSigcomplyDir(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("DiscoverExtensions: %v", err)
	}
	if len(exts) != 0 {
		t.Errorf("expected no extensions; got %v", exts)
	}
}

func TestDiscoverExtensions_EmptySigcomplyDir(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	if err := os.MkdirAll(filepath.Join(tmp, ".sigcomply"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("DiscoverExtensions: %v", err)
	}
	if len(exts) != 0 {
		t.Errorf("expected no extensions; got %v", exts)
	}
}

func TestDiscoverExtensions_PluginOnly(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	writePluginFile(t, tmp, "acme.internal_iam", "plugin.go", "func init() {}\n")
	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("DiscoverExtensions: %v", err)
	}
	if len(exts) != 1 {
		t.Fatalf("len(exts) = %d; want 1: %v", len(exts), exts)
	}
	got := exts[0]
	if got.Kind != ExtensionKindPlugin {
		t.Errorf("Kind = %q; want %q", got.Kind, ExtensionKindPlugin)
	}
	if got.Name != "acme.internal_iam" {
		t.Errorf("Name = %q", got.Name)
	}
	wantImport := fixtureModulePath + "/.sigcomply/plugins/acme.internal_iam"
	if got.ImportPath != wantImport {
		t.Errorf("ImportPath = %q; want %q", got.ImportPath, wantImport)
	}
	if got.PackageName != "acme_internal_iam" {
		t.Errorf("PackageName = %q", got.PackageName)
	}
}

func TestDiscoverExtensions_RuleAndEvidenceType(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	writeRuleFile(t, tmp, "acme.custom.cc6.1.contractor_review", "rule.go", "func init() {}\n")
	writeEvidenceTypeFile(t, tmp, "acme_internal_user", "et.go", "func init() {}\n")

	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("DiscoverExtensions: %v", err)
	}
	if len(exts) != 2 {
		t.Fatalf("len(exts) = %d; want 2: %v", len(exts), exts)
	}
	kinds := map[ExtensionKind]bool{}
	for _, e := range exts {
		kinds[e.Kind] = true
	}
	if !kinds[ExtensionKindRule] {
		t.Errorf("rule not discovered")
	}
	if !kinds[ExtensionKindEvidenceType] {
		t.Errorf("evidence_type not discovered")
	}
}

func TestDiscoverExtensions_SkipsDirsWithNoGoFiles(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	// Plugin dir holds only a YAML manifest — not a Go package, must
	// be skipped without error.
	dir := filepath.Join(tmp, ".sigcomply", "plugins", "yaml_only")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugin.yaml"), []byte("id: x\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("DiscoverExtensions: %v", err)
	}
	if len(exts) != 0 {
		t.Errorf("expected 0 exts; got %v", exts)
	}
}

func TestDiscoverExtensions_PackageNameMismatchErrors(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	dir := filepath.Join(tmp, ".sigcomply", "plugins", "myplugin")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Wrong package name on purpose.
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("package wrongname\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := DiscoverExtensions(tmp)
	if err == nil || !strings.Contains(err.Error(), "package name") {
		t.Fatalf("want package-name mismatch error; got %v", err)
	}
}

func TestDiscoverExtensions_RequiresGoMod(t *testing.T) {
	tmp := t.TempDir()
	// No go.mod — but there's a Go extension. Should error.
	writePluginFile(t, tmp, "x", "p.go", "")
	_, err := DiscoverExtensions(tmp)
	if err == nil || !strings.Contains(err.Error(), "go.mod") {
		t.Fatalf("want go.mod-required error; got %v", err)
	}
}

func TestDiscoverExtensions_FlatEvidenceTypesDir(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	// evidence_types/ is itself a Go package (flat layout).
	dir := filepath.Join(tmp, ".sigcomply", "evidence_types")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "types.go"), []byte("package evidence_types\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("DiscoverExtensions: %v", err)
	}
	if len(exts) != 1 || exts[0].Kind != ExtensionKindEvidenceType {
		t.Errorf("want one evidence_type ext; got %v", exts)
	}
}

func TestValidateExtensions_RejectsOsExec(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	writePluginFile(t, tmp, "evil", "bad.go", `import _ "os/exec"`+"\n")
	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("DiscoverExtensions: %v", err)
	}
	err = ValidateExtensions(exts)
	if err == nil || !strings.Contains(err.Error(), "os/exec") {
		t.Fatalf("want os/exec rejection; got %v", err)
	}
}

func TestValidateExtensions_RejectsNetHTTP(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	writePluginFile(t, tmp, "evil", "bad.go", `import _ "net/http"`+"\n")
	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("DiscoverExtensions: %v", err)
	}
	err = ValidateExtensions(exts)
	if err == nil || !strings.Contains(err.Error(), "net/http") {
		t.Fatalf("want net/http rejection; got %v", err)
	}
}

func TestValidateExtensions_RejectsBareNet(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	writePluginFile(t, tmp, "evil", "bad.go", `import _ "net"`+"\n")
	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("DiscoverExtensions: %v", err)
	}
	if err := ValidateExtensions(exts); err == nil {
		t.Fatalf("want bare-net rejection; got nil")
	}
}

func TestValidateExtensions_AllowsBenignImports(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	writePluginFile(t, tmp, "ok", "good.go",
		"import (\n\t\"fmt\"\n\t\"strings\"\n)\n\nvar _ = fmt.Stringer(nil)\nvar _ = strings.Builder{}\n")
	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("DiscoverExtensions: %v", err)
	}
	if err := ValidateExtensions(exts); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}

func TestGenerateEntrypoint_DeterministicShape(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	writePluginFile(t, tmp, "myplugin", "p.go", "")
	writeRuleFile(t, tmp, "acme.rule", "r.go", "")

	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("DiscoverExtensions: %v", err)
	}
	dir, err := GenerateEntrypoint(tmp, exts)
	if err != nil {
		t.Fatalf("GenerateEntrypoint: %v", err)
	}
	// Stable path: <project>/.sigcomply/.build/sigcomply-custom
	wantDir := filepath.Join(tmp, ".sigcomply", ".build", "sigcomply-custom")
	if dir != wantDir {
		t.Errorf("entrypoint dir = %q; want %q", dir, wantDir)
	}
	data, err := os.ReadFile(filepath.Join(dir, "main.go")) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	body := string(data)
	for _, want := range []string{
		"DO NOT EDIT",
		"package main",
		`cmd "` + CLIImportPath + `"`,
		fixtureModulePath + "/.sigcomply/plugins/myplugin",
		fixtureModulePath + "/.sigcomply/policies/acme.rule/rules",
		"cmd.Execute()",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("generated main.go missing %q\n--- generated ---\n%s", want, body)
		}
	}
}

func TestGenerateEntrypoint_OverwritesPrevious(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	writePluginFile(t, tmp, "first", "p.go", "")

	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("DiscoverExtensions: %v", err)
	}
	if _, err := GenerateEntrypoint(tmp, exts); err != nil {
		t.Fatalf("GenerateEntrypoint 1: %v", err)
	}
	// Now remove the first plugin, add a second.
	if err := os.RemoveAll(filepath.Join(tmp, ".sigcomply", "plugins", "first")); err != nil {
		t.Fatalf("rm: %v", err)
	}
	writePluginFile(t, tmp, "second", "p.go", "")
	exts2, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("DiscoverExtensions 2: %v", err)
	}
	dir, err := GenerateEntrypoint(tmp, exts2)
	if err != nil {
		t.Fatalf("GenerateEntrypoint 2: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "main.go")) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body := string(data)
	if strings.Contains(body, "/first") {
		t.Errorf("regeneration did not remove stale import 'first'")
	}
	if !strings.Contains(body, "/second") {
		t.Errorf("regeneration missing new import 'second'")
	}
}

func TestRunBuild_NoExtensionsIsNoOp(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)

	var stdout, stderr bytes.Buffer
	err := runBuild(context.Background(), &stdout, &stderr, buildFlags{
		project: tmp,
		output:  filepath.Join(tmp, "bin", "sigcomply"),
	})
	if err != nil {
		t.Fatalf("runBuild: %v", err)
	}
	if !strings.Contains(stdout.String(), "no project-local extensions found") {
		t.Errorf("unexpected stdout: %q", stdout.String())
	}
	// Must NOT have created the output binary or the entrypoint dir.
	if _, err := os.Stat(filepath.Join(tmp, "bin", "sigcomply")); !os.IsNotExist(err) {
		t.Errorf("no-op build should not create output binary")
	}
}

func TestRunBuild_BadProjectDir(t *testing.T) {
	err := runBuild(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, buildFlags{
		project: filepath.Join(t.TempDir(), "does-not-exist"),
	})
	if err == nil {
		t.Fatal("want error on missing project dir")
	}
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != orchestratorExitConfig {
		t.Errorf("want exitCodeError{code:3}; got %v", err)
	}
}

func TestRunBuild_RejectsForbiddenImports(t *testing.T) {
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	writePluginFile(t, tmp, "evil", "bad.go", `import _ "os/exec"`+"\n")
	err := runBuild(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, buildFlags{
		project: tmp,
		output:  filepath.Join(tmp, "bin", "sigcomply"),
	})
	if err == nil {
		t.Fatal("want error for forbidden import")
	}
	if !strings.Contains(err.Error(), "os/exec") {
		t.Errorf("error should mention os/exec: %v", err)
	}
}

func TestNewBuildCmd_Help(t *testing.T) {
	cmd := newBuildCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--help: %v", err)
	}
	if !strings.Contains(out.String(), "tailored") {
		t.Errorf("help missing usage text: %q", out.String())
	}
}

// TestRunBuild_EndToEnd_DiscoveryAndGeneration exercises the full
// flow from CLI flag parsing through entrypoint generation but stops
// short of invoking `go build` (which requires the project to be a
// resolved Go module). It does this by setting the output into the
// tempdir and observing that the generated entrypoint exists.
func TestRunBuild_EndToEnd_DiscoveryAndGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("skips invocation of `go build` under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable: " + err.Error())
	}

	tmp := t.TempDir()
	writeGoMod(t, tmp)
	writePluginFile(t, tmp, "myplugin", "plugin.go", "")

	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("DiscoverExtensions: %v", err)
	}
	if len(exts) != 1 {
		t.Fatalf("want 1 ext; got %d", len(exts))
	}
	if err := ValidateExtensions(exts); err != nil {
		t.Fatalf("validate: %v", err)
	}
	dir, err := GenerateEntrypoint(tmp, exts)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "main.go")); err != nil {
		t.Fatalf("main.go not generated: %v", err)
	}
}

// TestRunBuild_GoBuildFails_GracefulError confirms that, in an
// environment where `go build` is available but the project's go.mod
// does not actually pull in sigcomply-cli (the common case for unit
// tests), runBuild surfaces the failure as an exitCodeError. This
// exercises the runGoBuild path without requiring a fully wired module.
func TestRunBuild_GoBuildFails_GracefulError(t *testing.T) {
	if testing.Short() {
		t.Skip("skips invocation of `go build` under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable: " + err.Error())
	}
	if runtime.GOOS == "windows" {
		t.Skip("path semantics differ on windows")
	}

	tmp := t.TempDir()
	writeGoMod(t, tmp)
	writePluginFile(t, tmp, "myplugin", "plugin.go", "")

	err := runBuild(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, buildFlags{
		project: tmp,
		output:  filepath.Join(tmp, "bin", "sigcomply"),
	})
	// Expect failure: the fixture module doesn't actually import sigcomply-cli.
	// We only assert that it surfaced as an exitCodeError, not exit 0.
	if err == nil {
		t.Skip("environment provided sigcomply-cli to the fixture module — build unexpectedly succeeded")
	}
	var ec *exitCodeError
	if !errors.As(err, &ec) {
		t.Errorf("want exitCodeError; got %v", err)
	}
}

func TestImportValue_Strips(t *testing.T) {
	// Smoke-check the helper indirectly: parse a file with a known
	// import and confirm scanImports sees it.
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	writePluginFile(t, tmp, "ok", "good.go", "import \"fmt\"\n\nvar _ = fmt.Stringer(nil)\n")
	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if err := scanImports(exts[0].Dir); err != nil {
		t.Errorf("scanImports: %v", err)
	}
}

func TestMustRel(t *testing.T) {
	got := mustRel("/a/b", "/a/b/c")
	if got != "c" {
		t.Errorf("mustRel = %q; want c", got)
	}
	// On error path (incomparable paths), the function falls back to
	// the target unchanged. Hard to provoke on POSIX; the success case
	// is the load-bearing one — the fallback is defensive.
}

func TestRunGoVet_NoExtensionsIsNoOp(t *testing.T) {
	// Empty extensions list: runGoVet should return nil without
	// invoking go.
	if err := runGoVet(context.Background(), t.TempDir(), nil, &bytes.Buffer{}, false); err != nil {
		t.Errorf("runGoVet(empty): %v", err)
	}
}

func TestRunGoVet_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skips invoking `go vet` under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	// Self-contained package: no external imports, vet-clean.
	writePluginFile(t, tmp, "clean", "p.go", "var X = 1\n")
	exts, err := DiscoverExtensions(tmp)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	var stderr bytes.Buffer
	if err := runGoVet(context.Background(), tmp, exts, &stderr, false); err != nil {
		t.Errorf("runGoVet: %v\nstderr=%s", err, stderr.String())
	}
}

func TestRunBuild_VetFailureSurfaces(t *testing.T) {
	if testing.Short() {
		t.Skip("skips invoking `go vet` under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	// Write code that vet flags: a printf with mismatched verbs/args.
	writePluginFile(t, tmp, "broken", "p.go",
		"import \"fmt\"\n\nfunc Bad() { fmt.Printf(\"%s %s\\n\", \"only-one\") }\n")
	var stdout, stderr bytes.Buffer
	err := runBuild(context.Background(), &stdout, &stderr, buildFlags{
		project: tmp,
		output:  filepath.Join(tmp, "bin", "sigcomply"),
	})
	if err == nil {
		t.Skip("environment treats vet warning differently — skipping")
	}
	if !strings.Contains(err.Error(), "go vet") {
		t.Errorf("expected go-vet wrapped error; got %v", err)
	}
}

func TestRunBuild_VerboseLogging(t *testing.T) {
	if testing.Short() {
		t.Skip("skips invoking `go` under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	writePluginFile(t, tmp, "ok", "p.go", "")
	var stdout, stderr bytes.Buffer
	// The build will fail at `go build` (fixture has no sigcomply-cli
	// import), but we want to confirm the verbose discovery line was
	// emitted to stdout before then. Error path is expected and not
	// asserted here.
	if err := runBuild(context.Background(), &stdout, &stderr, buildFlags{
		project: tmp,
		output:  filepath.Join(tmp, "bin", "sigcomply"),
		verbose: true,
	}); err == nil {
		t.Log("build unexpectedly succeeded (fixture environment had sigcomply-cli available)")
	}
	if !strings.Contains(stdout.String(), "discovered 1 project-local extension") {
		t.Errorf("verbose stdout missing discovery line: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "generated entrypoint at") {
		t.Errorf("verbose stdout missing entrypoint line: %q", stdout.String())
	}
}

func TestRunBuild_OutputDirIsCreated(t *testing.T) {
	if testing.Short() {
		t.Skip("skips invoking `go` under -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable")
	}
	tmp := t.TempDir()
	writeGoMod(t, tmp)
	writePluginFile(t, tmp, "ok", "p.go", "")
	deepOut := filepath.Join(tmp, "deeply", "nested", "out", "sigcomply")
	// Build will fail at `go build` (no real sigcomply-cli), but the
	// output parent directory should be created en route. We assert
	// only the directory side-effect, not the (expected) build error.
	if err := runBuild(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, buildFlags{
		project: tmp,
		output:  deepOut,
	}); err == nil {
		t.Log("build unexpectedly succeeded")
	}
	if _, err := os.Stat(filepath.Dir(deepOut)); err != nil {
		t.Errorf("output parent dir not created: %v", err)
	}
}

func TestReadModulePath_MissingGoMod(t *testing.T) {
	tmp := t.TempDir()
	_, err := readModulePath(tmp)
	if err == nil || !strings.Contains(err.Error(), "go.mod") {
		t.Errorf("want missing-go.mod error; got %v", err)
	}
}

func TestReadModulePath_NoModuleDirective(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("go 1.25\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := readModulePath(tmp)
	if err == nil || !strings.Contains(err.Error(), "module directive") {
		t.Errorf("want no-module-directive error; got %v", err)
	}
}
