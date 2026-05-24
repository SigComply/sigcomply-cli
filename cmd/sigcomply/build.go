package cmd

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
)

// CLIImportPath is the import path of the shipped CLI command package.
// The generated entrypoint imports it for side-effect command
// registration and then calls cmd.Execute().
const CLIImportPath = "github.com/sigcomply/sigcomply-cli/cmd/sigcomply"

// buildFlags collects flags for `sigcomply build`. Keep this narrow:
// project-tailored binary builds are a customer-facing operation that
// should be predictable; extra knobs grow into combinatorial test
// surface area. See docs/architecture/07-extensibility.md.
type buildFlags struct {
	project string
	output  string
	tags    string
	ldflags string
	verbose bool
}

// forbiddenImports are the packages a project-local Go extension is
// not allowed to import in v1. These are the "outside-the-binary"
// edges — anything that can phone home or spawn subprocesses. The
// CLI's in-tree plugins reach the same APIs by going through curated
// internal/ packages; project-local code does not get that escape
// hatch in v1. v2 may add a sandboxed/WASM path that relaxes this.
var forbiddenImports = map[string]string{
	"os/exec": "spawning subprocesses bypasses the in-process security boundary",
}

// forbiddenImportPrefixes covers entire subtrees that are disallowed.
// "net/" catches net, net/http, net/http/httptest, net/url, etc. —
// project-local code in v1 must not reach the network directly.
var forbiddenImportPrefixes = []string{
	"net",
	"net/",
}

// newBuildCmd wires `sigcomply build` — the project-local Go-extension
// build wrapper. See docs/architecture/07-extensibility.md §Loading
// mechanism for project-local Go code.
func newBuildCmd() *cobra.Command {
	var flags buildFlags
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Compile a project-tailored sigcomply binary with .sigcomply/ Go extensions",
		Long: "`sigcomply build` discovers Go-based extensions under the project's `.sigcomply/`\n" +
			"directory (plugins, rule packages, evidence types), validates their imports\n" +
			"against the v1 security boundary, and compiles a tailored binary that registers\n" +
			"those extensions at startup alongside the shipped in-tree set.\n\n" +
			"If no Go extensions are present, the command is a no-op — the shipped binary\n" +
			"already covers Rego-only and YAML-DSL projects.\n",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBuild(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), flags)
		},
	}
	cmd.Flags().StringVar(&flags.project, "project", ".", "Project directory (the one containing .sigcomply/)")
	cmd.Flags().StringVar(&flags.output, "output", "./bin/sigcomply", "Output binary path")
	cmd.Flags().StringVar(&flags.tags, "tags", "", "Go build tags (comma-separated)")
	cmd.Flags().StringVar(&flags.ldflags, "ldflags", "", "Passthrough -ldflags to go build")
	cmd.Flags().BoolVarP(&flags.verbose, "verbose", "v", false, "Verbose output")
	return cmd
}

// runBuild is the testable entrypoint: stdout for human messages,
// stderr for go-tool output. Returning an error always bubbles up as
// exit code 2 via cobra; for configuration mistakes we wrap in
// exitCodeError{code:3} to mirror runCheck.
func runBuild(ctx context.Context, stdout, stderr io.Writer, flags buildFlags) error {
	projectAbs, err := filepath.Abs(flags.project)
	if err != nil {
		return &exitCodeError{code: orchestratorExitConfig, err: fmt.Errorf("resolve project dir: %w", err)}
	}
	if info, err := os.Stat(projectAbs); err != nil || !info.IsDir() {
		return &exitCodeError{code: orchestratorExitConfig, err: fmt.Errorf("project dir %q does not exist", projectAbs)}
	}

	exts, err := DiscoverExtensions(projectAbs)
	if err != nil {
		return &exitCodeError{code: orchestratorExitConfig, err: err}
	}
	if len(exts) == 0 {
		_, _ = fmt.Fprintln(stdout, "no project-local extensions found; the shipped CLI already includes the in-tree set") //nolint:errcheck // status output: nothing useful to do on stdout write failure
		return nil
	}

	if flags.verbose {
		_, _ = fmt.Fprintf(stdout, "discovered %d project-local extension package(s):\n", len(exts)) //nolint:errcheck // status output: nothing useful to do on stdout write failure
		for _, e := range exts {
			_, _ = fmt.Fprintf(stdout, "  - %s (%s) %s\n", e.ImportPath, e.Kind, e.Dir) //nolint:errcheck // status output: nothing useful to do on stdout write failure
		}
	}

	if err := ValidateExtensions(exts); err != nil {
		return &exitCodeError{code: orchestratorExitConfig, err: err}
	}

	if err := runGoVet(ctx, projectAbs, exts, stderr, flags.verbose); err != nil {
		return &exitCodeError{code: orchestratorExitConfig, err: fmt.Errorf("go vet: %w", err)}
	}

	entrypointDir, err := GenerateEntrypoint(projectAbs, exts)
	if err != nil {
		return &exitCodeError{code: orchestratorExitExecution, err: fmt.Errorf("generate entrypoint: %w", err)}
	}
	if flags.verbose {
		_, _ = fmt.Fprintf(stdout, "generated entrypoint at %s\n", entrypointDir) //nolint:errcheck // status output: nothing useful to do on stdout write failure
	}

	outAbs, err := filepath.Abs(flags.output)
	if err != nil {
		return &exitCodeError{code: orchestratorExitConfig, err: fmt.Errorf("resolve output: %w", err)}
	}
	if err := os.MkdirAll(filepath.Dir(outAbs), 0o750); err != nil {
		return &exitCodeError{code: orchestratorExitExecution, err: fmt.Errorf("create output dir: %w", err)}
	}

	if err := runGoBuild(ctx, projectAbs, entrypointDir, outAbs, flags, stderr); err != nil {
		return &exitCodeError{code: orchestratorExitExecution, err: fmt.Errorf("go build: %w", err)}
	}

	_, _ = fmt.Fprintf(stdout, "built %s with %d project-local extension(s)\n", outAbs, len(exts)) //nolint:errcheck // status output: nothing useful to do on stdout write failure
	return nil
}

// orchestratorExitConfig and orchestratorExitExecution mirror the
// orchestrator package's exit codes without importing it (avoids
// pulling the whole orchestrator into the build path). Keep these in
// lockstep with internal/orchestrator.Exit*.
const (
	orchestratorExitConfig    = 3
	orchestratorExitExecution = 2
)

// ExtensionKind tags what role a project-local Go package plays.
type ExtensionKind string

// Extension kinds recognized by the build wrapper.
const (
	ExtensionKindPlugin       ExtensionKind = "plugin"
	ExtensionKindRule         ExtensionKind = "rule"
	ExtensionKindEvidenceType ExtensionKind = "evidence_type"
)

// Extension is a discovered project-local Go package eligible for
// inclusion in the project-tailored binary. ImportPath is what the
// generated entrypoint will blank-import for side-effect registration.
type Extension struct {
	Kind        ExtensionKind
	Name        string // directory basename (also expected package name)
	Dir         string // absolute path to the package directory
	ImportPath  string // module-rooted import path
	PackageName string // declared `package X` name
}

// DiscoverExtensions walks the project's .sigcomply/ tree and returns
// every Go package found under the three supported subtrees. Returns
// nil with no error when the project has no extensions — the build
// wrapper treats that as a graceful no-op.
func DiscoverExtensions(projectDir string) ([]Extension, error) {
	root := filepath.Join(projectDir, ".sigcomply")
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat .sigcomply: %w", err)
	}
	modulePath, err := readModulePath(projectDir)
	if err != nil {
		return nil, err
	}

	var found []Extension
	more, err := discoverPlugins(root, modulePath, projectDir)
	if err != nil {
		return nil, err
	}
	found = append(found, more...)
	more, err = discoverRules(root, modulePath, projectDir)
	if err != nil {
		return nil, err
	}
	found = append(found, more...)
	more, err = discoverEvidenceTypes(root, modulePath, projectDir)
	if err != nil {
		return nil, err
	}
	found = append(found, more...)

	sort.Slice(found, func(i, j int) bool { return found[i].ImportPath < found[j].ImportPath })
	return found, nil
}

// discoverPlugins finds packages under .sigcomply/plugins/<name>/.
func discoverPlugins(root, modulePath, projectDir string) ([]Extension, error) {
	return discoverInSubdirs(filepath.Join(root, "plugins"), ExtensionKindPlugin, modulePath, projectDir, "")
}

// discoverRules finds packages under .sigcomply/policies/<name>/rules/.
func discoverRules(root, modulePath, projectDir string) ([]Extension, error) {
	return discoverInSubdirs(filepath.Join(root, "policies"), ExtensionKindRule, modulePath, projectDir, "rules")
}

// discoverEvidenceTypes finds packages under .sigcomply/evidence_types/.
// Supports both per-type subdirs and the flat layout where the
// evidence_types/ directory is itself a Go package.
func discoverEvidenceTypes(root, modulePath, projectDir string) ([]Extension, error) {
	etRoot := filepath.Join(root, "evidence_types")
	out, err := discoverInSubdirs(etRoot, ExtensionKindEvidenceType, modulePath, projectDir, "")
	if err != nil {
		return nil, err
	}
	ext, ok, err := classifyDir(etRoot, ExtensionKindEvidenceType, modulePath, projectDir)
	if err != nil {
		return nil, err
	}
	if ok {
		out = append(out, ext)
	}
	return out, nil
}

// discoverInSubdirs lists immediate subdirs of root and classifies each
// (optionally descending into a fixed `subdir` first — used for the
// `policies/<name>/rules/` layout). Missing roots are not errors —
// discovery is best-effort.
func discoverInSubdirs(root string, kind ExtensionKind, modulePath, projectDir, subdir string) ([]Extension, error) {
	subs, err := listSubdirs(root)
	if err != nil {
		return nil, err
	}
	var out []Extension
	for _, d := range subs {
		target := d
		if subdir != "" {
			target = filepath.Join(d, subdir)
		}
		ext, ok, err := classifyDir(target, kind, modulePath, projectDir)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, ext)
		}
	}
	return out, nil
}

// classifyDir checks whether dir holds a Go package and, if so,
// returns an Extension. A "package" here means: at least one non-test
// .go file whose `package X` declaration matches the directory's
// basename. That naming rule keeps the generated entrypoint readable
// and aligns with the worked examples in docs/architecture/07-extensibility.md.
func classifyDir(dir string, kind ExtensionKind, modulePath, projectDir string) (Extension, bool, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return Extension{}, false, nil
		}
		return Extension{}, false, fmt.Errorf("stat %s: %w", dir, err)
	}
	if !info.IsDir() {
		return Extension{}, false, nil
	}
	pkgName, hasGo, err := readPackageName(dir)
	if err != nil {
		return Extension{}, false, err
	}
	if !hasGo {
		return Extension{}, false, nil
	}
	base := filepath.Base(dir)
	expected := sanitizePackageName(base)
	if pkgName != expected {
		return Extension{}, false, fmt.Errorf("%s: package name %q does not match directory %q (expected %q)", dir, pkgName, base, expected)
	}
	rel, err := filepath.Rel(projectDir, dir)
	if err != nil {
		return Extension{}, false, fmt.Errorf("rel %s: %w", dir, err)
	}
	importPath := modulePath + "/" + filepath.ToSlash(rel)
	return Extension{
		Kind:        kind,
		Name:        base,
		Dir:         dir,
		ImportPath:  importPath,
		PackageName: pkgName,
	}, true, nil
}

// listSubdirs returns the immediate subdirectories of dir. Returns nil
// (not an error) when dir is missing — discovery is best-effort.
func listSubdirs(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("readdir %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out, nil
}

// readPackageName parses the first non-test .go file in dir to get its
// `package X` name. Returns (name, true, nil) when a Go file is found,
// ("", false, nil) when the dir holds no Go source.
func readPackageName(dir string) (name string, found bool, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false, fmt.Errorf("readdir %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.PackageClauseOnly)
		if err != nil {
			return "", false, fmt.Errorf("parse %s: %w", path, err)
		}
		return f.Name.Name, true, nil
	}
	return "", false, nil
}

// sanitizePackageName converts a directory basename to its expected Go
// package identifier: lowercase, dots and dashes replaced with
// underscores. Matches the convention in docs/architecture/07-extensibility.md
// (e.g., `acme.internal_iam/` declares `package acme_internal_iam`).
func sanitizePackageName(s string) string {
	r := strings.NewReplacer(".", "_", "-", "_")
	return r.Replace(s)
}

// ValidateExtensions enforces the v1 security boundary: project-local
// extensions cannot import the network or os/exec. Uses go/parser to
// walk every import in every .go file (excluding _test.go).
func ValidateExtensions(exts []Extension) error {
	for _, e := range exts {
		if err := scanImports(e.Dir); err != nil {
			return fmt.Errorf("%s: %w", e.ImportPath, err)
		}
	}
	return nil
}

func scanImports(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("readdir %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for _, imp := range f.Imports {
			p := importValue(imp)
			if reason, banned := forbiddenImports[p]; banned {
				return fmt.Errorf("%s imports forbidden package %q (%s)", path, p, reason)
			}
			for _, prefix := range forbiddenImportPrefixes {
				if p == strings.TrimSuffix(prefix, "/") || (strings.HasSuffix(prefix, "/") && strings.HasPrefix(p, prefix)) {
					return fmt.Errorf("%s imports forbidden package %q (network access is not permitted from project-local extensions in v1)", path, p)
				}
			}
		}
	}
	return nil
}

func importValue(imp *ast.ImportSpec) string {
	v := imp.Path.Value
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}

// readModulePath returns the module path declared in projectDir/go.mod.
// Returns an error if go.mod is missing or malformed — a project that
// has .sigcomply/ Go extensions but no go.mod can't possibly compile.
func readModulePath(projectDir string) (string, error) {
	modFile := filepath.Join(projectDir, "go.mod")
	data, err := os.ReadFile(modFile) //nolint:gosec // explicit project-local path
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("project go.mod not found at %s (project-local Go extensions require a Go module)", modFile)
		}
		return "", fmt.Errorf("read %s: %w", modFile, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "module "); ok {
			return strings.TrimSpace(after), nil
		}
	}
	return "", fmt.Errorf("module directive not found in %s", modFile)
}

// entrypointTemplate is the deterministic shape of the generated
// main.go. Easy to debug: one import per discovered extension, a
// single call to cmd.Execute(). Keep this template tight and stable.
const entrypointTemplate = `// Code generated by sigcomply build. DO NOT EDIT.
//
// This file is regenerated on every ` + "`sigcomply build`" + ` invocation. It
// imports the shipped CLI command package and every discovered
// project-local extension for side-effect registration.
package main

import (
	"os"

	cmd "{{ .CLIImport }}"
{{- range .Extensions }}
	_ "{{ .ImportPath }}" // {{ .Kind }}: {{ .Name }}
{{- end }}
)

func main() {
	os.Exit(cmd.Execute())
}
`

type entrypointData struct {
	CLIImport  string
	Extensions []Extension
}

// GenerateEntrypoint writes the project-tailored main.go to a stable
// scratch location inside the project's .sigcomply/.build/ tree. The
// path is deterministic so failed builds are easy to inspect; the
// directory is meant to be gitignored alongside `bin/`.
func GenerateEntrypoint(projectDir string, exts []Extension) (string, error) {
	dir := filepath.Join(projectDir, ".sigcomply", ".build", "sigcomply-custom")
	if err := os.RemoveAll(dir); err != nil {
		return "", fmt.Errorf("clean %s: %w", dir, err)
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmpl, err := template.New("entrypoint").Parse(entrypointTemplate)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}
	f, err := os.Create(filepath.Join(dir, "main.go")) //nolint:gosec // generated under project-controlled path
	if err != nil {
		return "", fmt.Errorf("create main.go: %w", err)
	}
	defer func() { _ = f.Close() }() //nolint:errcheck // best-effort
	if err := tmpl.Execute(f, entrypointData{CLIImport: CLIImportPath, Extensions: exts}); err != nil {
		return "", fmt.Errorf("render template: %w", err)
	}
	return dir, nil
}

// runGoVet runs `go vet` against the discovered extension packages.
// Surfacing vet failures before the build saves the customer a slow
// compile cycle on errors a quick parse can catch.
func runGoVet(ctx context.Context, projectDir string, exts []Extension, stderr io.Writer, verbose bool) error {
	if len(exts) == 0 {
		return nil
	}
	args := []string{"vet"}
	for _, e := range exts {
		args = append(args, "./"+filepath.ToSlash(mustRel(projectDir, e.Dir)))
	}
	cmd := exec.CommandContext(ctx, "go", args...) //nolint:gosec // args are derived from validated project paths
	cmd.Dir = projectDir
	cmd.Stderr = stderr
	if verbose {
		cmd.Stdout = stderr
	}
	return cmd.Run()
}

// runGoBuild compiles the generated entrypoint into outPath. The build
// runs from projectDir so the generated main.go resolves its imports
// through the project's go.mod (which must depend on sigcomply-cli).
func runGoBuild(ctx context.Context, projectDir, entrypointDir, outPath string, flags buildFlags, stderr io.Writer) error {
	rel, err := filepath.Rel(projectDir, entrypointDir)
	if err != nil {
		return fmt.Errorf("rel %s: %w", entrypointDir, err)
	}
	args := []string{"build", "-o", outPath}
	if flags.tags != "" {
		args = append(args, "-tags", flags.tags)
	}
	if flags.ldflags != "" {
		args = append(args, "-ldflags", flags.ldflags)
	}
	args = append(args, "./"+filepath.ToSlash(rel))

	cmd := exec.CommandContext(ctx, "go", args...) //nolint:gosec // args are derived from validated project paths
	cmd.Dir = projectDir
	cmd.Stderr = stderr
	if flags.verbose {
		cmd.Stdout = stderr
	}
	return cmd.Run()
}

func mustRel(base, target string) string {
	r, err := filepath.Rel(base, target)
	if err != nil {
		return target
	}
	return r
}
