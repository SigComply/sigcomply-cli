package orchestrator

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// registerProjectLocal discovers and registers DATA-driven project-local
// extensions from the .sigcomply/ tree next to the project config —
// evidence-type JSON schemas, Rego rules, and YAML policies. These need
// no recompile (unlike the Go plugins/rules/types wired by `sigcomply
// build`): they load at every `sigcomply check`/`report` bootstrap.
//
// This is the runtime counterpart to `sigcomply build`. build handles
// Go extensions (compiled in); this handles the data-only ones the
// extensibility design promised but that previously had no loader:
//
//	.sigcomply/evidence_types/*.json         → set.EvidenceTypes
//	.sigcomply/policies/<id>/rule.rego       → set.Rules (OPA-backed)
//	.sigcomply/policies/<id>/policy.yaml     → set.Policies (+ cfg refs)
//
// Discovery is best-effort on a missing .sigcomply/ tree (no error);
// malformed content is a configuration error (exit 3) so a typo never
// silently drops a customer's control. Ordering — types, then rules,
// then policies — mirrors Bootstrap: types underpin slot validation and
// rules are referenced by policies' rule: field.
func registerProjectLocal(projectDir string, cfg *spec.ProjectConfig, set *registry.Set) error {
	root := filepath.Join(projectDir, ".sigcomply")
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("project-local: stat .sigcomply: %w", err)
	}
	if err := loadProjectEvidenceTypes(filepath.Join(root, "evidence_types"), set); err != nil {
		return err
	}
	if err := loadProjectRules(filepath.Join(root, "policies"), set); err != nil {
		return err
	}
	return loadProjectPolicies(filepath.Join(root, "policies"), cfg, set)
}

// loadProjectEvidenceTypes registers every *.json schema directly under
// evidence_types/. Per-type Go packages (subdirectories, compiled in by
// `sigcomply build`) are ignored here — this path is for the data-only
// JSON schemas documented at .sigcomply/evidence_types/<id>.v<n>.json.
func loadProjectEvidenceTypes(dir string, set *registry.Set) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("project-local: read evidence_types: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names) // deterministic failure ordering
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path) //nolint:gosec // explicit project-local path under .sigcomply/
		if err != nil {
			return fmt.Errorf("project-local: read %s: %w", path, err)
		}
		et, err := spec.LoadEvidenceType(data)
		if err != nil {
			return fmt.Errorf("project-local: load evidence type %s: %w", path, err)
		}
		if err := set.EvidenceTypes.Register(et); err != nil {
			return fmt.Errorf("project-local: register evidence type %s: %w", path, err)
		}
	}
	return nil
}

// loadProjectRules registers a Rego rule for every
// .sigcomply/policies/<id>/rule.rego. The rule's identity is intrinsic
// to the module: the Rego `package` path is both the registered rule ID
// (what a policy.yaml's `rule:` field references) and the query base —
// the module must expose a `result` document, so the query is
// `data.<package>.result`. This matches the existing RegoRule contract
// (result.status string + optional violations[]).
func loadProjectRules(policiesDir string, set *registry.Set) error {
	subs, err := listPolicyDirs(policiesDir)
	if err != nil {
		return err
	}
	for _, dir := range subs {
		path := filepath.Join(dir, "rule.rego")
		data, err := os.ReadFile(path) //nolint:gosec // explicit project-local path under .sigcomply/
		if err != nil {
			if os.IsNotExist(err) {
				continue // a policy dir may be pass_when-only, with no Rego rule
			}
			return fmt.Errorf("project-local: read %s: %w", path, err)
		}
		pkg, err := regoPackage(data)
		if err != nil {
			return fmt.Errorf("project-local: %s: %w", path, err)
		}
		query := "data." + pkg + ".result"
		rule, err := evaluator.NewRegoRule(pkg, string(data), query)
		if err != nil {
			return fmt.Errorf("project-local: compile rego rule %s: %w", path, err)
		}
		if err := set.Rules.Register(rule); err != nil {
			return fmt.Errorf("project-local: register rego rule %s (package %q): %w", path, pkg, err)
		}
	}
	return nil
}

// loadProjectPolicies registers a core.Policy for every
// .sigcomply/policies/<id>/policy.yaml and records its PolicyRef on cfg
// so the planner enumerates it alongside the framework's own policies
// (one project = one framework, so every project-local policy belongs
// to the active framework).
func loadProjectPolicies(policiesDir string, cfg *spec.ProjectConfig, set *registry.Set) error {
	subs, err := listPolicyDirs(policiesDir)
	if err != nil {
		return err
	}
	for _, dir := range subs {
		path := filepath.Join(dir, "policy.yaml")
		data, err := os.ReadFile(path) //nolint:gosec // explicit project-local path under .sigcomply/
		if err != nil {
			if os.IsNotExist(err) {
				continue // a dir may hold only a rule.rego (referenced by a framework policy)
			}
			return fmt.Errorf("project-local: read %s: %w", path, err)
		}
		pol, err := spec.LoadPolicy(data)
		if err != nil {
			return fmt.Errorf("project-local: load policy %s: %w", path, err)
		}
		if err := set.Policies.Register(pol); err != nil {
			return fmt.Errorf("project-local: register policy %s: %w", path, err)
		}
		cfg.ProjectLocalPolicies = append(cfg.ProjectLocalPolicies, core.PolicyRef{PolicyID: pol.ID})
	}
	return nil
}

// listPolicyDirs returns the sorted immediate subdirectories of
// policies/ (the per-policy directories). Missing policies/ is not an
// error — discovery is best-effort.
func listPolicyDirs(policiesDir string) ([]string, error) {
	entries, err := os.ReadDir(policiesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("project-local: read policies: %w", err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, filepath.Join(policiesDir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// regoPackage extracts the package path from a Rego module, e.g.
// "package sigcomply.rules.acme_v1" → "sigcomply.rules.acme_v1". It
// scans for the first non-comment, non-blank line, which Rego requires
// to be the package declaration.
func regoPackage(data []byte) (string, error) {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if pkg, ok := strings.CutPrefix(line, "package "); ok {
			pkg = strings.TrimSpace(pkg)
			if pkg == "" {
				return "", fmt.Errorf("empty Rego package declaration")
			}
			return pkg, nil
		}
		return "", fmt.Errorf("first non-comment line is not a package declaration: %q", line)
	}
	return "", fmt.Errorf("no Rego package declaration found")
}
