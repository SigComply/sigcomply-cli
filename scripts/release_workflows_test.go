package scripts_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// releaseRefGuard is the condition every privileged release job carries,
// so a release is cut only from main, or from an existing v* tag (the
// documented re-release path in release.yml). A workflow_dispatch from any
// other branch skips the release.
const releaseRefGuard = "(github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v'))"

// The workflow files a release involves are found by what they do, not by
// name, so a new release workflow is held to the same rules.
const (
	promoteWorkflow  = "./.github/workflows/release-promote.yml"
	pipelineWorkflow = "./.github/workflows/auto-release-pipeline.yml"
	publishScript    = "scripts/publish-release.sh"
)

type workflowFile struct {
	On   yaml.Node              `yaml:"on"`
	Jobs map[string]workflowJob `yaml:"jobs"`
}

// reusableOnly reports whether the workflow runs only when another
// workflow calls it. Its jobs run with the caller's ref, and the calling
// job is held to the ref guard, so they are not checked on their own.
func (w *workflowFile) reusableOnly() bool {
	const call = "workflow_call"
	switch w.On.Kind {
	case yaml.ScalarNode:
		return w.On.Value == call
	case yaml.MappingNode:
		return len(w.On.Content) == 2 && w.On.Content[0].Value == call
	case yaml.SequenceNode:
		return len(w.On.Content) == 1 && w.On.Content[0].Value == call
	}
	return false
}

type workflowJob struct {
	If          string            `yaml:"if"`
	Needs       stringList        `yaml:"needs"`
	Uses        string            `yaml:"uses"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []workflowStep    `yaml:"steps"`
}

type workflowStep struct {
	Run  string            `yaml:"run"`
	Uses string            `yaml:"uses"`
	Env  map[string]string `yaml:"env"`
}

// releaseActions are third-party actions that create or publish a
// GitHub release.
var releaseActions = []string{"goreleaser/goreleaser-action", "softprops/action-gh-release", "ncipollo/release-action", "actions/create-release"}

// stringList accepts `needs: a` and `needs: [a, b]`.
type stringList []string

func (s *stringList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*s = []string{n.Value}
		return nil
	}
	var list []string
	if err := n.Decode(&list); err != nil {
		return err
	}
	*s = list
	return nil
}

func loadWorkflows(t *testing.T) map[string]workflowFile {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no workflow files found")
	}
	out := map[string]workflowFile{}
	for _, p := range paths {
		data, err := os.ReadFile(p) //nolint:gosec // #nosec G304 -- repository workflow files
		if err != nil {
			t.Fatal(err)
		}
		var wf workflowFile
		if err := yaml.Unmarshal(data, &wf); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out[filepath.Base(p)] = wf
	}
	return out
}

// publishes: the job can create, edit or publish a release: it runs the
// publish script or `gh release`, uses a release action, or can write
// repository contents (tags and releases).
func (j *workflowJob) publishes() bool {
	if j.Permissions["contents"] == "write" {
		return true
	}
	for _, s := range j.Steps {
		if strings.Contains(s.Run, publishScript) || strings.Contains(s.Run, "gh release") {
			return true
		}
		for _, a := range releaseActions {
			if strings.HasPrefix(s.Uses, a+"@") {
				return true
			}
		}
	}
	return false
}

// guarded reports whether cond is the ref guard, alone or joined to more
// conditions with a top-level "&&". A top-level "||" next to it would let
// the job run from any ref.
func guarded(cond string) bool {
	cond = strings.TrimSpace(cond)
	if cond == releaseRefGuard {
		return true
	}
	var rest string
	switch {
	case strings.HasSuffix(cond, " && "+releaseRefGuard):
		rest = strings.TrimSuffix(cond, " && "+releaseRefGuard)
	case strings.HasPrefix(cond, releaseRefGuard+" && "):
		rest = strings.TrimPrefix(cond, releaseRefGuard+" && ")
	default:
		return false
	}
	depth := 0
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth == 0 && i+1 < len(rest) && rest[i+1] == '|' {
				return false
			}
		}
	}
	return depth == 0
}

// privileged: the job can push a tag, publish or promote a release, or
// sign provenance, directly or through a reusable workflow.
func (j *workflowJob) privileged() bool {
	if j.Uses == promoteWorkflow || j.Uses == pipelineWorkflow || j.publishes() {
		return true
	}
	for _, scope := range []string{"contents", "id-token", "attestations"} {
		if j.Permissions[scope] == "write" {
			return true
		}
	}
	return false
}

// releaseWorkflows are the files that publish, promote or call the
// release pipeline.
func releaseWorkflows(t *testing.T, all map[string]workflowFile) []string {
	t.Helper()
	var names []string
	for name := range all {
		wf := all[name]
		if wf.reusableOnly() && name != filepath.Base(pipelineWorkflow) {
			continue
		}
		for _, j := range wf.Jobs {
			if j.Uses == promoteWorkflow || j.Uses == pipelineWorkflow || j.publishes() {
				names = append(names, name)
				break
			}
		}
	}
	sort.Strings(names)
	// The two entry points and the pipeline must be found, or the rule
	// below checks nothing.
	for _, want := range []string{"release.yml", "auto-release.yml", "auto-release-pipeline.yml"} {
		if !contains(names, want) {
			t.Fatalf("release workflows found: %v; %s is missing (did the detection rules drift?)", names, want)
		}
	}
	return names
}

func TestGuarded(t *testing.T) {
	for cond, want := range map[string]bool{
		releaseRefGuard:                           true,
		"a == 'b' && " + releaseRefGuard:          true,
		releaseRefGuard + " && !contains(x, '-')": true,
		"(a || b) && " + releaseRefGuard:          true,
		"always() || " + releaseRefGuard:          false,
		"a || b && " + releaseRefGuard:            false,
		"x == '" + releaseRefGuard + "'":          false,
		"":                                        false,
		"github.ref == 'refs/heads/main'":         false,
	} {
		if got := guarded(cond); got != want {
			t.Errorf("guarded(%q) = %v; want %v", cond, got, want)
		}
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// TestReleaseWorkflows_PrivilegedJobsRunOnlyFromMainOrTags pins CICD-6:
// a workflow_dispatch of a release workflow from a feature branch must not
// build, sign, tag, publish or promote that branch's code.
func TestReleaseWorkflows_PrivilegedJobsRunOnlyFromMainOrTags(t *testing.T) {
	all := loadWorkflows(t)
	for _, name := range releaseWorkflows(t, all) {
		for id, j := range all[name].Jobs {
			if !j.privileged() {
				continue
			}
			if !guarded(j.If) {
				t.Errorf("%s: job %q can release but its `if` is not the ref guard %s, alone or joined with && (got %q)",
					name, id, releaseRefGuard, j.If)
			}
		}
	}
}

// TestReleaseWorkflows_PromoteNeedsVerifiedInstall pins CICD-6: a release
// is promoted to latest only after install.sh installed it with build
// provenance required, in the same run.
func TestReleaseWorkflows_PromoteNeedsVerifiedInstall(t *testing.T) {
	all := loadWorkflows(t)
	promoters := 0
	for name, wf := range all {
		for id, j := range wf.Jobs {
			if j.Uses != promoteWorkflow {
				continue
			}
			promoters++
			verified := false
			for _, need := range j.Needs {
				if dep, ok := wf.Jobs[need]; ok && installsWithProvenance(&dep) {
					verified = true
				}
			}
			if !verified {
				t.Errorf("%s: job %q promotes a release but none of its needs %v runs scripts/install.sh with SIGCOMPLY_REQUIRE_PROVENANCE=1",
					name, id, j.Needs)
			}
		}
	}
	// release.yml and auto-release-pipeline.yml both promote.
	if promoters < 2 {
		t.Fatalf("found %d jobs calling %s; want at least 2", promoters, promoteWorkflow)
	}
}

func installsWithProvenance(j *workflowJob) bool {
	for _, s := range j.Steps {
		if strings.Contains(s.Run, "scripts/install.sh") && s.Env["SIGCOMPLY_REQUIRE_PROVENANCE"] == "1" {
			return true
		}
	}
	return false
}
