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
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	If          string            `yaml:"if"`
	Needs       stringList        `yaml:"needs"`
	Uses        string            `yaml:"uses"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []workflowStep    `yaml:"steps"`
}

type workflowStep struct {
	Run string            `yaml:"run"`
	Env map[string]string `yaml:"env"`
}

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

func (j *workflowJob) publishes() bool {
	for _, s := range j.Steps {
		if strings.Contains(s.Run, publishScript) {
			return true
		}
	}
	return false
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
	for name, wf := range all {
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
			if !strings.Contains(j.If, releaseRefGuard) {
				t.Errorf("%s: job %q can release but its `if` lacks the ref guard %s (got %q)",
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
