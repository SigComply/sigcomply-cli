package scripts_test

import (
	"os"
	"path/filepath"
	"regexp"
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
	RunsOn      string            `yaml:"runs-on"`
	Needs       stringList        `yaml:"needs"`
	Uses        string            `yaml:"uses"`
	With        map[string]string `yaml:"with"`
	Environment environment       `yaml:"environment"`
	Permissions map[string]string `yaml:"permissions"`
	Steps       []workflowStep    `yaml:"steps"`
}

// environment accepts `environment: name` and `environment: {name: ...}`.
type environment string

func (e *environment) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*e = environment(n.Value)
		return nil
	}
	var m struct {
		Name string `yaml:"name"`
	}
	if err := n.Decode(&m); err != nil {
		return err
	}
	*e = environment(m.Name)
	return nil
}

type workflowStep struct {
	Run   string            `yaml:"run"`
	Shell string            `yaml:"shell"`
	Uses  string            `yaml:"uses"`
	Env   map[string]string `yaml:"env"`
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
	if j.Permissions["contents"] == permWrite {
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
		if j.Permissions[scope] == permWrite {
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
		for id := range wf.Jobs {
			j := wf.Jobs[id]
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

const (
	permWrite       = "write"
	liveWorkflow    = "live-e2e.yml"
	liveEnvironment = "live-e2e"
)

// TestLiveE2E_CloudCredentialsStayInTheProtectedEnvironment pins the
// live tier's trust boundary. The cloud roles trust only this repository's
// live-e2e environment, which allows only main and v* tags; a job that
// mints an OIDC token outside it, or a trigger that runs it on a pull
// request, would hand a fork the fixture accounts.
func TestLiveE2E_CloudCredentialsStayInTheProtectedEnvironment(t *testing.T) {
	all := loadWorkflows(t)
	live, ok := all[liveWorkflow]
	if !ok {
		t.Fatalf("%s not found", liveWorkflow)
	}
	if triggers := triggerNames(&live); strings.Join(triggers, ",") != "workflow_call,workflow_dispatch" {
		t.Errorf("%s triggers = %v; want only workflow_call and workflow_dispatch", liveWorkflow, triggers)
	}

	envJobs := 0
	for id, j := range live.Jobs {
		oidc := j.Permissions["id-token"] == permWrite
		inEnv := j.Environment == liveEnvironment
		if oidc && !inEnv {
			t.Errorf("%s: job %q can mint an OIDC token but does not run in the %s environment", liveWorkflow, id, liveEnvironment)
		}
		if inEnv && !guarded(j.If) {
			t.Errorf("%s: job %q runs in the %s environment without the ref guard %s (got %q)", liveWorkflow, id, liveEnvironment, releaseRefGuard, j.If)
		}
		if inEnv {
			envJobs++
			if !runsLiveTestRequired(&j) {
				t.Errorf("%s: job %q has no step running scripts/run-live-tests.sh '^TestLiveE2E_...' with LIVE_E2E_REQUIRED=1 and SIGCOMPLY_E2E_BINARY; a skipped test would pass the gate",
					liveWorkflow, id)
			}
		}
	}
	// aws, gcp, azure, saas.
	if envJobs < 4 {
		t.Errorf("%s: %d jobs run in the %s environment; want the four provider jobs", liveWorkflow, envJobs, liveEnvironment)
	}

	for name, wf := range all {
		for id, j := range wf.Jobs {
			if j.Environment == liveEnvironment && name != liveWorkflow {
				t.Errorf("%s: job %q uses the %s environment; only %s may", name, id, liveEnvironment, liveWorkflow)
			}
		}
	}
}

// TestLiveE2E_DispatchFromOtherRefFails: a dispatch from another branch
// skips every guarded job, so resolve must fail it; otherwise the run is
// green with nothing tested, and the setup steps read a green dispatch as
// the signal to turn the gate on.
func TestLiveE2E_DispatchFromOtherRefFails(t *testing.T) {
	live := loadWorkflows(t)[liveWorkflow]
	if r, ok := live.Jobs["resolve"]; !ok || !refusesOtherRefs(&r) {
		t.Errorf("%s: the resolve job does not fail a run from a ref other than main or a v* tag", liveWorkflow)
	}
}

// refusesOtherRefs: a step fails the job unless GITHUB_REF is main or a v*
// tag.
func refusesOtherRefs(j *workflowJob) bool {
	for _, st := range j.Steps {
		if strings.Contains(st.Run, "refs/heads/main|refs/tags/v*)") && strings.Contains(st.Run, "exit 1") {
			return true
		}
	}
	return false
}

// runsLiveTestRequired: the job runs a TestLiveE2E_ test with skips turned
// into failures and against the installed binary, not one built from source.
func runsLiveTestRequired(j *workflowJob) bool {
	for _, st := range j.Steps {
		if strings.Contains(st.Run, "scripts/run-live-tests.sh '^TestLiveE2E_") &&
			st.Env["LIVE_E2E_REQUIRED"] == "1" && st.Env["SIGCOMPLY_E2E_BINARY"] != "" {
			return true
		}
	}
	return false
}

// triggerNames returns the workflow's `on:` event names, sorted.
func triggerNames(w *workflowFile) []string {
	var names []string
	if w.On.Kind == yaml.MappingNode {
		for i := 0; i < len(w.On.Content); i += 2 {
			names = append(names, w.On.Content[i].Value)
		}
	}
	sort.Strings(names)
	return names
}

// TestReleasePromote_PromoteWaitsForTheLiveTier pins that a release with
// LIVE_E2E on is promoted only after the live tier passed for its tag, and
// that the tier being off (skipped) is the only other way through.
func TestReleasePromote_PromoteWaitsForTheLiveTier(t *testing.T) {
	all := loadWorkflows(t)
	rp := all[filepath.Base(promoteWorkflow)]
	live, ok := rp.Jobs["live-e2e"]
	if !ok {
		t.Fatal("release-promote.yml has no live-e2e job")
	}
	if live.Uses != "./.github/workflows/"+liveWorkflow || live.If != "vars.LIVE_E2E == 'on'" || live.With["tag"] != "${{ inputs.tag }}" {
		t.Errorf("live-e2e job = uses %q, if %q, tag %q; want %s on vars.LIVE_E2E == 'on' for inputs.tag",
			live.Uses, live.If, live.With["tag"], liveWorkflow)
	}
	if live.Permissions["id-token"] != permWrite {
		t.Error("live-e2e job does not grant id-token: write; the called jobs cannot get cloud credentials")
	}

	promote := rp.Jobs["promote"]
	if !contains(promote.Needs, "live-e2e") || !contains(promote.Needs, "e2e-gate") {
		t.Errorf("promote needs %v; want both e2e-gate and live-e2e", promote.Needs)
	}
	cond := strings.Join(strings.Fields(promote.If), " ")
	for _, want := range []string{
		"(needs.e2e-gate.result == 'success' || (vars.RELEASE_GATE != 'on' && needs.e2e-gate.result == 'skipped'))",
		"(needs.live-e2e.result == 'success' || (vars.LIVE_E2E != 'on' && needs.live-e2e.result == 'skipped'))",
	} {
		if !strings.Contains(cond, want) {
			t.Errorf("promote `if` = %q; want it to require %s", cond, want)
		}
	}
	if strings.Contains(cond, "always()") {
		t.Errorf("promote `if` = %q; always() would promote after a canceled gate", cond)
	}
}

// TestReleaseWorkflows_PromoteCallersGrantOIDC: a called workflow's job
// gets no permission its caller did not grant, so every job calling
// release-promote.yml must grant id-token: write for the live tier.
func TestReleaseWorkflows_PromoteCallersGrantOIDC(t *testing.T) {
	all := loadWorkflows(t)
	for name, wf := range all {
		for id, j := range wf.Jobs {
			if j.Uses == promoteWorkflow && j.Permissions["id-token"] != permWrite {
				t.Errorf("%s: job %q calls %s without id-token: write", name, id, promoteWorkflow)
			}
		}
	}
}

// TestLiveE2E_IdentifiersAreSecrets: GitHub prints a step's `with:` and
// `env:` values in the public log and masks only secrets, so every account
// identifier the live tier reads (role ARN, project, subscription, bucket,
// e-mail) must come from secrets. Only these non-identifying switches may
// be variables.
func TestLiveE2E_IdentifiersAreSecrets(t *testing.T) {
	// The live workflow and the two that call it; RELEASE_GATE is the E2E
	// gate's switch.
	allowed := map[string]bool{
		"LIVE_E2E": true, "LIVE_E2E_AWS_REGION": true, "LIVE_E2E_AWS_INSPECTOR": true, "RELEASE_GATE": true,
	}
	for _, name := range []string{liveWorkflow, "live-e2e-nightly.yml", filepath.Base(promoteWorkflow)} {
		data, err := os.ReadFile(filepath.Join("..", ".github", "workflows", name)) //nolint:gosec // #nosec G304 -- repository workflow files
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range regexp.MustCompile(`vars\.([A-Z0-9_]+)`).FindAllStringSubmatch(string(data), -1) {
			if !allowed[m[1]] {
				t.Errorf("%s reads vars.%s; store it as a live-e2e environment secret, the log prints variables", name, m[1])
			}
		}
	}
}

// TestLiveE2E_NightlyFollowsTheSwitch: LIVE_E2E is the one off switch for
// the tier. A nightly run that ignored it would fail and comment on the
// drift issue every night while the accounts are not set up or a vendor
// is down.
func TestLiveE2E_NightlyFollowsTheSwitch(t *testing.T) {
	all := loadWorkflows(t)
	nightly, ok := all["live-e2e-nightly.yml"]
	if !ok {
		t.Fatal("live-e2e-nightly.yml not found")
	}
	calls := 0
	for id, j := range nightly.Jobs {
		if j.Uses != "./.github/workflows/"+liveWorkflow {
			continue
		}
		calls++
		if j.If != "vars.LIVE_E2E == 'on'" {
			t.Errorf("live-e2e-nightly.yml: job %q calls %s with `if` %q; want vars.LIVE_E2E == 'on'", id, liveWorkflow, j.If)
		}
	}
	if calls != 1 {
		t.Errorf("live-e2e-nightly.yml calls %s from %d jobs; want 1", liveWorkflow, calls)
	}
}

// TestReleasePromote_GateDispatchNamesTheRef: `gh workflow run` without
// --ref asks the API for the target repo's default branch, which the
// fine-grained E2E_GATE_TOKEN (Actions read/write only) may not read, so
// the v1.1.4 gate failed before it dispatched anything. Every dispatch
// names the branch.
func TestReleasePromote_GateDispatchNamesTheRef(t *testing.T) {
	all := loadWorkflows(t)
	dispatches := 0
	for id, j := range all[filepath.Base(promoteWorkflow)].Jobs {
		for _, s := range j.Steps {
			for _, cmd := range strings.Split(strings.ReplaceAll(s.Run, "\\\n", " "), "\n") {
				if !strings.Contains(cmd, "gh workflow run") {
					continue
				}
				dispatches++
				if !strings.Contains(cmd, "--ref main") {
					t.Errorf("job %q dispatches without --ref main: %s", id, strings.TrimSpace(cmd))
				}
			}
		}
	}
	if dispatches == 0 {
		t.Fatal("release-promote.yml dispatches no workflow; did the gate job move?")
	}
}

// windowsVerifyJob is the install check on a Windows runner each release
// workflow runs next to the Linux and macOS one.
const windowsVerifyJob = "verify-windows"

// TestReleaseWorkflows_WindowsInstallIsASignalNotAGate: both release
// workflows install the release on windows-latest through install.sh in
// Git Bash, with provenance required, as docs/guides/install.md tells
// Windows users to. No job needs it, so a Windows-only failure turns the
// run red without holding back the promotion that Linux and macOS
// verified.
func TestReleaseWorkflows_WindowsInstallIsASignalNotAGate(t *testing.T) {
	all := loadWorkflows(t)
	for _, name := range []string{"release.yml", "auto-release-pipeline.yml"} {
		wf := all[name]
		j, ok := wf.Jobs[windowsVerifyJob]
		if !ok {
			t.Errorf("%s has no %s job", name, windowsVerifyJob)
			continue
		}
		if j.RunsOn != "windows-latest" {
			t.Errorf("%s: %s runs on %q; want windows-latest", name, windowsVerifyJob, j.RunsOn)
		}
		if !installsWithProvenance(&j) {
			t.Errorf("%s: %s does not run scripts/install.sh with SIGCOMPLY_REQUIRE_PROVENANCE=1", name, windowsVerifyJob)
		}
		verifiesVersion := false
		for _, s := range j.Steps {
			if s.Run == "" {
				continue
			}
			if s.Shell != "bash" {
				t.Errorf("%s: %s has a run step with shell %q; want bash (Git Bash, the documented Windows install)", name, windowsVerifyJob, s.Shell)
			}
			if strings.Contains(s.Run, "sigcomply version") {
				verifiesVersion = true
			}
		}
		if !verifiesVersion {
			t.Errorf("%s: %s never runs `sigcomply version`", name, windowsVerifyJob)
		}
		if verify, ok := wf.Jobs["verify"]; ok && j.If != verify.If {
			t.Errorf("%s: %s `if` = %q; want the verify job's %q", name, windowsVerifyJob, j.If, verify.If)
		}
		for id := range wf.Jobs {
			if contains(wf.Jobs[id].Needs, windowsVerifyJob) {
				t.Errorf("%s: job %q needs %s; the Windows check must not gate anything", name, id, windowsVerifyJob)
			}
		}
	}
}
