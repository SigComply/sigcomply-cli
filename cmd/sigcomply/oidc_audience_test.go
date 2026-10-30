package cmd

// OIDC audience separation (AGENTS.md, invariant "OIDC audiences"). A
// token minted for submitter.DefaultAudience goes to SigComply Cloud on
// every submission, so a cloud role that trusts that audience trusts a
// token SigComply Cloud holds. These tests read every CI file and doc a
// customer copies from: the init-ci templates and their goldens,
// examples/, and the JSON trust policies and CLI commands in the docs.

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/sigcomply/sigcomply-cli/internal/submitter"
)

// awsAudience is the audience AWS STS expects by default and the one
// every AWS-facing token in a template, example or doc must carry.
const awsAudience = "sts.amazonaws.com"

// repoRoot is the repository root relative to this package.
var repoRoot = filepath.Join("..", "..")

// ciFile is one GitHub workflow or GitLab pipeline a customer runs.
type ciFile struct {
	name string
	body []byte
}

// ciFiles returns every shipped CI file of one kind ("github" or
// "gitlab"): the embedded templates, their goldens and examples/.
func ciFiles(t *testing.T, kind string) []ciFile {
	t.Helper()
	var out []ciFile
	for path, body := range shippedTemplates(t) {
		if strings.Contains(path, "/"+kind+"/") {
			out = append(out, ciFile{path, []byte(body)})
		}
	}
	var globs []string
	switch kind {
	case ciGitHub:
		globs = []string{"cmd/sigcomply/testdata/golden_compliance-*.yml", "examples/github-actions/*.yml"}
	case ciGitLab:
		globs = []string{"cmd/sigcomply/testdata/golden_gitlab-ci.yml", "examples/gitlab-ci.yml"}
	}
	for _, g := range globs {
		matches, err := filepath.Glob(filepath.Join(repoRoot, g))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range matches {
			b, err := os.ReadFile(m) //nolint:gosec // #nosec G304 -- committed repository files
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, ciFile{m, b})
		}
	}
	return out
}

// Every GitHub workflow hands AWS a token with AWS's own audience, set
// explicitly so a reader sees it, never SigComply's.
func TestCIFiles_GitHubAWSStepUsesItsOwnAudience(t *testing.T) {
	files := ciFiles(t, ciGitHub)
	if len(files) < 6 {
		t.Fatalf("found %d GitHub workflows; want the 2 templates, 2 goldens and the examples", len(files))
	}
	for _, f := range files {
		var wf struct {
			Jobs map[string]struct {
				Steps []struct {
					Uses string            `yaml:"uses"`
					With map[string]string `yaml:"with"`
				} `yaml:"steps"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(f.body, &wf); err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		found := 0
		for job, j := range wf.Jobs {
			for _, s := range j.Steps {
				if !strings.HasPrefix(s.Uses, "aws-actions/configure-aws-credentials@") {
					continue
				}
				found++
				if got := s.With["audience"]; got != awsAudience {
					t.Errorf("%s job %s: configure-aws-credentials audience = %q; want %q (never %q)",
						f.name, job, got, awsAudience, submitter.DefaultAudience)
				}
			}
		}
		if found == 0 {
			t.Errorf("%s: no configure-aws-credentials step", f.name)
		}
	}
}

// awsTokenFileWrite matches the line that writes a GitLab ID token into
// the AWS SDK's web identity token file and captures the variable.
var awsTokenFileWrite = regexp.MustCompile(`printf '%s' "\$([A-Z_]+)" > "\$AWS_WEB_IDENTITY_TOKEN_FILE"`)

// Every GitLab pipeline mints two ID tokens: SIGCOMPLY_ID_TOKEN with
// SigComply's audience for the CLI, and a separate one with AWS's audience
// that is the only one written to AWS_WEB_IDENTITY_TOKEN_FILE.
func TestCIFiles_GitLabAWSTokenIsNotTheSubmissionToken(t *testing.T) {
	files := ciFiles(t, ciGitLab)
	if len(files) < 3 {
		t.Fatalf("found %d GitLab pipelines; want the template, its golden and the example", len(files))
	}
	for _, f := range files {
		var doc map[string]struct {
			IDTokens map[string]struct {
				Aud string `yaml:"aud"`
			} `yaml:"id_tokens"`
		}
		if err := yaml.Unmarshal(f.body, &doc); err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		auds := map[string]string{}
		for job, j := range doc {
			for name, tok := range j.IDTokens {
				auds[name] = tok.Aud
				if name != submitter.GitLabIDTokenEnv && tok.Aud == submitter.DefaultAudience {
					t.Errorf("%s job %s: id_tokens.%s has the SigComply Cloud audience; only %s may",
						f.name, job, name, submitter.GitLabIDTokenEnv)
				}
			}
		}
		if auds[submitter.GitLabIDTokenEnv] != submitter.DefaultAudience {
			t.Errorf("%s: id_tokens.%s.aud = %q; want %q", f.name, submitter.GitLabIDTokenEnv, auds[submitter.GitLabIDTokenEnv], submitter.DefaultAudience)
		}
		writes := awsTokenFileWrite.FindAllStringSubmatch(string(f.body), -1)
		if len(writes) == 0 {
			t.Errorf("%s: nothing writes AWS_WEB_IDENTITY_TOKEN_FILE", f.name)
		}
		for _, w := range writes {
			if got := auds[w[1]]; got != awsAudience {
				t.Errorf("%s: AWS_WEB_IDENTITY_TOKEN_FILE gets $%s, whose audience is %q; want an id_tokens entry with aud %q",
					f.name, w[1], got, awsAudience)
			}
		}
	}
}

// customerDocs returns every Markdown file a customer reads, plus the
// examples, by path relative to the repository root.
func customerDocs(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	root := os.DirFS(repoRoot)
	add := func(p string) {
		b, err := fs.ReadFile(root, p)
		if err != nil {
			t.Fatal(err)
		}
		out[p] = string(b)
	}
	for _, p := range []string{"README.md", "llms.txt"} {
		add(p)
	}
	for _, dir := range []string{"docs", "examples"} {
		err := fs.WalkDir(root, dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (p == "docs/claude" || p == "docs/architecture") {
				return fs.SkipDir
			}
			if !d.IsDir() && (strings.HasSuffix(p, ".md") || strings.HasSuffix(p, ".yml")) {
				add(p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// jsonBlock matches a fenced JSON code block.
var jsonBlock = regexp.MustCompile("(?s)```json\\n(.*?)```")

// trustStatement is the part of an IAM trust policy statement these
// checks read. Condition values are a string or a list of strings.
type trustStatement struct {
	Sid       string                    `json:"Sid"`
	Action    any                       `json:"Action"`
	Condition map[string]map[string]any `json:"Condition"`
}

// trustPolicies returns every documented IAM trust policy for the OIDC
// web identity, keyed "file#n".
func trustPolicies(t *testing.T) map[string][]trustStatement {
	t.Helper()
	out := map[string][]trustStatement{}
	for p, body := range customerDocs(t) {
		for i, m := range jsonBlock.FindAllStringSubmatch(body, -1) {
			if !strings.Contains(m[1], "sts:AssumeRoleWithWebIdentity") {
				continue
			}
			var doc struct {
				Statement []trustStatement `json:"Statement"`
			}
			if err := json.Unmarshal([]byte(m[1]), &doc); err != nil {
				t.Fatalf("%s block %d: trust policy is not valid JSON: %v", p, i, err)
			}
			out[p+"#"+strconv.Itoa(i)] = doc.Statement
		}
	}
	return out
}

func conditionValues(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// The documented trust policies accept only AWS's audience, and the
// scheduled role (the one that writes cadence state and whose runs are
// submitted) trusts only the default branch: exact `sub` values, no
// wildcard. Each statement names its role with a Sid so the check knows
// which rule applies.
func TestDocs_TrustPoliciesSeparateAudiencesAndPinTheScheduledRole(t *testing.T) {
	policies := trustPolicies(t)
	if len(policies) < 4 {
		t.Fatalf("found %d documented trust policies; want the scheduled and on-push roles for GitHub and GitLab", len(policies))
	}
	scheduled := 0
	for name, stmts := range policies {
		for _, s := range stmts {
			if checkTrustStatement(t, name, &s) {
				scheduled++
			}
		}
	}
	if scheduled < 2 {
		t.Errorf("found %d scheduled-role trust policies; want one each for GitHub and GitLab", scheduled)
	}
}

// mainBranchSub reports whether sub names exactly the main branch, in
// GitHub's or GitLab's claim format.
func mainBranchSub(sub string) bool {
	return !strings.Contains(sub, "*") &&
		(strings.HasSuffix(sub, ":ref:refs/heads/main") || strings.HasSuffix(sub, ":ref_type:branch:ref:main"))
}

// checkTrustStatement applies the audience rule to one statement, and
// the main-branch rule when it is the scheduled role's. It reports
// whether it was.
func checkTrustStatement(t *testing.T, name string, s *trustStatement) bool {
	t.Helper()
	var auds, subs []string
	subNotExact := false
	for op, conds := range s.Condition {
		for key, v := range conds {
			switch {
			case strings.HasSuffix(key, ":aud"):
				auds = append(auds, conditionValues(v)...)
			case strings.HasSuffix(key, ":sub"):
				subs = append(subs, conditionValues(v)...)
				subNotExact = subNotExact || op != "StringEquals"
			}
		}
	}
	if len(auds) == 0 {
		t.Errorf("%s: statement %q has no aud condition", name, s.Sid)
	}
	for _, a := range auds {
		if a != awsAudience {
			t.Errorf("%s: statement %q trusts audience %q; want only %q (never %q)", name, s.Sid, a, awsAudience, submitter.DefaultAudience)
		}
	}
	switch s.Sid {
	case "SigComplyScheduled":
		if subNotExact || len(subs) == 0 {
			t.Errorf("%s: the scheduled role must match sub with StringEquals", name)
		}
		for _, sub := range subs {
			if !mainBranchSub(sub) {
				t.Errorf("%s: the scheduled role trusts sub %q; want the main branch only", name, sub)
			}
		}
		return true
	case "SigComplyOnPush":
	default:
		t.Errorf("%s: trust statement Sid %q; want SigComplyScheduled or SigComplyOnPush", name, s.Sid)
	}
	return false
}

// No customer doc tells anyone to register SigComply's audience with AWS
// or to grant the broad ReadOnlyAccess policy, which also reads every
// object in every bucket.
func TestDocs_NoSigComplyAudienceOrReadOnlyAccessForAWS(t *testing.T) {
	// A command that registers a client ID with an AWS OIDC provider:
	// create-open-id-connect-provider --client-id-list, or
	// add-client-id-to-open-id-connect-provider --client-id.
	registers := regexp.MustCompile(`(--client-id-list|add-client-id-to-open-id-connect-provider)[^\n]*`)
	for p, body := range customerDocs(t) {
		for _, m := range registers.FindAllString(body, -1) {
			if strings.Contains(m, submitter.DefaultAudience) {
				t.Errorf("%s: %q registers the SigComply Cloud audience with AWS", p, m)
			}
		}
		if strings.Contains(body, "ReadOnlyAccess") {
			t.Errorf("%s: recommends ReadOnlyAccess; use SecurityAudit and ViewOnlyAccess plus the buckets", p)
		}
	}
}
