package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"path/filepath"
	"slices"
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
	linkedPolicy   = "soc2.cc6.2.accounts_linked_to_roster"
	inactivePolicy = "soc2.cc6.2.no_active_accounts_for_inactive_personnel"

	// Source IDs of the fake sources wired into the roster e2e runs.
	sourceOkta   = "okta"
	sourceGitHub = "github"
	sourceAWSIAM = "aws.iam"

	// testNameCIBot is the non_human account name the github fake emits.
	testNameCIBot = "acme-ci-bot"

	// keyAliases is the experimental.roster config key the fixtures fill.
	keyAliases = "aliases"

	carlEmail       = "carl@acme.com"
	keyRosterSource = "source"

	// Evidence-record field names the roster policies read.
	fieldEmail      = "email"
	fieldUsername   = "username"
	fieldMFAEnabled = "mfa_enabled"
	fieldStatus     = "status"

	// slotRoster is the roster slot's name in the policy binding.
	slotRoster = "roster"
)

// rosterFakeSource emits fixed records, returning only those of the
// types the binding asked for, and remembers which slots it was
// collected for.
type rosterFakeSource struct {
	id      string
	records []core.EvidenceRecord
	slots   []string
}

func (s *rosterFakeSource) ID() string { return s.id }

func (s *rosterFakeSource) Emits() []string {
	var out []string
	for i := range s.records {
		if !slices.Contains(out, s.records[i].Type) {
			out = append(out, s.records[i].Type)
		}
	}
	return out
}

func (*rosterFakeSource) Init(context.Context, map[string]any) error { return nil }

func (s *rosterFakeSource) Collect(_ context.Context, req core.SlotRequest) ([]core.EvidenceRecord, error) {
	s.slots = append(s.slots, req.SlotName)
	var out []core.EvidenceRecord
	for i := range s.records {
		if req.Accepts(s.records[i].Type) {
			out = append(out, s.records[i])
		}
	}
	return out, nil
}

func fakeRecord(t *testing.T, source, typ string, payload map[string]any) core.EvidenceRecord {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := payload["id"].(string) //nolint:errcheck // fixture ids are always strings
	return core.EvidenceRecord{Type: typ, ID: id, SourceID: source, Payload: b}
}

// rosterFakes returns an Okta-like roster source (which also emits its own
// directory users), a GitHub-like and an AWS-IAM-like account source.
func rosterFakes(t *testing.T) (okta, github, aws *rosterFakeSource) {
	t.Helper()
	okta = &rosterFakeSource{id: sourceOkta, records: []core.EvidenceRecord{
		fakeRecord(t, sourceOkta, "roster_entry", map[string]any{"id": "p-jane", fieldEmail: "Jane@Acme.com", fieldStatus: "active"}),
		fakeRecord(t, sourceOkta, "roster_entry", map[string]any{"id": "p-bob", fieldEmail: bobEmail, fieldStatus: "inactive"}),
		fakeRecord(t, sourceOkta, "roster_entry", map[string]any{"id": "p-carl", fieldEmail: carlEmail, fieldStatus: "pending"}),
		// Would fail the linked policy if the roster source were ever
		// checked against itself.
		fakeRecord(t, sourceOkta, "directory_user", map[string]any{"id": "00u-stray", fieldEmail: "stray@acme.com", fieldMFAEnabled: true}),
	}}
	github = &rosterFakeSource{id: sourceGitHub, records: []core.EvidenceRecord{
		fakeRecord(t, sourceGitHub, "directory_user", map[string]any{"id": "101", fieldUsername: "JDoe", fieldMFAEnabled: true}),                                              // alias → jane
		fakeRecord(t, sourceGitHub, "directory_user", map[string]any{"id": "102", fieldUsername: "bobby", fieldMFAEnabled: true}),                                             // alias → bob (inactive)
		fakeRecord(t, sourceGitHub, "directory_user", map[string]any{"id": "103", fieldUsername: testNameCIBot, fieldMFAEnabled: false}),                                      // non_human
		fakeRecord(t, sourceGitHub, "directory_user", map[string]any{"id": "104", fieldUsername: "mallory", fieldEmail: "mallory@example.com", fieldMFAEnabled: true}),        // unlinked
		fakeRecord(t, sourceGitHub, "directory_user", map[string]any{"id": "105", fieldUsername: "carl", fieldEmail: carlEmail, fieldMFAEnabled: true}),                       // pending person
		fakeRecord(t, sourceGitHub, "directory_user", map[string]any{"id": "106", fieldUsername: "bob-old", fieldEmail: bobEmail, fieldMFAEnabled: true, "is_active": false}), // disabled
	}}
	aws = &rosterFakeSource{id: sourceAWSIAM, records: []core.EvidenceRecord{
		fakeRecord(t, sourceAWSIAM, "directory_user.v2", map[string]any{"id": "root", "is_root": true, fieldMFAEnabled: true, "has_console_access": true, "has_programmatic_access": false}),
		fakeRecord(t, sourceAWSIAM, "directory_user.v2", map[string]any{"id": "AIDANOEMAIL", fieldUsername: "deploy-legacy", "is_root": false, fieldMFAEnabled: false, "has_console_access": false, "has_programmatic_access": true}),
	}}
	return okta, github, aws
}

func runRosterCheck(t *testing.T, experimental map[string]any, sources ...*rosterFakeSource) (orchestrator.Result, string, core.Vault, error) {
	t.Helper()
	regs := bootstrapWithRegistries(nil)
	if err := soc2.Register(regs); err != nil {
		t.Fatalf("register soc2: %v", err)
	}
	cfg := &spec.ProjectConfig{
		Framework:    testFramework,
		Sources:      map[string]map[string]any{},
		Experimental: experimental,
	}
	for _, s := range sources {
		if err := regs.Sources.Register(s); err != nil {
			t.Fatalf("register %s: %v", s.id, err)
		}
		cfg.Sources[s.id] = map[string]any{}
	}
	vaultDir := filepath.Join(t.TempDir(), "vault")
	cfg.Vault = localVault(vaultDir)
	v := local.New(vaultDir)
	if err := v.Init(context.Background()); err != nil {
		t.Fatalf("vault init: %v", err)
	}
	var stdout bytes.Buffer
	res, err := orchestrator.Run(context.Background(), &orchestrator.Options{
		Config:     cfg,
		Registries: regs,
		Vault:      v,
		Stdout:     &stdout,
		Logger:     log.New(&bytes.Buffer{}, false),
		Now:        func() time.Time { return time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC) },
		Filter:     planner.Filter{Policies: []string{linkedPolicy, inactivePolicy}},
	})
	return res, stdout.String(), v, err
}

func readPolicyResult(t *testing.T, v core.Vault, runRoot, policyID string) core.PolicyResult {
	t.Helper()
	body, err := v.GetBinary(context.Background(), runRoot+"/policies/"+policyID+"/result.json")
	if err != nil {
		t.Fatalf("read result for %s: %v", policyID, err)
	}
	var pr core.PolicyResult
	if err := json.Unmarshal(body, &pr); err != nil {
		t.Fatalf("unmarshal result for %s: %v", policyID, err)
	}
	return pr
}

// The shipped SOC 2 roster policies run end to end through the planner,
// collector and evaluator: aliases and non-human declarations link or
// exclude accounts, root is never a person, disabled accounts are out of
// scope, and the roster source's own accounts are never checked against
// itself.
func TestE2E_RosterPolicies(t *testing.T) {
	okta, github, aws := rosterFakes(t)
	res, stdout, v, err := runRosterCheck(t, map[string]any{slotRoster: map[string]any{
		keyRosterSource: sourceOkta,
		keyAliases:      map[string]any{sourceGitHub: map[string]any{"jdoe": janeEmail, "bobby": bobEmail}},
		"non_human":     map[string]any{sourceGitHub: []any{testNameCIBot}},
	}}, okta, github, aws)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, stdout)
	}
	if res.ExitCode != orchestrator.ExitViolation {
		t.Errorf("exit = %d; want %d\n%s", res.ExitCode, orchestrator.ExitViolation, stdout)
	}

	// 6 GitHub + 2 AWS accounts; the roster slot is a lookup table and
	// Okta's own directory user is never bound to the accounts slot.
	const accounts = 8

	assertRosterFailure(t, v, res.RunRoot, linkedPolicy, accounts, map[string]string{
		"aws.iam/AIDANOEMAIL": "identity aws.iam/AIDANOEMAIL is not linked to anyone in the roster",
		"github/104":          "identity github/104 is not linked to anyone in the roster",
	})
	assertRosterFailure(t, v, res.RunRoot, inactivePolicy, accounts, map[string]string{
		"github/102": "identity github/102 belongs to bob@acme.com, who is inactive in the roster",
	})

	for _, s := range []*rosterFakeSource{okta, github, aws} {
		for _, slot := range s.slots {
			if (s == okta) != (slot == slotRoster) {
				t.Errorf("source %s collected for slot %q", s.id, slot)
			}
		}
	}
	if len(okta.slots) != 2 {
		t.Errorf("okta collected for %v; want only the two roster slots", okta.slots)
	}
}

// Without experimental.roster the roster slot stays unbound: both
// policies skip with an actionable reason and nothing is collected.
func TestE2E_RosterPolicies_SkipWithoutDesignatedRoster(t *testing.T) {
	okta, github, aws := rosterFakes(t)
	res, stdout, v, err := runRosterCheck(t, nil, okta, github, aws)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, stdout)
	}
	for _, id := range []string{linkedPolicy, inactivePolicy} {
		if pr := readPolicyResult(t, v, res.RunRoot, id); pr.Status != core.StatusSkip {
			t.Errorf("%s status = %q; want skip", id, pr.Status)
		}
		want := id + " — no roster source designated — set experimental.roster.source"
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	for _, s := range []*rosterFakeSource{okta, github, aws} {
		if len(s.slots) != 0 {
			t.Errorf("source %s collected for %v; want nothing collected for a skipped policy", s.id, s.slots)
		}
	}
}

// A designated roster source that is not configured is a configuration
// error (exit 3), not a silent skip.
func TestE2E_RosterPolicies_UnconfiguredRosterSource(t *testing.T) {
	_, github, aws := rosterFakes(t)
	res, _, _, err := runRosterCheck(t, map[string]any{slotRoster: map[string]any{keyRosterSource: sourceOkta}}, github, aws)
	if err == nil || res.ExitCode != orchestrator.ExitConfig {
		t.Fatalf("exit = %d err = %v; want exit %d with an error", res.ExitCode, err, orchestrator.ExitConfig)
	}
	if !strings.Contains(err.Error(), sourceOkta) {
		t.Errorf("error %q does not name the roster source", err)
	}
}

// assertRosterFailure checks a failed roster policy: its violations are
// exactly want (account.ref → reason) and every account was evaluated.
func assertRosterFailure(t *testing.T, v core.Vault, runRoot, policyID string, evaluated int, want map[string]string) {
	t.Helper()
	pr := readPolicyResult(t, v, runRoot, policyID)
	if pr.Status != core.StatusFail {
		t.Errorf("%s status = %q (diag %v); want fail", policyID, pr.Status, pr.Diag)
	}
	got := make(map[string]string, len(pr.Violations))
	for _, viol := range pr.Violations {
		got[viol.ResourceID] = viol.Reason
	}
	if !maps.Equal(got, want) {
		t.Errorf("%s violations = %v; want %v", policyID, got, want)
	}
	if pr.ResourcesEvaluated != evaluated || pr.ResourcesFailed != len(want) {
		t.Errorf("%s evaluated=%d failed=%d; want %d and %d", policyID, pr.ResourcesEvaluated, pr.ResourcesFailed, evaluated, len(want))
	}
}

const sourceGCPIAM = "gcp.iam"

// gcpIAMFake emits iam_binding records shaped the way gcp.iam does: the
// record id names the grant ("<role>|<member>"), and the person — when
// the principal is one — is in payload.principal_id. allUsers has no
// colon in its member string, so its principal_type is "" (see
// principalType in internal/sources/gcp/iam), which is why it stays in
// the checked population rather than being inferred non-human.
func gcpIAMFake(t *testing.T) *rosterFakeSource {
	t.Helper()
	bind := func(role, member, principalID, principalType string) core.EvidenceRecord {
		return fakeRecord(t, sourceGCPIAM, "iam_binding", map[string]any{
			"id": role + "|" + member, "role": role,
			"principal_id": principalID, "principal_type": principalType,
			"is_broad_admin_role": false, "has_condition": false,
		})
	}
	return &rosterFakeSource{id: sourceGCPIAM, records: []core.EvidenceRecord{
		bind("roles/owner", "user:Jane@Acme.com", "Jane@Acme.com", "user"),              // linked by principal
		bind("roles/viewer", "user:bob@acme.com", bobEmail, "user"),                     // inactive in the roster
		bind("roles/editor", "user:mallory@example.com", "mallory@example.com", "user"), // unlinked
		bind("roles/viewer", "user:mallory@example.com", "mallory@example.com", "user"), // unlinked, second role
		bind("roles/storage.admin", "user:c@personal.test", "c@personal.test", "user"),  // aliased → carl
		bind("roles/owner", "serviceAccount:ci@p.iam.gserviceaccount.com", "ci@p.iam.gserviceaccount.com", "service_account"),
		bind("roles/viewer", "group:eng@acme.com", "eng@acme.com", "group"),
		bind("roles/viewer", "domain:partner.example", "partner.example", "domain"),
		bind("roles/viewer", "allUsers", "allUsers", ""),
	}}
}

// The roster join is type-agnostic: a cloud IAM grant is checked against
// the roster exactly as an account is. This is the blind spot the
// account side cannot see — a role held by a principal that was never an
// account in any bound directory, which is how access outlives a
// departure.
func TestE2E_RosterPolicies_IAMGrants(t *testing.T) {
	okta, _, _ := rosterFakes(t)
	res, stdout, v, err := runRosterCheck(t, map[string]any{slotRoster: map[string]any{
		keyRosterSource: sourceOkta,
		keyAliases:      map[string]any{sourceGCPIAM: map[string]any{"c@personal.test": carlEmail}},
	}}, okta, gcpIAMFake(t))
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, stdout)
	}
	if res.ExitCode != orchestrator.ExitViolation {
		t.Errorf("exit = %d; want %d\n%s", res.ExitCode, orchestrator.ExitViolation, stdout)
	}

	// All 9 bindings are evaluated: the roster slot is a lookup table
	// and never counts. Findings are per grant, because a grant is what
	// you revoke — mallory's two roles are two revocations.
	const grants = 9

	assertRosterFailure(t, v, res.RunRoot, linkedPolicy, grants, map[string]string{
		"gcp.iam/roles/editor|user:mallory@example.com": "identity gcp.iam/roles/editor|user:mallory@example.com is not linked to anyone in the roster",
		"gcp.iam/roles/viewer|user:mallory@example.com": "identity gcp.iam/roles/viewer|user:mallory@example.com is not linked to anyone in the roster",
		// A public grant names no person, so it can never link. The
		// fail-safe on an unclassifiable principal_type is what keeps
		// the most dangerous binding in GCP inside the population.
		"gcp.iam/roles/viewer|allUsers": "identity gcp.iam/roles/viewer|allUsers is not linked to anyone in the roster",
	})
	assertRosterFailure(t, v, res.RunRoot, inactivePolicy, grants, map[string]string{
		"gcp.iam/roles/viewer|user:bob@acme.com": "identity gcp.iam/roles/viewer|user:bob@acme.com belongs to bob@acme.com, who is inactive in the roster",
	})
}

// A declared alias or non_human account name no collected account
// carries is the other half of a typo — the source-ID half already fails
// the plan — and it is silent without this. It is reported once per run,
// on stdout, after every roster policy has had its chance to use it.
func TestE2E_RosterPolicies_UnusedKeysWarn(t *testing.T) {
	okta, github, aws := rosterFakes(t)
	_, stdout, _, err := runRosterCheck(t, map[string]any{slotRoster: map[string]any{
		keyRosterSource: sourceOkta,
		keyAliases: map[string]any{
			sourceGitHub: map[string]any{"jdoe": janeEmail, "jdoee": janeEmail},
			sourceAWSIAM: map[string]any{"deploy-legacy": bobEmail},
		},
		"non_human": map[string]any{
			sourceGitHub: []any{testNameCIBot, "acme-ci-bott"},
			sourceAWSIAM: []any{"root"},
		},
	}}, okta, github, aws)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, stdout)
	}
	for _, want := range []string{
		`unused-alias: experimental.roster.aliases["github"]["jdoee"]`,
		`unused-non-human: experimental.roster.non_human["github"]["acme-ci-bott"]`,
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	// Used keys stay quiet — including ones only one of the two roster
	// policies could have matched, and a non_human entry for an account
	// that is already non-human by construction (the AWS root user).
	for _, used := range []string{
		`unused-alias: experimental.roster.aliases["github"]["jdoe"]`,
		`unused-alias: experimental.roster.aliases["aws.iam"]["deploy-legacy"]`,
		`unused-non-human: experimental.roster.non_human["github"]["acme-ci-bot"]`,
		`unused-non-human: experimental.roster.non_human["aws.iam"]["root"]`,
	} {
		if strings.Contains(stdout, used) {
			t.Errorf("stdout reports a used key as unused (%s):\n%s", used, stdout)
		}
	}
}
