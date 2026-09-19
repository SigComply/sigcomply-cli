package evaluator

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

// Slot names, field paths and fixture identities shared by the
// account-link and roster-matching tests.
const (
	slotAccounts = "accounts"
	slotRoster   = "roster"

	fieldAccountRef = "account.ref"

	testSourceGitHub = "github"
	testEmailJane    = "jane@acme.com"
	testEmailJdoe    = "jdoe@acme.com"
)

func field(t *testing.T, ec *evalCtx, r *core.EvidenceRecord, path string) any {
	t.Helper()
	v, ok := ec.getField(r, path)
	if !ok {
		t.Fatalf("getField(%q) not found", path)
	}
	return v
}

func TestAccountFields_NoRoster(t *testing.T) {
	ec := newEvalCtx(nil, nil, nil)
	r := account(testSourceAWSIAM, "AIDA1", map[string]any{linkedByEmail: " Jane@Acme.com "})
	cases := map[string]any{
		fieldAccountRef:     "aws.iam/AIDA1",
		"account.key":       testEmailJane,
		"account.linked_by": linkedByEmail,
		"account.non_human": false,
		"account.active":    true,
	}
	for path, want := range cases {
		if got := field(t, ec, &r, path); got != want {
			t.Errorf("%s = %v; want %v", path, got, want)
		}
	}
	none := account(testSourceGitHub, "x", map[string]any{"is_active": false, "is_root": true})
	if got := field(t, ec, &none, "account.linked_by"); got != linkedByNone {
		t.Errorf("linked_by = %v; want none", got)
	}
	if got := field(t, ec, &none, "account.key"); got != "" {
		t.Errorf("key = %v; want empty", got)
	}
	if got := field(t, ec, &none, "account.active"); got != false {
		t.Errorf("active = %v; want false", got)
	}
	if got := field(t, ec, &none, "account.non_human"); got != true {
		t.Errorf("non_human via is_root = %v; want true", got)
	}
	if _, ok := ec.getField(&none, "account.bogus"); ok {
		t.Error("unknown account.* field must not resolve")
	}
}

func TestAccountFields_AliasByIDAndUsername(t *testing.T) {
	roster := &planner.RosterLink{
		Source: "okta",
		Aliases: map[string]map[string]string{
			testSourceGitHub: {"jdoe": "Jane@acme.com"},
			testSourceAWSIAM: {"jane.doe": testEmailJane},
		},
		NonHuman: map[string][]string{testSourceGitHub: {"acme-ci-bot"}, testSourceAWSIAM: {"deployer"}},
	}
	ec := newEvalCtx(nil, nil, roster)

	byID := account(testSourceGitHub, "JDoe", map[string]any{linkedByEmail: "other@acme.com", "display_name": "acme-ci-bot"})
	if got := field(t, ec, &byID, "account.key"); got != testEmailJane {
		t.Errorf("alias by id: key = %v", got)
	}
	if got := field(t, ec, &byID, "account.linked_by"); got != "alias" {
		t.Errorf("alias by id: linked_by = %v", got)
	}
	// display_name is never used for lookups.
	if got := field(t, ec, &byID, "account.non_human"); got != false {
		t.Errorf("display_name must not match non_human; got %v", got)
	}

	byUsername := account(testSourceAWSIAM, "AIDA123", map[string]any{"username": "Jane.Doe"})
	if got := field(t, ec, &byUsername, "account.key"); got != testEmailJane {
		t.Errorf("alias by username: key = %v", got)
	}

	// Aliases are scoped per source: a github alias does not apply to gitlab.
	otherSource := account("gitlab", "jdoe", map[string]any{})
	if got := field(t, ec, &otherSource, "account.linked_by"); got != linkedByNone {
		t.Errorf("alias leaked across sources: linked_by = %v", got)
	}

	bot := account(testSourceGitHub, "12", map[string]any{"username": "ACME-CI-bot"})
	if got := field(t, ec, &bot, "account.non_human"); got != true {
		t.Errorf("non_human by username = %v; want true", got)
	}
	deployer := account(testSourceAWSIAM, "Deployer", map[string]any{})
	if got := field(t, ec, &deployer, "account.non_human"); got != true {
		t.Errorf("non_human by id = %v; want true", got)
	}
}

func TestAccountFields_RenderMsg(t *testing.T) {
	ec := newEvalCtx(nil, nil, nil)
	r := account(testSourceGitHub, "jdoe", map[string]any{linkedByEmail: "Jane@acme.com"})
	got := ec.renderMsg("{{.account.ref}} / {{.account.key}} / {{.account.linked_by}} / {{.payload.email}}", &r)
	if want := "github/jdoe / jane@acme.com / email / Jane@acme.com"; got != want {
		t.Errorf("renderMsg = %q; want %q", got, want)
	}
}

// identity_key account.ref keeps github jdoe and gitlab jdoe apart; the
// default id key would collapse them into one violation.
func TestAccountRef_IdentityKeyDedupAcrossSources(t *testing.T) {
	slots := map[string][]core.EvidenceRecord{
		slotAccounts: {
			account(testSourceGitHub, "jdoe", map[string]any{linkedByEmail: testEmailJdoe}),
			account("gitlab", "jdoe", map[string]any{linkedByEmail: testEmailJdoe}),
			account(testSourceGitHub, "jdoe", map[string]any{linkedByEmail: testEmailJdoe}),
		},
		slotRoster: {},
	}
	byRef := evaluatePassWhen(linkedClause(matchesIn("account.key", "", nil), nil), newEvalCtx(slots, nil, nil))
	if ids := violationIDs(byRef); len(ids) != 2 || ids[0] != "github/jdoe" || ids[1] != "gitlab/jdoe" {
		t.Errorf("account.ref identity: violations = %v; want [github/jdoe gitlab/jdoe]", ids)
	}
	spec := linkedClause(matchesIn("account.key", "", nil), nil)
	spec.Clauses[0].IdentityKey = ""
	if ids := violationIDs(evaluatePassWhen(spec, newEvalCtx(slots, nil, nil))); len(ids) != 1 {
		t.Errorf("id identity: violations = %v; want one", ids)
	}
}

// The roster clause filters out inactive and non-human accounts.
func TestAccountFields_FilterActiveHumans(t *testing.T) {
	filter := &core.PassWhenCondition{Op: opAllOf, Conditions: []*core.PassWhenCondition{
		{Op: "eq", Field: "account.active", Value: true},
		{Op: "eq", Field: "account.non_human", Value: false},
	}}
	roster := &planner.RosterLink{NonHuman: map[string][]string{testSourceGitHub: {"bot"}}}
	slots := map[string][]core.EvidenceRecord{
		slotAccounts: {
			account(testSourceGitHub, "bot", map[string]any{}),
			account(testSourceAWSIAM, "root", map[string]any{"is_root": true}),
			account(testSourceGitHub, "gone", map[string]any{"is_active": false}),
			account(testSourceGitHub, "real", map[string]any{linkedByEmail: "nobody@acme.com"}),
		},
		slotRoster: {person("p1", testEmailJane, statusActive)},
	}
	got := evaluatePassWhen(linkedClause(matchesIn("account.key", core.NormalizeLowerTrim, nil), filter), newEvalCtx(slots, nil, roster))
	if ids := violationIDs(got); len(ids) != 1 || ids[0] != "github/real" {
		t.Errorf("violations = %v; want [github/real]", ids)
	}
}
