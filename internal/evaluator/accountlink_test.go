package evaluator

import (
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
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
	r := account("aws.iam", "AIDA1", map[string]any{"email": " Jane@Acme.com "})
	cases := map[string]any{
		"account.ref":       "aws.iam/AIDA1",
		"account.key":       "jane@acme.com",
		"account.linked_by": "email",
		"account.non_human": false,
		"account.active":    true,
	}
	for path, want := range cases {
		if got := field(t, ec, &r, path); got != want {
			t.Errorf("%s = %v; want %v", path, got, want)
		}
	}
	none := account("github", "x", map[string]any{"is_active": false, "is_root": true})
	if got := field(t, ec, &none, "account.linked_by"); got != "none" {
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
			"github":  {"jdoe": "Jane@acme.com"},
			"aws.iam": {"jane.doe": "jane@acme.com"},
		},
		NonHuman: map[string][]string{"github": {"acme-ci-bot"}, "aws.iam": {"deployer"}},
	}
	ec := newEvalCtx(nil, nil, roster)

	byID := account("github", "JDoe", map[string]any{"email": "other@acme.com", "display_name": "acme-ci-bot"})
	if got := field(t, ec, &byID, "account.key"); got != "jane@acme.com" {
		t.Errorf("alias by id: key = %v", got)
	}
	if got := field(t, ec, &byID, "account.linked_by"); got != "alias" {
		t.Errorf("alias by id: linked_by = %v", got)
	}
	// display_name is never used for lookups.
	if got := field(t, ec, &byID, "account.non_human"); got != false {
		t.Errorf("display_name must not match non_human; got %v", got)
	}

	byUsername := account("aws.iam", "AIDA123", map[string]any{"username": "Jane.Doe"})
	if got := field(t, ec, &byUsername, "account.key"); got != "jane@acme.com" {
		t.Errorf("alias by username: key = %v", got)
	}

	// Aliases are scoped per source: a github alias does not apply to gitlab.
	otherSource := account("gitlab", "jdoe", map[string]any{})
	if got := field(t, ec, &otherSource, "account.linked_by"); got != "none" {
		t.Errorf("alias leaked across sources: linked_by = %v", got)
	}

	bot := account("github", "12", map[string]any{"username": "ACME-CI-bot"})
	if got := field(t, ec, &bot, "account.non_human"); got != true {
		t.Errorf("non_human by username = %v; want true", got)
	}
	deployer := account("aws.iam", "Deployer", map[string]any{})
	if got := field(t, ec, &deployer, "account.non_human"); got != true {
		t.Errorf("non_human by id = %v; want true", got)
	}
}

func TestAccountFields_RenderMsg(t *testing.T) {
	ec := newEvalCtx(nil, nil, nil)
	r := account("github", "jdoe", map[string]any{"email": "Jane@acme.com"})
	got := ec.renderMsg("{{.account.ref}} / {{.account.key}} / {{.account.linked_by}} / {{.payload.email}}", &r)
	if want := "github/jdoe / jane@acme.com / email / Jane@acme.com"; got != want {
		t.Errorf("renderMsg = %q; want %q", got, want)
	}
}

// identity_key account.ref keeps github jdoe and gitlab jdoe apart; the
// default id key would collapse them into one violation.
func TestAccountRef_IdentityKeyDedupAcrossSources(t *testing.T) {
	slots := map[string][]core.EvidenceRecord{
		"accounts": {
			account("github", "jdoe", map[string]any{"email": "jdoe@acme.com"}),
			account("gitlab", "jdoe", map[string]any{"email": "jdoe@acme.com"}),
			account("github", "jdoe", map[string]any{"email": "jdoe@acme.com"}),
		},
		"roster": {},
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
	filter := &core.PassWhenCondition{Op: "all_of", Conditions: []*core.PassWhenCondition{
		{Op: "eq", Field: "account.active", Value: true},
		{Op: "eq", Field: "account.non_human", Value: false},
	}}
	roster := &planner.RosterLink{NonHuman: map[string][]string{"github": {"bot"}}}
	slots := map[string][]core.EvidenceRecord{
		"accounts": {
			account("github", "bot", map[string]any{}),
			account("aws.iam", "root", map[string]any{"is_root": true}),
			account("github", "gone", map[string]any{"is_active": false}),
			account("github", "real", map[string]any{"email": "nobody@acme.com"}),
		},
		"roster": {person("p1", "jane@acme.com", "active")},
	}
	got := evaluatePassWhen(linkedClause(matchesIn("account.key", core.NormalizeLowerTrim, nil), filter), newEvalCtx(slots, nil, roster))
	if ids := violationIDs(got); len(ids) != 1 || ids[0] != "github/real" {
		t.Errorf("violations = %v; want [github/real]", ids)
	}
}
