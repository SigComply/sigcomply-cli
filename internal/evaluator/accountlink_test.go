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

	fieldAccountRef      = "account.ref"
	fieldAccountNonHuman = "account.non_human"
	fieldAccountActive   = "account.active"

	testSourceGitHub = "github"
	testEmailJane    = "jane@acme.com"
	testEmailJdoe    = "jdoe@acme.com"

	// Payload keys the account link reads off a record.
	fieldIsRoot   = "is_root"
	fieldUsername = "username"

	// Account names the roster fixtures declare aliases and
	// non_human entries for. Case-varied spellings ("JDoe",
	// "Jane.Doe", "ACME-CI-bot") stay inline: they are the point of
	// the case-insensitivity assertions.
	testNameJdoe     = "jdoe"
	testNameJaneDoe  = "jane.doe"
	testNameCIBot    = "acme-ci-bot"
	testNameDeployer = "deployer"
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
		fieldAccountRef:      "aws.iam/AIDA1",
		"account.key":        testEmailJane,
		"account.linked_by":  linkedByEmail,
		fieldAccountNonHuman: false,
		fieldAccountActive:   true,
	}
	for path, want := range cases {
		if got := field(t, ec, &r, path); got != want {
			t.Errorf("%s = %v; want %v", path, got, want)
		}
	}
	none := account(testSourceGitHub, "x", map[string]any{"is_active": false, fieldIsRoot: true})
	if got := field(t, ec, &none, "account.linked_by"); got != linkedByNone {
		t.Errorf("linked_by = %v; want none", got)
	}
	if got := field(t, ec, &none, "account.key"); got != "" {
		t.Errorf("key = %v; want empty", got)
	}
	if got := field(t, ec, &none, fieldAccountActive); got != false {
		t.Errorf("active = %v; want false", got)
	}
	if got := field(t, ec, &none, fieldAccountNonHuman); got != true {
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
			testSourceGitHub: {testNameJdoe: "Jane@acme.com"},
			testSourceAWSIAM: {testNameJaneDoe: testEmailJane},
		},
		NonHuman: map[string][]string{testSourceGitHub: {testNameCIBot}, testSourceAWSIAM: {testNameDeployer}},
	}
	ec := newEvalCtx(nil, nil, roster)

	byID := account(testSourceGitHub, "JDoe", map[string]any{linkedByEmail: "other@acme.com", "display_name": testNameCIBot})
	if got := field(t, ec, &byID, "account.key"); got != testEmailJane {
		t.Errorf("alias by id: key = %v", got)
	}
	if got := field(t, ec, &byID, "account.linked_by"); got != "alias" {
		t.Errorf("alias by id: linked_by = %v", got)
	}
	// display_name is never used for lookups.
	if got := field(t, ec, &byID, fieldAccountNonHuman); got != false {
		t.Errorf("display_name must not match non_human; got %v", got)
	}

	byUsername := account(testSourceAWSIAM, "AIDA123", map[string]any{fieldUsername: "Jane.Doe"})
	if got := field(t, ec, &byUsername, "account.key"); got != testEmailJane {
		t.Errorf("alias by username: key = %v", got)
	}

	// Aliases are scoped per source: a github alias does not apply to gitlab.
	otherSource := account("gitlab", testNameJdoe, map[string]any{})
	if got := field(t, ec, &otherSource, "account.linked_by"); got != linkedByNone {
		t.Errorf("alias leaked across sources: linked_by = %v", got)
	}

	bot := account(testSourceGitHub, "12", map[string]any{fieldUsername: "ACME-CI-bot"})
	if got := field(t, ec, &bot, fieldAccountNonHuman); got != true {
		t.Errorf("non_human by username = %v; want true", got)
	}
	deployer := account(testSourceAWSIAM, "Deployer", map[string]any{})
	if got := field(t, ec, &deployer, fieldAccountNonHuman); got != true {
		t.Errorf("non_human by id = %v; want true", got)
	}
}

func TestAccountFields_RenderMsg(t *testing.T) {
	ec := newEvalCtx(nil, nil, nil)
	r := account(testSourceGitHub, testNameJdoe, map[string]any{linkedByEmail: "Jane@acme.com"})
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
			account(testSourceGitHub, testNameJdoe, map[string]any{linkedByEmail: testEmailJdoe}),
			account("gitlab", testNameJdoe, map[string]any{linkedByEmail: testEmailJdoe}),
			account(testSourceGitHub, testNameJdoe, map[string]any{linkedByEmail: testEmailJdoe}),
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
		{Op: "eq", Field: fieldAccountActive, Value: true},
		{Op: "eq", Field: fieldAccountNonHuman, Value: false},
	}}
	roster := &planner.RosterLink{NonHuman: map[string][]string{testSourceGitHub: {"bot"}}}
	slots := map[string][]core.EvidenceRecord{
		slotAccounts: {
			account(testSourceGitHub, "bot", map[string]any{}),
			account(testSourceAWSIAM, "root", map[string]any{fieldIsRoot: true}),
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

// Fixture identities for the IAM-grant half of the account link.
const (
	testTypeIAMBinding = "iam_binding"
	testSourceGCPIAM   = "gcp.iam"
	testRoleOwner      = "roles/owner"
	keyPrincipalID     = "principal_id"
	keyPrincipalType   = "principal_type"
)

// binding builds an iam_binding record shaped the way gcp.iam emits
// one: the id names the grant ("<role>|<member>"), never the person.
func binding(member, principalID, principalType string) core.EvidenceRecord {
	const role = testRoleOwner
	return rec(testSourceGCPIAM, testTypeIAMBinding, role+"|"+member, map[string]any{
		keyPrincipalID:   principalID,
		keyPrincipalType: principalType,
		"role":           role,
	})
}

// An IAM grant names a person in payload.principal_id — the record id
// is the grant, so without the principal fallback every binding would
// resolve to an empty key and mass-fail the linked-to-roster policies.
func TestAccountFields_IAMBindingLinksByPrincipal(t *testing.T) {
	ec := newEvalCtx(nil, nil, nil)
	r := binding("user:Jane@Acme.com", " Jane@Acme.com ", principalTypeUser)
	cases := map[string]any{
		fieldAccountRef:      "gcp.iam/roles/owner|user:Jane@Acme.com",
		"account.key":        testEmailJane,
		"account.linked_by":  linkedByPrincipal,
		fieldAccountNonHuman: false,
		fieldAccountActive:   true,
	}
	for path, want := range cases {
		if got := field(t, ec, &r, path); got != want {
			t.Errorf("%s = %v; want %v", path, got, want)
		}
	}
}

// A principal that is not a person can never appear in a roster, so it
// is non-human by construction rather than by declaration. An empty
// principal_type is deliberately treated as human: reporting a grant we
// cannot classify is fail-safe, silently dropping it is not.
func TestAccountFields_IAMBindingNonHumanPrincipals(t *testing.T) {
	ec := newEvalCtx(nil, nil, nil)
	for _, tc := range []struct {
		principalType string
		want          bool
	}{
		{principalTypeUser, false},
		// allUsers and allAuthenticatedUsers carry no colon, so gcp.iam
		// emits "" for them rather than the member string. Treating the
		// unclassifiable case as a person is the fail-safe: a public
		// binding stays in the population instead of being excused.
		{"", false},
		{"service_account", true},
		{"group", true},
		{"domain", true},
	} {
		r := binding("x", "someone@acme.com", tc.principalType)
		if got := field(t, ec, &r, fieldAccountNonHuman); got != tc.want {
			t.Errorf("principal_type %q: non_human = %v; want %v", tc.principalType, got, tc.want)
		}
	}
}

// Aliases and non_human declarations reach a grant through the
// principal, which is the only name in the record an operator can
// recognize — the record id is "<role>|<member>".
func TestAccountFields_IAMBindingAliasAndNonHumanByPrincipal(t *testing.T) {
	roster := &planner.RosterLink{
		Aliases:  map[string]map[string]string{testSourceGCPIAM: {"jane@personal.example": testEmailJane}},
		NonHuman: map[string][]string{testSourceGCPIAM: {"breakglass@acme.com"}},
	}
	ec := newEvalCtx(nil, nil, roster)

	aliased := binding("user:jane@personal.example", "jane@personal.example", principalTypeUser)
	if got := field(t, ec, &aliased, "account.key"); got != testEmailJane {
		t.Errorf("aliased key = %v; want %v", got, testEmailJane)
	}
	if got := field(t, ec, &aliased, "account.linked_by"); got != linkedByAlias {
		t.Errorf("aliased linked_by = %v; want alias", got)
	}

	declared := binding("user:breakglass@acme.com", "breakglass@acme.com", principalTypeUser)
	if got := field(t, ec, &declared, fieldAccountNonHuman); got != true {
		t.Errorf("declared non_human = %v; want true", got)
	}
}

// The principal fallback is last: a record carrying a real email still
// links by it, so no existing evidence type changes behavior.
func TestAccountFields_EmailStillWinsOverPrincipal(t *testing.T) {
	ec := newEvalCtx(nil, nil, nil)
	r := rec(testSourceGCPIAM, testTypeIAMBinding, "weird", map[string]any{
		linkedByEmail:  testEmailJdoe,
		keyPrincipalID: "someone-else@acme.com",
	})
	if got := field(t, ec, &r, "account.key"); got != testEmailJdoe {
		t.Errorf("key = %v; want %v", got, testEmailJdoe)
	}
	if got := field(t, ec, &r, "account.linked_by"); got != linkedByEmail {
		t.Errorf("linked_by = %v; want email", got)
	}
}
