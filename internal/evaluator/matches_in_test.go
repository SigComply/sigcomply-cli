package evaluator

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

// rec builds a record with an explicit source and type.
func rec(source, typ, id string, payload map[string]any) core.EvidenceRecord {
	p, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return core.EvidenceRecord{ID: id, Type: typ, SourceID: source, Payload: p, CollectedAt: time.Now()}
}

func account(source, id string, payload map[string]any) core.EvidenceRecord {
	return rec(source, "directory_user", id, payload)
}

func person(id, email, status string) core.EvidenceRecord {
	return rec("okta", "roster_entry", id, map[string]any{"email": email, "status": status})
}

func matchesIn(field, normalize string, where *core.PassWhenCondition) *core.PassWhenCondition {
	return &core.PassWhenCondition{
		Op: core.OpMatchesIn, Field: field, InSlot: "roster",
		RemoteField: "payload.email", Normalize: normalize, Where: where,
	}
}

func linkedClause(cond, filter *core.PassWhenCondition) *core.PassWhenSpec {
	return &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:         "accounts",
		Quantifier:   core.QuantifierAll,
		Condition:    cond,
		Filter:       filter,
		IdentityKey:  "account.ref",
		ViolationMsg: "account {{.account.ref}} is not linked",
	}}}
}

func violationIDs(r core.RuleResult) []string {
	out := make([]string, 0, len(r.Violations))
	for _, v := range r.Violations {
		out = append(out, v.ResourceID)
	}
	return out
}

func TestMatchesIn_MatchAndNoMatch(t *testing.T) {
	slots := map[string][]core.EvidenceRecord{
		"accounts": {
			account("github", "u1", map[string]any{"email": "jane@acme.com"}),
			account("github", "u2", map[string]any{"email": "ghost@acme.com"}),
		},
		"roster": {person("p1", "jane@acme.com", "active")},
	}
	got := evaluatePassWhen(linkedClause(matchesIn("payload.email", "", nil), nil), newEvalCtx(slots, nil, nil))
	if got.Status != core.StatusFail {
		t.Fatalf("status = %q; want fail", got.Status)
	}
	if ids := violationIDs(got); len(ids) != 1 || ids[0] != "github/u2" {
		t.Errorf("violations = %v; want [github/u2]", ids)
	}
	if got.Violations[0].Reason != "account github/u2 is not linked" {
		t.Errorf("reason = %q", got.Violations[0].Reason)
	}
}

func TestMatchesIn_Normalize(t *testing.T) {
	slots := map[string][]core.EvidenceRecord{
		"accounts": {account("github", "u1", map[string]any{"email": "  Jane@ACME.com "})},
		"roster":   {person("p1", "jane@acme.COM", "active")},
	}
	exact := evaluatePassWhen(linkedClause(matchesIn("payload.email", "", nil), nil), newEvalCtx(slots, nil, nil))
	if exact.Status != core.StatusFail {
		t.Errorf("exact compare: status = %q; want fail", exact.Status)
	}
	norm := evaluatePassWhen(linkedClause(matchesIn("payload.email", core.NormalizeLowerTrim, nil), nil), newEvalCtx(slots, nil, nil))
	if norm.Status != core.StatusPass {
		t.Errorf("lower_trim: status = %q; want pass (%v)", norm.Status, norm.Violations)
	}
}

// A local record without a usable key can never be proven linked: it is
// a non-match, not an error. Remote records without a key never match.
func TestMatchesIn_MissingKeys(t *testing.T) {
	slots := map[string][]core.EvidenceRecord{
		"accounts": {
			account("github", "nokey", map[string]any{}),
			account("github", "blank", map[string]any{"email": "   "}),
			account("github", "num", map[string]any{"email": 5}),
		},
		"roster": {
			rec("okta", "roster_entry", "p1", map[string]any{"status": "active"}),
			rec("okta", "roster_entry", "p2", map[string]any{"status": "active", "email": ""}),
		},
	}
	got := evaluatePassWhen(linkedClause(matchesIn("payload.email", core.NormalizeLowerTrim, nil), nil), newEvalCtx(slots, nil, nil))
	if got.Status != core.StatusFail || len(got.Violations) != 3 {
		t.Fatalf("status = %q violations = %v; want fail with 3", got.Status, violationIDs(got))
	}
}

func TestMatchesIn_WhereFiltersRemote(t *testing.T) {
	inactive := &core.PassWhenCondition{Op: "eq", Field: "payload.status", Value: "inactive"}
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:        "accounts",
		Quantifier:  core.QuantifierNone,
		Condition:   matchesIn("account.key", core.NormalizeLowerTrim, inactive),
		IdentityKey: "account.ref",
	}}}
	slots := map[string][]core.EvidenceRecord{
		"accounts": {
			account("github", "jane", map[string]any{"email": "jane@acme.com"}),
			account("github", "bob", map[string]any{"email": "bob@acme.com"}),
		},
		"roster": {
			person("p1", "jane@acme.com", "active"),
			person("p2", "BOB@acme.com", "inactive"),
		},
	}
	got := evaluatePassWhen(spec, newEvalCtx(slots, nil, nil))
	if ids := violationIDs(got); got.Status != core.StatusFail || len(ids) != 1 || ids[0] != "github/bob" {
		t.Fatalf("status = %q violations = %v; want fail [github/bob]", got.Status, ids)
	}
}

// where is strict: a remote record missing the where field is a type
// error for the whole policy, never a silently smaller index.
func TestMatchesIn_WhereStrict_Errors(t *testing.T) {
	where := &core.PassWhenCondition{Op: "eq", Field: "payload.nope", Value: "inactive"}
	slots := map[string][]core.EvidenceRecord{
		"accounts": {account("github", "jane", map[string]any{"email": "jane@acme.com"})},
		"roster":   {person("p1", "jane@acme.com", "inactive")},
	}
	spec := linkedClause(matchesIn("payload.email", "", where), nil)
	if got := evaluatePassWhen(spec, newEvalCtx(slots, nil, nil)); got.Status != core.StatusError {
		t.Errorf("status = %q; want error", got.Status)
	}
}

// Filters are lenient, but a matches_in index is built before any record
// loop, so a bad where inside a filter still errors the policy instead of
// excluding every record and passing vacuously.
func TestMatchesIn_InFilterWithBadWhere_Errors(t *testing.T) {
	where := &core.PassWhenCondition{Op: "eq", Field: "payload.nope", Value: "x"}
	filter := matchesIn("payload.email", "", where)
	cond := &core.PassWhenCondition{Op: "eq", Field: "payload.mfa", Value: true}
	slots := map[string][]core.EvidenceRecord{
		"accounts": {account("github", "jane", map[string]any{"email": "jane@acme.com", "mfa": false})},
		"roster":   {person("p1", "jane@acme.com", "active")},
	}
	if got := evaluatePassWhen(linkedClause(cond, filter), newEvalCtx(slots, nil, nil)); got.Status != core.StatusError {
		t.Errorf("status = %q; want error", got.Status)
	}
}

func TestMatchesIn_UndeclaredSlot_Errors(t *testing.T) {
	cond := &core.PassWhenCondition{Op: core.OpMatchesIn, Field: "payload.email", InSlot: "rostr", RemoteField: "payload.email"}
	slots := map[string][]core.EvidenceRecord{
		"accounts": {account("github", "jane", map[string]any{"email": "jane@acme.com"})},
	}
	if got := evaluatePassWhen(linkedClause(cond, nil), newEvalCtx(slots, nil, nil)); got.Status != core.StatusError {
		t.Errorf("no such slot key: status = %q; want error", got.Status)
	}
	ec := newEvalCtx(slots, nil, nil)
	ec.declared = map[string]core.Slot{"accounts": {}, "roster": {}}
	if got := evaluatePassWhen(linkedClause(cond, nil), ec); got.Status != core.StatusError {
		t.Errorf("undeclared slot: status = %q; want error", got.Status)
	}
}

func TestMatchesIn_EmptyRemoteSlot_IsVacuous(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       "accounts",
		Quantifier: core.QuantifierNone,
		Condition:  matchesIn("payload.email", "", nil),
	}}}
	slots := map[string][]core.EvidenceRecord{
		"accounts": {account("github", "jane", map[string]any{"email": "jane@acme.com"})},
	}
	// Declared but unbound: the collector writes no key for it.
	ec := newEvalCtx(slots, nil, nil)
	ec.declared = map[string]core.Slot{"accounts": {}, "roster": {}}
	got := evaluatePassWhen(spec, ec)
	if got.Status != core.StatusPass {
		t.Fatalf("status = %q; want pass", got.Status)
	}
	v, ok := got.Diag["vacuous_clauses"].([]string)
	if !ok || len(v) != 1 || v[0] != "accounts" {
		t.Errorf("vacuous_clauses = %v; want [accounts]", got.Diag["vacuous_clauses"])
	}
}

// ---- countResources ----

func TestEvaluate_CountsExcludeInSlotOnlySlot(t *testing.T) {
	pp := planner.PlannedPolicy{
		Spec: core.Policy{
			ID:           "p1",
			EvidenceMode: core.EvidenceModeAutomated,
			Slots: map[string]core.Slot{
				"roster":   {Accepts: []string{"roster_entry"}, Required: true, Role: core.SlotRoleRoster},
				"accounts": {Accepts: []string{"directory_user"}, Required: true, Role: core.SlotRoleRosterSubject},
			},
			PassWhen: linkedClause(matchesIn("account.key", core.NormalizeLowerTrim, nil), nil),
		},
		ShouldEvaluate: true,
		Roster:         &planner.RosterLink{Source: "okta"},
	}
	in := &Input{
		Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{"p1": {
			"accounts": {
				account("github", "jane", map[string]any{"email": "jane@acme.com"}),
				account("github", "ghost", map[string]any{"email": "ghost@acme.com"}),
			},
			"roster": {person("p1", "jane@acme.com", "active"), person("p2", "x@acme.com", "active"), person("p3", "y@acme.com", "active")},
		}},
		Now: time.Now(),
	}
	res, err := Evaluate(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	r := res[0]
	if r.Status != core.StatusFail || r.ResourcesEvaluated != 2 || r.ResourcesFailed != 1 {
		t.Errorf("status=%q evaluated=%d failed=%d; want fail 2 1", r.Status, r.ResourcesEvaluated, r.ResourcesFailed)
	}
	if !strings.Contains(r.Violations[0].Reason, "github/ghost") {
		t.Errorf("reason = %q", r.Violations[0].Reason)
	}
}

func TestInSlotOnlySlots(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{
		{Slot: "accounts", Condition: &core.PassWhenCondition{Op: "all_of", Conditions: []*core.PassWhenCondition{
			{Op: core.OpMatchesIn, InSlot: "roster"},
			{Op: core.OpMatchesIn, InSlot: "other"},
		}}},
		{Slot: "other", Filter: &core.PassWhenCondition{Op: core.OpMatchesIn, InSlot: "hr"}, Condition: &core.PassWhenCondition{Op: "is_set", Field: "id"}},
	}}
	got := inSlotOnlySlots(spec)
	if len(got) != 2 {
		t.Fatalf("got %v; want roster and hr", got)
	}
	for _, s := range []string{"roster", "hr"} {
		if _, ok := got[s]; !ok {
			t.Errorf("missing %q in %v", s, got)
		}
	}
	if inSlotOnlySlots(nil) != nil {
		t.Error("nil spec must exclude nothing")
	}
}
