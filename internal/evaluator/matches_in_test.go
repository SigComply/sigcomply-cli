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

// slotOther is a slot name used only to exercise unresolved-slot paths.
const slotOther = "other"

// rec builds a record with an explicit source and type.
func rec(source, typ, id string, payload map[string]any) core.EvidenceRecord {
	p, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return core.EvidenceRecord{ID: id, Type: typ, SourceID: source, Payload: p, CollectedAt: time.Now()}
}

func account(source, id string, payload map[string]any) core.EvidenceRecord {
	return rec(source, testTypeDirectoryUser, id, payload)
}

func person(id, email, status string) core.EvidenceRecord {
	return rec("okta", "roster_entry", id, map[string]any{linkedByEmail: email, keyStatus: status})
}

func matchesIn(field, normalize string, where *core.PassWhenCondition) *core.PassWhenCondition {
	return &core.PassWhenCondition{
		Op: core.OpMatchesIn, Field: field, InSlot: slotRoster,
		RemoteField: fieldPayloadEmail, Normalize: normalize, Where: where,
	}
}

func linkedClause(cond, filter *core.PassWhenCondition) *core.PassWhenSpec {
	return &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:         slotAccounts,
		Quantifier:   core.QuantifierAll,
		Condition:    cond,
		Filter:       filter,
		IdentityKey:  fieldAccountRef,
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
		slotAccounts: {
			account(testSourceGitHub, "u1", map[string]any{linkedByEmail: testEmailJane}),
			account(testSourceGitHub, "u2", map[string]any{linkedByEmail: "ghost@acme.com"}),
		},
		slotRoster: {person("p1", testEmailJane, statusActive)},
	}
	got := evaluatePassWhen(linkedClause(matchesIn(fieldPayloadEmail, "", nil), nil), newEvalCtx(slots, nil, nil))
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
		slotAccounts: {account(testSourceGitHub, "u1", map[string]any{linkedByEmail: "  Jane@ACME.com "})},
		slotRoster:   {person("p1", "jane@acme.COM", statusActive)},
	}
	exact := evaluatePassWhen(linkedClause(matchesIn(fieldPayloadEmail, "", nil), nil), newEvalCtx(slots, nil, nil))
	if exact.Status != core.StatusFail {
		t.Errorf("exact compare: status = %q; want fail", exact.Status)
	}
	norm := evaluatePassWhen(linkedClause(matchesIn(fieldPayloadEmail, core.NormalizeLowerTrim, nil), nil), newEvalCtx(slots, nil, nil))
	if norm.Status != core.StatusPass {
		t.Errorf("lower_trim: status = %q; want pass (%v)", norm.Status, norm.Violations)
	}
}

// A local record without a usable key can never be proven linked: it is
// a non-match, not an error. Remote records without a key never match.
func TestMatchesIn_MissingKeys(t *testing.T) {
	slots := map[string][]core.EvidenceRecord{
		slotAccounts: {
			account(testSourceGitHub, "nokey", map[string]any{}),
			account(testSourceGitHub, "blank", map[string]any{linkedByEmail: "   "}),
			account(testSourceGitHub, "num", map[string]any{linkedByEmail: 5}),
		},
		slotRoster: {
			rec("okta", "roster_entry", "p1", map[string]any{keyStatus: statusActive}),
			rec("okta", "roster_entry", "p2", map[string]any{keyStatus: statusActive, linkedByEmail: ""}),
		},
	}
	got := evaluatePassWhen(linkedClause(matchesIn(fieldPayloadEmail, core.NormalizeLowerTrim, nil), nil), newEvalCtx(slots, nil, nil))
	if got.Status != core.StatusFail || len(got.Violations) != 3 {
		t.Fatalf("status = %q violations = %v; want fail with 3", got.Status, violationIDs(got))
	}
}

func TestMatchesIn_WhereFiltersRemote(t *testing.T) {
	inactive := &core.PassWhenCondition{Op: "eq", Field: "payload.status", Value: statusInactive}
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:        slotAccounts,
		Quantifier:  core.QuantifierNone,
		Condition:   matchesIn("account.key", core.NormalizeLowerTrim, inactive),
		IdentityKey: fieldAccountRef,
	}}}
	slots := map[string][]core.EvidenceRecord{
		slotAccounts: {
			account(testSourceGitHub, "jane", map[string]any{linkedByEmail: testEmailJane}),
			account(testSourceGitHub, "bob", map[string]any{linkedByEmail: "bob@acme.com"}),
		},
		slotRoster: {
			person("p1", testEmailJane, statusActive),
			person("p2", "BOB@acme.com", statusInactive),
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
	where := &core.PassWhenCondition{Op: "eq", Field: "payload.nope", Value: statusInactive}
	slots := map[string][]core.EvidenceRecord{
		slotAccounts: {account(testSourceGitHub, "jane", map[string]any{linkedByEmail: testEmailJane})},
		slotRoster:   {person("p1", testEmailJane, statusInactive)},
	}
	spec := linkedClause(matchesIn(fieldPayloadEmail, "", where), nil)
	if got := evaluatePassWhen(spec, newEvalCtx(slots, nil, nil)); got.Status != core.StatusError {
		t.Errorf("status = %q; want error", got.Status)
	}
}

// Filters are lenient, but a matches_in index is built before any record
// loop, so a bad where inside a filter still errors the policy instead of
// excluding every record and passing vacuously.
func TestMatchesIn_InFilterWithBadWhere_Errors(t *testing.T) {
	where := &core.PassWhenCondition{Op: "eq", Field: "payload.nope", Value: "x"}
	filter := matchesIn(fieldPayloadEmail, "", where)
	cond := &core.PassWhenCondition{Op: "eq", Field: fieldPayloadMFA, Value: true}
	slots := map[string][]core.EvidenceRecord{
		slotAccounts: {account(testSourceGitHub, "jane", map[string]any{linkedByEmail: testEmailJane, keyMFA: false})},
		slotRoster:   {person("p1", testEmailJane, statusActive)},
	}
	if got := evaluatePassWhen(linkedClause(cond, filter), newEvalCtx(slots, nil, nil)); got.Status != core.StatusError {
		t.Errorf("status = %q; want error", got.Status)
	}
}

func TestMatchesIn_UndeclaredSlot_Errors(t *testing.T) {
	cond := &core.PassWhenCondition{Op: core.OpMatchesIn, Field: fieldPayloadEmail, InSlot: "rostr", RemoteField: fieldPayloadEmail}
	slots := map[string][]core.EvidenceRecord{
		slotAccounts: {account(testSourceGitHub, "jane", map[string]any{linkedByEmail: testEmailJane})},
	}
	if got := evaluatePassWhen(linkedClause(cond, nil), newEvalCtx(slots, nil, nil)); got.Status != core.StatusError {
		t.Errorf("no such slot key: status = %q; want error", got.Status)
	}
	ec := newEvalCtx(slots, nil, nil)
	ec.declared = map[string]core.Slot{slotAccounts: {}, slotRoster: {}}
	if got := evaluatePassWhen(linkedClause(cond, nil), ec); got.Status != core.StatusError {
		t.Errorf("undeclared slot: status = %q; want error", got.Status)
	}
}

func TestMatchesIn_EmptyRemoteSlot_IsVacuous(t *testing.T) {
	spec := &core.PassWhenSpec{Clauses: []core.PassWhenClause{{
		Slot:       slotAccounts,
		Quantifier: core.QuantifierNone,
		Condition:  matchesIn(fieldPayloadEmail, "", nil),
	}}}
	slots := map[string][]core.EvidenceRecord{
		slotAccounts: {account(testSourceGitHub, "jane", map[string]any{linkedByEmail: testEmailJane})},
	}
	// Declared but unbound: the collector writes no key for it.
	ec := newEvalCtx(slots, nil, nil)
	ec.declared = map[string]core.Slot{slotAccounts: {}, slotRoster: {}}
	got := evaluatePassWhen(spec, ec)
	if got.Status != core.StatusPass {
		t.Fatalf("status = %q; want pass", got.Status)
	}
	v, ok := got.Diag["vacuous_clauses"].([]string)
	if !ok || len(v) != 1 || v[0] != slotAccounts {
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
				slotRoster:   {Accepts: []string{"roster_entry"}, Required: true, Role: core.SlotRoleRoster},
				slotAccounts: {Accepts: []string{testTypeDirectoryUser}, Required: true, Role: core.SlotRoleRosterSubject},
			},
			PassWhen: linkedClause(matchesIn("account.key", core.NormalizeLowerTrim, nil), nil),
		},
		ShouldEvaluate: true,
		Roster:         &planner.RosterLink{Source: "okta"},
	}
	in := &Input{
		Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}},
		RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{"p1": {
			slotAccounts: {
				account(testSourceGitHub, "jane", map[string]any{linkedByEmail: testEmailJane}),
				account(testSourceGitHub, "ghost", map[string]any{linkedByEmail: "ghost@acme.com"}),
			},
			slotRoster: {person("p1", testEmailJane, statusActive), person("p2", "x@acme.com", statusActive), person("p3", "y@acme.com", statusActive)},
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
		{Slot: slotAccounts, Condition: &core.PassWhenCondition{Op: opAllOf, Conditions: []*core.PassWhenCondition{
			{Op: core.OpMatchesIn, InSlot: slotRoster},
			{Op: core.OpMatchesIn, InSlot: slotOther},
		}}},
		{Slot: slotOther, Filter: &core.PassWhenCondition{Op: core.OpMatchesIn, InSlot: "hr"}, Condition: &core.PassWhenCondition{Op: opIsSet, Field: "id"}},
	}}
	got := inSlotOnlySlots(spec)
	if len(got) != 2 {
		t.Fatalf("got %v; want roster and hr", got)
	}
	for _, s := range []string{slotRoster, "hr"} {
		if _, ok := got[s]; !ok {
			t.Errorf("missing %q in %v", s, got)
		}
	}
	if inSlotOnlySlots(nil) != nil {
		t.Error("nil spec must exclude nothing")
	}
}
