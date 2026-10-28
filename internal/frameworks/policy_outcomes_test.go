package frameworks_test

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
	evidencetypes "github.com/sigcomply/sigcomply-cli/internal/evidence_types"
	fwregistry "github.com/sigcomply/sigcomply-cli/internal/frameworks"
	_ "github.com/sigcomply/sigcomply-cli/internal/frameworks/builtin" // registers every framework
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

// updatePolicyOutcomes regenerates testdata/policy-outcomes/<framework>_golden.json:
//
//	go test ./internal/frameworks/ -run TestPolicyOutcomesGolden -update
//
// Read the diff before committing it. Every changed line is a policy whose
// verdict on the same evidence changed; that is either the point of the
// change or a regression.
var updatePolicyOutcomes = flag.Bool("update", false, "regenerate the policy outcome goldens")

const outcomesDir = "testdata/policy-outcomes"

// outcomeRecord is one evidence record in records.json. Scenarios names
// the scenarios it belongs to; Why says what it is there to prove and is
// never read.
type outcomeRecord struct {
	Scenarios []string        `json:"scenarios"`
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	SourceID  string          `json:"source_id"`
	Why       string          `json:"why,omitempty"`
	Payload   json.RawMessage `json:"payload"`
}

type outcomeFixture struct {
	Scenarios []string `json:"scenarios"`
	// Roster is the experimental.roster block every scenario runs with.
	Roster struct {
		Source   string                       `json:"source"`
		Aliases  map[string]map[string]string `json:"aliases"`
		NonHuman map[string][]string          `json:"non_human"`
	} `json:"roster"`
	// Manual maps a scenario to the signed_document payload every manual
	// policy receives in it. A scenario that is absent gets no record.
	Manual  map[string]json.RawMessage `json:"manual"`
	Records []outcomeRecord            `json:"records"`
}

// policyOutcome is what the golden pins for one policy in one scenario.
type policyOutcome struct {
	Status             core.PolicyStatus `json:"status"`
	ResourcesEvaluated int               `json:"resources_evaluated"`
	ResourcesFailed    int               `json:"resources_failed"`
	Violated           []string          `json:"violated,omitempty"`
	VacuousSlots       []string          `json:"vacuous_slots,omitempty"`
	Reason             string            `json:"reason,omitempty"`
}

// TestPolicyOutcomesGolden runs every shipped policy of every registered
// framework through the real evaluator against a committed evidence fixture
// and pins each verdict: status, counts and the IDs of the resources it
// flags.
//
// Why this exists: the framework tests check that policies are well formed,
// and a handful of policies have behavior tests. Nothing else notices when
// a threshold, an operator, a filter or a slot's accepted types changes what
// a policy decides. This does, for every policy at once.
//
// The fixture (testdata/policy-outcomes/records.json) has three scenarios:
// "compliant" (every automated policy should pass, with values on the
// threshold where a policy has one), "noncompliant" (adds or swaps in
// records that break each policy, values one past the threshold) and
// "sparse" (most evidence types absent, optional fields left out, older
// type versions), which pins skip, error and vacuous outcomes. Records are
// synthetic and validated against their evidence-type schema.
//
// A policy with no golden entry fails the test, so a new policy cannot ship
// without a pinned outcome.
func TestPolicyOutcomesGolden(t *testing.T) {
	fixture := loadOutcomeFixture(t)

	ids := fwregistry.IDs()
	if len(ids) == 0 {
		t.Fatal("no framework registered")
	}
	for _, fwID := range ids {
		t.Run(fwID, func(t *testing.T) {
			policies := frameworkPolicies(t, fwID)
			got := map[string]map[string]policyOutcome{}
			for _, scenario := range fixture.Scenarios {
				for id, out := range evaluateScenario(t, fixture, scenario, policies) {
					if got[id] == nil {
						got[id] = map[string]policyOutcome{}
					}
					got[id][scenario] = out
				}
			}
			compareOutcomeGolden(t, filepath.Join(outcomesDir, fwID+"_golden.json"), got)
		})
	}
}

func loadOutcomeFixture(t *testing.T) *outcomeFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(outcomesDir, "records.json"))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f outcomeFixture
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("records.json: %v", err)
	}

	set := registry.NewSet()
	if err := evidencetypes.Register(set); err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, s := range f.Scenarios {
		known[s] = true
	}
	seen := map[string]bool{}
	for i := range f.Records {
		r := &f.Records[i]
		key := r.SourceID + "|" + r.Type + "|" + r.ID
		if seen[key] {
			t.Errorf("records.json: duplicate record %s", key)
		}
		seen[key] = true
		if len(r.Scenarios) == 0 {
			t.Errorf("records.json: record %s belongs to no scenario", key)
		}
		for _, s := range r.Scenarios {
			if !known[s] {
				t.Errorf("records.json: record %s names unknown scenario %q", key, s)
			}
		}
		validateFixturePayload(t, set, r.Type, key, r.Payload)
	}
	for s, p := range f.Manual {
		if !known[s] {
			t.Errorf("records.json: manual payload for unknown scenario %q", s)
		}
		validateFixturePayload(t, set, "signed_document", "manual/"+s, p)
	}
	if t.Failed() {
		t.FailNow()
	}
	return &f
}

// validateFixturePayload holds the fixture to the same schema check the
// collector applies before signing, so no record could not have come from
// a real source.
func validateFixturePayload(t *testing.T, set *registry.Set, typeID, key string, payload json.RawMessage) {
	t.Helper()
	et, ok := set.EvidenceTypes.Lookup(typeID)
	if !ok {
		t.Errorf("records.json: record %s has unregistered type %q", key, typeID)
		return
	}
	if err := evidencetypes.Validate(et.Schema, payload); err != nil {
		t.Errorf("records.json: record %s: %v", key, err)
	}
}

// frameworkPolicies returns every policy the framework registers, sorted by ID.
func frameworkPolicies(t *testing.T, fwID string) []core.Policy {
	t.Helper()
	f, ok := fwregistry.Lookup(fwID)
	if !ok {
		t.Fatalf("framework %q not registered", fwID)
	}
	set := registry.NewSet()
	if err := f.Register(set); err != nil {
		t.Fatalf("register %s: %v", fwID, err)
	}
	policies := set.Policies.All()
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	if len(policies) == 0 {
		t.Fatalf("framework %q registers no policies", fwID)
	}
	return policies
}

// evaluateScenario runs every policy against the scenario's records and
// returns each policy's outcome.
func evaluateScenario(t *testing.T, f *outcomeFixture, scenario string, policies []core.Policy) map[string]policyOutcome {
	t.Helper()
	records := scenarioRecords(f, scenario)
	roster := &planner.RosterLink{Source: f.Roster.Source, Aliases: f.Roster.Aliases, NonHuman: f.Roster.NonHuman}

	plan := &planner.RunPlan{}
	byPolicy := map[string]map[string][]core.EvidenceRecord{}
	for i := range policies {
		p := &policies[i]
		pp := planner.PlannedPolicy{Spec: *p, Parameters: map[string]any{}, ShouldEvaluate: true}
		for _, slot := range p.Slots {
			if slot.Role != core.SlotRoleNone {
				pp.Roster = roster
			}
		}
		plan.Policies = append(plan.Policies, pp)
		byPolicy[p.ID] = slotRecords(p, records, f, scenario)
	}

	results, err := evaluator.Evaluate(context.Background(), &evaluator.Input{
		Plan:            plan,
		RecordsByPolicy: byPolicy,
		Now:             time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("%s: Evaluate: %v", scenario, err)
	}
	out := make(map[string]policyOutcome, len(results))
	for i := range results {
		out[results[i].PolicyID] = outcomeOf(&results[i])
	}
	return out
}

func scenarioRecords(f *outcomeFixture, scenario string) []core.EvidenceRecord {
	var records []core.EvidenceRecord
	for i := range f.Records {
		r := &f.Records[i]
		if slices.Contains(r.Scenarios, scenario) {
			records = append(records, core.EvidenceRecord{
				Type: r.Type, ID: r.ID, SourceID: r.SourceID, Payload: r.Payload,
				CollectedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
			})
		}
	}
	return records
}

// slotRecords feeds a policy's slots the way a run with every source
// configured would: a slot receives every record whose type it accepts,
// except that a roster slot binds only the roster source and a
// roster_subject slot never does (the planner keeps the two disjoint). A
// manual policy gets the scenario's signed_document record, if any.
func slotRecords(p *core.Policy, records []core.EvidenceRecord, f *outcomeFixture, scenario string) map[string][]core.EvidenceRecord {
	slots := map[string][]core.EvidenceRecord{}
	if p.EvidenceMode == core.EvidenceModeManual {
		if payload, ok := f.Manual[scenario]; ok {
			slots[spec.ManualSlotName] = []core.EvidenceRecord{{
				Type: "signed_document", ID: "manual/" + p.CatalogEntry, SourceID: "manual", Payload: payload,
			}}
		}
	}
	for name, slot := range p.Slots {
		for i := range records {
			rec := &records[i]
			fromRoster := rec.SourceID == f.Roster.Source
			switch {
			case !slices.Contains(slot.Accepts, rec.Type):
			case slot.Role == core.SlotRoleRosterSubject && fromRoster:
			case slot.Role == core.SlotRoleRoster && !fromRoster:
			default:
				slots[name] = append(slots[name], *rec)
			}
		}
	}
	return slots
}

func outcomeOf(r *core.PolicyResult) policyOutcome {
	o := policyOutcome{
		Status:             r.Status,
		ResourcesEvaluated: r.ResourcesEvaluated,
		ResourcesFailed:    r.ResourcesFailed,
		VacuousSlots:       r.VacuousSlots(),
	}
	for _, v := range r.Violations {
		o.Violated = append(o.Violated, v.ResourceID)
	}
	sort.Strings(o.Violated)
	if r.Status == core.StatusError || r.Status == core.StatusSkip {
		for _, k := range []string{"reason", "rule_error", "collect_error"} {
			if s, ok := r.Diag[k].(string); ok && s != "" {
				o.Reason = s
				break
			}
		}
	}
	return o
}

// compareOutcomeGolden writes the golden under -update, then reports every
// policy whose outcome differs from it, by name.
func compareOutcomeGolden(t *testing.T, path string, got map[string]map[string]policyOutcome) {
	t.Helper()
	// encoding/json sorts map keys, so the file is stable and diffs by policy.
	buf, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	buf = append(buf, '\n')
	if *updatePolicyOutcomes {
		if err := os.WriteFile(path, buf, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path) //nolint:gosec // #nosec G304 -- fixed testdata path
	if err != nil {
		t.Fatalf("%v (generate with -update)", err)
	}
	var want map[string]map[string]policyOutcome
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("%s: %v", path, err)
	}

	var problems []string
	for id, scenarios := range got {
		w, ok := want[id]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: no golden entry (a new policy needs a pinned outcome)", id))
			continue
		}
		for scenario, g := range scenarios {
			gj, _ := json.Marshal(g)           //nolint:errcheck // plain struct
			wj, _ := json.Marshal(w[scenario]) //nolint:errcheck // plain struct
			if !bytes.Equal(gj, wj) {
				problems = append(problems, fmt.Sprintf("%s [%s]:\n      got  %s\n      want %s", id, scenario, gj, wj))
			}
		}
	}
	for id := range want {
		if _, ok := got[id]; !ok {
			problems = append(problems, fmt.Sprintf("%s: in the golden but no longer registered", id))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		t.Errorf("%d policy outcome(s) differ from %s:\n  %s\nIf every change is intended, regenerate with -update and review the diff.",
			len(problems), path, strings.Join(problems, "\n  "))
		return
	}
	if !bytes.Equal(raw, buf) {
		t.Errorf("%s is not in canonical form; regenerate with -update", path)
	}
}
