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
	"github.com/sigcomply/sigcomply-cli/internal/sources"
	"github.com/sigcomply/sigcomply-cli/internal/sources/azure/entra"
	_ "github.com/sigcomply/sigcomply-cli/internal/sources/builtin" // registers every source factory
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

const (
	outcomesDir          = "testdata/policy-outcomes"
	scenarioCompliant    = "compliant"
	scenarioNoncompliant = "noncompliant"

	// pluginSourcePrefix marks a record standing in for a project-local
	// plugin: input the schema allows that no in-tree source produces.
	pluginSourcePrefix = "plugin."
	pluginWhyPrefix    = "project-local plugin: "
	manualSourceID     = "manual.pdf"
)

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
	// Roster is the experimental.roster block of the project config every
	// scenario runs with.
	Roster map[string]any `json:"roster"`
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
// "compliant" (every policy passes, with values on the threshold where a
// policy has one), "noncompliant" (adds or swaps in records that break each
// policy, values one past the threshold) and "sparse" (most evidence types
// absent, optional fields left out, older type versions), which pins skip,
// error and vacuous outcomes. Records are synthetic, validated against their
// evidence-type schema, and attributed to a source that emits their type.
//
// The run is planned by the real planner from a project config that lists
// every source in the fixture, so bindings, the roster link and parameters
// are what a fully configured project gets. The collector step is the only
// one replaced: each binding receives the fixture records of its source and
// accepted types.
//
// A policy with no golden entry fails the test, so a new policy cannot ship
// without a pinned outcome. Independently of the golden, every policy must
// pass in "compliant" and fail in "noncompliant": regenerating cannot pin a
// policy that never passes or never fails.
func TestPolicyOutcomesGolden(t *testing.T) {
	fixture := loadOutcomeFixture(t)
	plugins := fixtureSources(t, fixture)

	ids := fwregistry.IDs()
	if len(ids) == 0 {
		t.Fatal("no framework registered")
	}
	for _, fwID := range ids {
		t.Run(fwID, func(t *testing.T) {
			plan := planFixtureRun(t, fwID, fixture, plugins)
			got := map[string]map[string]policyOutcome{}
			for _, scenario := range fixture.Scenarios {
				for id, out := range evaluateScenario(t, fixture, scenario, plan) {
					if got[id] == nil {
						got[id] = map[string]policyOutcome{}
					}
					got[id][scenario] = out
				}
			}
			checkEveryPolicyPassesAndFails(t, plan, got)
			compareOutcomeGolden(t, filepath.Join(outcomesDir, fwID+"_golden.json"), got)
		})
	}
}

// checkEveryPolicyPassesAndFails holds the fixture, not the golden, to the
// two outcomes that make a pinned verdict worth having: each policy passes
// on compliant evidence and fails on noncompliant evidence.
func checkEveryPolicyPassesAndFails(t *testing.T, plan *planner.RunPlan, got map[string]map[string]policyOutcome) {
	t.Helper()
	var bad []string
	for i := range plan.Policies {
		id := plan.Policies[i].Spec.ID
		c, n := got[id][scenarioCompliant], got[id][scenarioNoncompliant]
		if c.Status != core.StatusPass {
			bad = append(bad, fmt.Sprintf("%s: %s in %s; want pass", id, c.Status, scenarioCompliant))
		}
		if n.Status != core.StatusFail {
			bad = append(bad, fmt.Sprintf("%s: %s in %s; want fail", id, n.Status, scenarioNoncompliant))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("%d policy outcome(s) break the fixture invariant; extend records.json:\n  %s", len(bad), strings.Join(bad, "\n  "))
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

// fixtureSources builds the source plugin behind every source ID the
// fixture names, and fails unless it emits the type of each record
// attributed to it. In-tree sources are built from their factories with
// static dummy settings (no network call); azure.entra cannot be built
// without a credential, so its static Emits() is read from a bare
// instance. A plugin.* source is a stub emitting exactly its records'
// types.
func fixtureSources(t *testing.T, f *outcomeFixture) map[string]core.SourcePlugin {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	env := sources.Env{Config: map[string]any{
		"region": "us-east-1", "org": "acme", "group": "acme", "token": "dummy",
		"org_url": "https://example.okta.com", "api_token": "dummy",
	}}

	pluginTypes := map[string][]string{}
	for i := range f.Records {
		r := &f.Records[i]
		if strings.HasPrefix(r.SourceID, pluginSourcePrefix) {
			if !strings.HasPrefix(r.Why, pluginWhyPrefix) {
				t.Errorf("records.json: %s/%s: a %s* record must say why in a why starting %q", r.SourceID, r.ID, pluginSourcePrefix, pluginWhyPrefix)
			}
			if !slices.Contains(pluginTypes[r.SourceID], r.Type) {
				pluginTypes[r.SourceID] = append(pluginTypes[r.SourceID], r.Type)
			}
		}
	}

	out := map[string]core.SourcePlugin{manualSourceID: stubSource{id: manualSourceID, emits: []string{"signed_document"}}}
	for i := range f.Records {
		id := f.Records[i].SourceID
		if _, done := out[id]; done {
			continue
		}
		switch {
		case strings.HasPrefix(id, pluginSourcePrefix):
			out[id] = stubSource{id: id, emits: pluginTypes[id]}
		case id == entra.SourceID:
			out[id] = entra.New(entra.Options{})
		default:
			p, err := sources.Build(context.Background(), id, env)
			if err != nil {
				t.Fatalf("records.json: source %q: %v (name an in-tree source, or %s<name> for plugin-shaped input)", id, err, pluginSourcePrefix)
			}
			out[id] = p
		}
	}
	for i := range f.Records {
		r := &f.Records[i]
		if !slices.Contains(out[r.SourceID].Emits(), r.Type) {
			t.Errorf("records.json: %s/%s: source %s does not emit %s (it emits %v)", r.SourceID, r.ID, r.SourceID, r.Type, out[r.SourceID].Emits())
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	return out
}

// stubSource stands in for a source that cannot be built here. The planner
// reads only ID and Emits; nothing collects.
type stubSource struct {
	id    string
	emits []string
}

func (s stubSource) ID() string                               { return s.id }
func (s stubSource) Emits() []string                          { return s.emits }
func (stubSource) Init(context.Context, map[string]any) error { return nil }
func (s stubSource) Collect(context.Context, core.SlotRequest) ([]core.EvidenceRecord, error) {
	return nil, fmt.Errorf("stub source %s does not collect", s.id)
}

// planFixtureRun plans a first run of the framework for a project that
// configures every fixture source and the fixture's roster block.
func planFixtureRun(t *testing.T, fwID string, f *outcomeFixture, plugins map[string]core.SourcePlugin) *planner.RunPlan {
	t.Helper()
	fw, ok := fwregistry.Lookup(fwID)
	if !ok {
		t.Fatalf("framework %q not registered", fwID)
	}
	set := registry.NewSet()
	if err := evidencetypes.Register(set); err != nil {
		t.Fatal(err)
	}
	if err := fw.Register(set); err != nil {
		t.Fatalf("register %s: %v", fwID, err)
	}
	cfg := &spec.ProjectConfig{
		Framework:    fwID,
		Sources:      map[string]map[string]any{},
		Experimental: map[string]any{spec.RosterKey: f.Roster},
	}
	for id, p := range plugins {
		if err := set.Sources.Register(p); err != nil {
			t.Fatal(err)
		}
		cfg.Sources[id] = map[string]any{}
	}
	now := time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC)
	plan, err := planner.Plan(&planner.Input{Config: cfg, Registries: set, CommitTime: now, Now: now})
	if err != nil {
		t.Fatalf("plan %s: %v", fwID, err)
	}
	if len(plan.Policies) == 0 {
		t.Fatalf("framework %q planned no policies", fwID)
	}
	for i := range plan.Policies {
		if !plan.Policies[i].ShouldEvaluate {
			t.Fatalf("%s: planned as not due on a first run", plan.Policies[i].Spec.ID)
		}
	}
	return plan
}

// evaluateScenario runs the plan against the scenario's records and
// returns each policy's outcome.
func evaluateScenario(t *testing.T, f *outcomeFixture, scenario string, plan *planner.RunPlan) map[string]policyOutcome {
	t.Helper()
	records := scenarioRecords(f, scenario)
	byPolicy := map[string]map[string][]core.EvidenceRecord{}
	for i := range plan.Policies {
		pp := &plan.Policies[i]
		byPolicy[pp.Spec.ID] = boundRecords(pp, records, f, scenario)
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

// boundRecords stands in for the collector: each binding of a slot gets
// the records of its source whose type the binding accepts. A manual
// policy gets the scenario's signed_document record, if any.
func boundRecords(pp *planner.PlannedPolicy, records []core.EvidenceRecord, f *outcomeFixture, scenario string) map[string][]core.EvidenceRecord {
	slots := map[string][]core.EvidenceRecord{}
	if pp.Spec.EvidenceMode == core.EvidenceModeManual {
		if payload, ok := f.Manual[scenario]; ok {
			slots[spec.ManualSlotName] = []core.EvidenceRecord{{
				Type: "signed_document", ID: "manual/" + pp.Spec.CatalogEntry, SourceID: manualSourceID, Payload: payload,
			}}
		}
		return slots
	}
	for slot, bindings := range pp.Bindings {
		for _, b := range bindings {
			for i := range records {
				if records[i].SourceID == b.SourceID && slices.Contains(b.AcceptedTypes, records[i].Type) {
					slots[slot] = append(slots[slot], records[i])
				}
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
