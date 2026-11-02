package frameworks_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/collector"
	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/registry"
	"github.com/sigcomply/sigcomply-cli/internal/sources/github"
	"github.com/sigcomply/sigcomply-cli/internal/sources/gitlab"
	"github.com/sigcomply/sigcomply-cli/internal/vault/local"
)

const (
	traceRepo       = "acme/web"
	traceSHA        = "f00dfeed"
	traceEnvProd    = "production"
	traceDeployer   = "bob"
	traceStatusOK   = "success"
	traceTypeDeploy = "deployment"
	traceSlotDeploy = "deployments"
	traceSlotChange = "changes"
	traceSourceGH   = "github"
)

// The SOC 2 and ISO 27001 copies of the deployment-traceability policy are
// built separately, so each behavior is pinned for both.
var deploymentTraceabilityPolicies = []struct{ fw, id string }{
	{"soc2", "soc2.cc8.1.production_deploys_from_approved_changes"},
	{"iso27001", "iso27001.8.32.production_deploys_from_approved_changes"},
}

func deploymentTraceabilitySpec(t *testing.T, fw, id string) core.Policy {
	t.Helper()
	policies := frameworkPolicies(t, fw)
	for i := range policies {
		if policies[i].ID == id {
			return policies[i]
		}
	}
	t.Fatalf("policy %s not found in %s", id, fw)
	return core.Policy{}
}

// A production deployment of a commit no merged change produced (a direct
// push deployed by CI) is the unreviewed release the control exists to
// catch. When the period has no merged change at all the bound `changes`
// lookup slot is empty, and the deployment must still fail rather than skip:
// one unrelated approved change already makes the same deployment fail.
func TestDeploymentTraceability_NoMergedChangesFailsProductionDeploy(t *testing.T) {
	for _, tc := range deploymentTraceabilityPolicies {
		t.Run(tc.id, func(t *testing.T) {
			spec := deploymentTraceabilitySpec(t, tc.fw, tc.id)
			body, err := json.Marshal(map[string]any{
				"repository": traceRepo, "deployment_id": "900", "environment": traceEnvProd,
				"is_production": true, "deployed_by": traceDeployer, "deployed_at": "2026-08-02T10:00:00Z",
				"commit_sha": "direct-push-sha", "status": traceStatusOK,
			})
			if err != nil {
				t.Fatal(err)
			}
			deploy := core.EvidenceRecord{Type: traceTypeDeploy, ID: traceRepo + "/deployments/900", SourceID: traceSourceGH, Payload: body}
			// github emits both types, so the planner binds it to both slots.
			bindings := map[string][]planner.Binding{
				traceSlotDeploy: {{SourceID: traceSourceGH, AcceptedTypes: []string{traceTypeDeploy}}},
				traceSlotChange: {{SourceID: traceSourceGH, AcceptedTypes: []string{"pull_request"}}},
			}
			in := &evaluator.Input{
				Plan: &planner.RunPlan{Policies: []planner.PlannedPolicy{{
					Spec: spec, Parameters: map[string]any{}, ShouldEvaluate: true, Bindings: bindings,
				}}},
				RecordsByPolicy: map[string]map[string][]core.EvidenceRecord{
					tc.id: {traceSlotDeploy: {deploy}, traceSlotChange: {}},
				},
				Now: time.Date(2026, 9, 18, 0, 0, 0, 0, time.UTC),
			}
			res, err := evaluator.Evaluate(context.Background(), in)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if len(res) != 1 {
				t.Fatalf("got %d results; want 1", len(res))
			}
			got := res[0]
			if got.Status != core.StatusFail {
				t.Fatalf("status = %q (diag %v); want fail: deployment of direct-push-sha traces to no approved change", got.Status, got.Diag)
			}
			if got.ResourcesEvaluated != 1 || got.ResourcesFailed != 1 {
				t.Errorf("resources evaluated/failed = %d/%d; want 1/1", got.ResourcesEvaluated, got.ResourcesFailed)
			}
		})
	}
}

// Fakes for the two plugins that emit both types. Each embeds the API
// interface so only the two listings this policy reads need bodies; the
// plugin re-applies the window it is given, which is what is under test.
type ghTraceAPI struct {
	github.API
	pulls   []github.PullRequest
	deploys []github.Deployment
}

func (f *ghTraceAPI) ListMergedPullRequests(context.Context, time.Time, time.Time) ([]github.PullRequest, error) {
	return f.pulls, nil
}

func (f *ghTraceAPI) ListDeployments(context.Context, time.Time, time.Time) ([]github.Deployment, error) {
	return f.deploys, nil
}

type glTraceAPI struct {
	gitlab.API
	pulls   []gitlab.PullRequest
	deploys []gitlab.Deployment
}

func (f *glTraceAPI) ListMergedPullRequests(context.Context, time.Time, time.Time) ([]gitlab.PullRequest, error) {
	return f.pulls, nil
}

func (f *glTraceAPI) ListDeployments(context.Context, time.Time, time.Time) ([]gitlab.Deployment, error) {
	return f.deploys, nil
}

// A deployment inside the period of a change approved and merged before it
// (a release merged on the last day of one quarter and deployed on the first
// day of the next, or a rollback) ships an approved change. The `changes`
// lookup slot reads back changeLookback (90 days) before the period, so the
// deployment traces; a change merged further back than that is not read.
// This runs the real plugin, collector and evaluator for both vendors.
func TestDeploymentTraceability_DeployOfChangeMergedBeforePeriod(t *testing.T) {
	periodStart := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, time.March, 31, 23, 59, 59, 0, time.UTC)
	deployedAt := periodStart.Add(2 * time.Hour)
	approver := "carol"

	cases := []struct {
		name       string
		mergedAt   time.Time
		wantStatus core.PolicyStatus
	}{
		{"merged two hours before the period passes", periodStart.Add(-2 * time.Hour), core.StatusPass},
		{"merged exactly 90 days before the period passes", periodStart.Add(-90 * 24 * time.Hour), core.StatusPass},
		{"merged more than 90 days before the period fails", periodStart.Add(-90*24*time.Hour - time.Second), core.StatusFail},
	}
	vendors := map[string]func(mergedAt time.Time) core.SourcePlugin{
		traceSourceGH: func(mergedAt time.Time) core.SourcePlugin {
			return github.New(github.Options{Org: "acme-corp", Now: func() time.Time { return periodEnd }, API: &ghTraceAPI{
				pulls: []github.PullRequest{{
					Repository: traceRepo, Number: 7, Author: "alice", MergedBy: traceDeployer, TargetBranch: "main",
					MergeCommitSHA: traceSHA, MergedAt: mergedAt,
					Reviews: []github.Review{{User: approver, State: "APPROVED", SubmittedAt: mergedAt.Add(-time.Hour)}},
				}},
				deploys: []github.Deployment{{
					Repository: traceRepo, ID: "99", Environment: traceEnvProd, ProductionEnvironment: true,
					Creator: traceDeployer, CreatedAt: deployedAt, SHA: traceSHA, State: traceStatusOK,
				}},
			}})
		},
		"gitlab": func(mergedAt time.Time) core.SourcePlugin {
			return gitlab.New(gitlab.Options{Now: func() time.Time { return periodEnd }, API: &glTraceAPI{
				pulls: []gitlab.PullRequest{{
					Repository: traceRepo, Number: 7, Author: "alice", MergedBy: traceDeployer, TargetBranch: "main",
					MergeCommitSHA: traceSHA, MergedAt: mergedAt, Approvers: []string{approver},
				}},
				deploys: []gitlab.Deployment{{
					Repository: traceRepo, ID: "99", Environment: traceEnvProd, EnvironmentTier: traceEnvProd,
					Creator: traceDeployer, CreatedAt: deployedAt, SHA: traceSHA, Status: traceStatusOK,
				}},
			}})
		},
	}

	for _, pol := range deploymentTraceabilityPolicies {
		spec := deploymentTraceabilitySpec(t, pol.fw, pol.id)
		for vendor, build := range vendors {
			for _, tc := range cases {
				t.Run(pol.fw+"/"+vendor+"/"+tc.name, func(t *testing.T) {
					reg := registry.NewSet()
					if err := reg.Sources.Register(build(tc.mergedAt)); err != nil {
						t.Fatal(err)
					}
					pp := planner.PlannedPolicy{
						Spec: spec, Parameters: map[string]any{}, ShouldEvaluate: true,
						Bindings: map[string][]planner.Binding{
							traceSlotDeploy: {{SourceID: vendor, AcceptedTypes: []string{traceTypeDeploy}}},
							traceSlotChange: {{SourceID: vendor, AcceptedTypes: []string{"pull_request"}}},
						},
					}
					plan := &planner.RunPlan{Policies: []planner.PlannedPolicy{pp}}
					out, err := collector.Collect(context.Background(), &collector.Input{
						Plan: plan, Sources: reg.Sources, Vault: local.New(t.TempDir()), RunRoot: "run",
						SlotParamsExtras: map[string]any{"period_id": "2026-Q1", "period_start": periodStart, "period_end": periodEnd},
						Now:              periodEnd,
					})
					if err != nil {
						t.Fatalf("Collect: %v", err)
					}
					if e := out.CollectErrorsByPolicy[pol.id]; e != nil {
						t.Fatalf("collect error: %v", e)
					}
					res, err := evaluator.Evaluate(context.Background(), &evaluator.Input{
						Plan: plan, RecordsByPolicy: out.RecordsByPolicy, Now: periodEnd,
					})
					if err != nil {
						t.Fatalf("Evaluate: %v", err)
					}
					got := res[0]
					if got.Status != tc.wantStatus {
						t.Errorf("status = %q; want %q (changes=%d, violations=%+v)",
							got.Status, tc.wantStatus, len(out.RecordsByPolicy[pol.id][traceSlotChange]), got.Violations)
					}
					// The changes read from before the period are a lookup
					// table: the deployment is the only resource evaluated.
					if got.ResourcesEvaluated != 1 {
						t.Errorf("ResourcesEvaluated = %d; want 1 (the deployment only)", got.ResourcesEvaluated)
					}
				})
			}
		}
	}
}
