package frameworks_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sigcomply/sigcomply-cli/internal/core"
	"github.com/sigcomply/sigcomply-cli/internal/evaluator"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
)

const (
	traceRepo       = "acme/web"
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
