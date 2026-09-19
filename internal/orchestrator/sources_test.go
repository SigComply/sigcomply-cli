package orchestrator

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/log"
	"github.com/sigcomply/sigcomply-cli/internal/planner"
	"github.com/sigcomply/sigcomply-cli/internal/spec"
)

func planBinding(sourceID string) *planner.RunPlan {
	return &planner.RunPlan{Policies: []planner.PlannedPolicy{{
		Bindings: map[string][]planner.Binding{
			slotAccounts: {{SourceID: sourceID}},
		},
	}}}
}

// The banner prints every configured source before planning, so an
// unused one reads as active. This is the line that says otherwise.
func TestEmitUnboundSourceWarnings_NamesOnlyTheUnused(t *testing.T) {
	var buf bytes.Buffer
	cfg := &spec.ProjectConfig{Sources: map[string]map[string]any{
		sourceOkta:         {},
		"active_directory": {},
	}}
	emitUnboundSourceWarnings(log.New(&buf, false), cfg, planBinding(sourceOkta))

	got := buf.String()
	if !strings.Contains(got, "unbound-source: active_directory is configured but no policy slot accepts") {
		t.Errorf("log = %q; want the unbound warning for active_directory", got)
	}
	if strings.Contains(got, "unbound-source: "+sourceOkta) {
		t.Errorf("log = %q; must not warn about a source that bound", got)
	}
}

// Every source bound: silence. Otherwise the warning is noise on every run.
func TestEmitUnboundSourceWarnings_SilentWhenAllBound(t *testing.T) {
	var buf bytes.Buffer
	cfg := &spec.ProjectConfig{Sources: map[string]map[string]any{sourceOkta: {}}}
	emitUnboundSourceWarnings(log.New(&buf, false), cfg, planBinding(sourceOkta))
	if buf.String() != "" {
		t.Errorf("log = %q; want silence", buf.String())
	}
}

// Bracketed instances are distinct source IDs: aws.iam[prod] binding
// says nothing about aws.iam[staging].
func TestEmitUnboundSourceWarnings_InstancesAreDistinct(t *testing.T) {
	var buf bytes.Buffer
	cfg := &spec.ProjectConfig{Sources: map[string]map[string]any{
		"aws.iam[prod]":    {},
		"aws.iam[staging]": {},
	}}
	emitUnboundSourceWarnings(log.New(&buf, false), cfg, planBinding("aws.iam[prod]"))

	got := buf.String()
	if !strings.Contains(got, "aws.iam[staging]") {
		t.Errorf("log = %q; want the staging instance named", got)
	}
	if strings.Contains(got, "aws.iam[prod] is configured") {
		t.Errorf("log = %q; must not warn about the bound instance", got)
	}
}
