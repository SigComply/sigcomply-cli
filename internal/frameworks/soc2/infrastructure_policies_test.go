package soc2

import (
	"context"
	"strings"
	"testing"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// --- helpers --------------------------------------------------------

func trailRec(t *testing.T, id, name string, multi, logging bool) core.EvidenceRecord {
	t.Helper()
	payload := mustMarshal(t, map[string]any{
		"name":                  name,
		"is_multi_region_trail": multi,
		"is_logging":            logging,
	})
	return core.EvidenceRecord{
		Type:     "cloudtrail_trail",
		ID:       id,
		Payload:  payload,
		SourceID: "aws.cloudtrail",
	}
}

func logGroupRec(t *testing.T, id, name string, set bool, days int) core.EvidenceRecord {
	t.Helper()
	payload := mustMarshal(t, map[string]any{
		"name":              name,
		"retention_set":     set,
		"retention_in_days": days,
	})
	return core.EvidenceRecord{
		Type:     "cloudwatch_log_group",
		ID:       id,
		Payload:  payload,
		SourceID: "aws.cloudwatch",
	}
}

func detectorRec(t *testing.T, id string, enabled bool) core.EvidenceRecord {
	t.Helper()
	payload := mustMarshal(t, map[string]any{
		"detector_id": id,
		"enabled":     enabled,
	})
	return core.EvidenceRecord{
		Type:     "guardduty_detector",
		ID:       id,
		Payload:  payload,
		SourceID: "aws.guardduty",
	}
}

func recorderRec(t *testing.T, id, name string, recording bool) core.EvidenceRecord {
	t.Helper()
	payload := mustMarshal(t, map[string]any{
		"name":      name,
		"recording": recording,
	})
	return core.EvidenceRecord{
		Type:     "config_recorder",
		ID:       id,
		Payload:  payload,
		SourceID: "aws.config",
	}
}

// --- cloudtrail rule ------------------------------------------------

func TestCloudTrailMultiRegionEnabledRule_PassWhenAllMultiAndLogging(t *testing.T) {
	rule := cloudtrailMultiRegionEnabledRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"trails": {
				trailRec(t, "arn:t1", "t1", true, true),
				trailRec(t, "arn:t2", "t2", true, true),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass", res.Status)
	}
	if len(res.Violations) != 0 {
		t.Errorf("violations = %v; want none", res.Violations)
	}
}

func TestCloudTrailMultiRegionEnabledRule_FailWhenSingleRegion(t *testing.T) {
	rule := cloudtrailMultiRegionEnabledRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"trails": {trailRec(t, "arn:t1", "t1", false, true)},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail || len(res.Violations) != 1 {
		t.Fatalf("res = %+v; want 1 violation", res)
	}
	if !strings.Contains(res.Violations[0].Reason, "single-region") {
		t.Errorf("violation reason = %q; want single-region mention", res.Violations[0].Reason)
	}
}

func TestCloudTrailMultiRegionEnabledRule_FailWhenNotLogging(t *testing.T) {
	rule := cloudtrailMultiRegionEnabledRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"trails": {trailRec(t, "arn:t1", "t1", true, false)},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail || len(res.Violations) != 1 {
		t.Fatalf("res = %+v; want 1 violation", res)
	}
	if !strings.Contains(res.Violations[0].Reason, "not logging") {
		t.Errorf("violation reason = %q; want 'not logging'", res.Violations[0].Reason)
	}
}

func TestCloudTrailMultiRegionEnabledRule_FailWhenBothMissing(t *testing.T) {
	rule := cloudtrailMultiRegionEnabledRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"trails": {trailRec(t, "arn:t1", "t1", false, false)},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail || len(res.Violations) != 1 {
		t.Fatalf("res = %+v; want 1 violation", res)
	}
	if !strings.Contains(res.Violations[0].Reason, "single-region and not logging") {
		t.Errorf("violation reason = %q", res.Violations[0].Reason)
	}
}

func TestCloudTrailMultiRegionEnabledRule_NoTrailsPasses(t *testing.T) {
	rule := cloudtrailMultiRegionEnabledRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{"trails": {}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass when no trails", res.Status)
	}
}

func TestCloudTrailMultiRegionEnabledRule_FallsBackToIDWhenNameMissing(t *testing.T) {
	rule := cloudtrailMultiRegionEnabledRule()
	payload := mustMarshal(t, map[string]any{
		"is_multi_region_trail": false,
		"is_logging":            true,
	})
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"trails": {{ID: "arn:fallback", Payload: payload, Type: "cloudtrail_trail"}},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !strings.Contains(res.Violations[0].Reason, "arn:fallback") {
		t.Errorf("expected ID fallback in reason; got %q", res.Violations[0].Reason)
	}
}

// --- cloudwatch rule ------------------------------------------------

func TestCloudWatchLogsRetentionSetRule_PassWhenAllAtOrAboveThreshold(t *testing.T) {
	rule := cloudwatchLogsRetentionSetRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"log_groups": {
				logGroupRec(t, "g1", "/aws/g1", true, 90),
				logGroupRec(t, "g2", "/aws/g2", true, 365),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass", res.Status)
	}
}

func TestCloudWatchLogsRetentionSetRule_FailWhenUnset(t *testing.T) {
	rule := cloudwatchLogsRetentionSetRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"log_groups": {logGroupRec(t, "g1", "/aws/g1", false, 0)},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail || len(res.Violations) != 1 {
		t.Fatalf("res = %+v; want 1 violation", res)
	}
	if !strings.Contains(res.Violations[0].Reason, "no retention configured") {
		t.Errorf("violation reason = %q", res.Violations[0].Reason)
	}
}

func TestCloudWatchLogsRetentionSetRule_FailWhenBelowThreshold(t *testing.T) {
	rule := cloudwatchLogsRetentionSetRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"log_groups": {logGroupRec(t, "g1", "/aws/g1", true, 30)},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail || len(res.Violations) != 1 {
		t.Fatalf("res = %+v; want 1 violation", res)
	}
	if !strings.Contains(res.Violations[0].Reason, "below threshold") {
		t.Errorf("violation reason = %q", res.Violations[0].Reason)
	}
}

func TestCloudWatchLogsRetentionSetRule_FallsBackToIDWhenNameMissing(t *testing.T) {
	rule := cloudwatchLogsRetentionSetRule()
	payload := mustMarshal(t, map[string]any{"retention_set": false})
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"log_groups": {{ID: "id-only", Payload: payload}},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !strings.Contains(res.Violations[0].Reason, "id-only") {
		t.Errorf("expected ID fallback; got %q", res.Violations[0].Reason)
	}
}

// --- guardduty rule -------------------------------------------------

func TestGuardDutyEnabledRule_PassWhenAtLeastOneEnabled(t *testing.T) {
	rule := guardDutyEnabledRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"detectors": {
				detectorRec(t, "d1", false),
				detectorRec(t, "d2", true),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass", res.Status)
	}
	if len(res.Violations) != 0 {
		t.Errorf("violations = %v; want none on pass", res.Violations)
	}
}

func TestGuardDutyEnabledRule_FailWhenNoneEnabled(t *testing.T) {
	rule := guardDutyEnabledRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"detectors": {detectorRec(t, "d1", false)},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "account" {
		t.Errorf("violations = %+v; want one account-level violation", res.Violations)
	}
}

func TestGuardDutyEnabledRule_FailWhenNoDetectorsAtAll(t *testing.T) {
	rule := guardDutyEnabledRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{"detectors": {}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail when no detectors", res.Status)
	}
}

// --- config recorder rule -------------------------------------------

func TestConfigRecorderEnabledRule_PassWhenAtLeastOneRecording(t *testing.T) {
	rule := configRecorderEnabledRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"recorders": {
				recorderRec(t, "r1", "default", false),
				recorderRec(t, "r2", "second", true),
			},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusPass {
		t.Errorf("Status = %q; want pass", res.Status)
	}
}

func TestConfigRecorderEnabledRule_FailWhenNoneRecording(t *testing.T) {
	rule := configRecorderEnabledRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{
			"recorders": {recorderRec(t, "r1", "default", false)},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail", res.Status)
	}
	if len(res.Violations) != 1 || res.Violations[0].ResourceID != "account" {
		t.Errorf("violations = %+v; want one account-level violation", res.Violations)
	}
}

func TestConfigRecorderEnabledRule_FailWhenNoRecordersAtAll(t *testing.T) {
	rule := configRecorderEnabledRule()
	res, err := rule.Evaluate(context.Background(), core.RuleInput{
		Slots: map[string][]core.EvidenceRecord{"recorders": {}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if res.Status != core.StatusFail {
		t.Errorf("Status = %q; want fail when no recorders", res.Status)
	}
}

// --- policy/rule registration symmetry ------------------------------

func TestInfrastructurePolicies_HaveMatchingRuleRefs(t *testing.T) {
	rules := make(map[string]struct{}, len(infrastructureRules()))
	for _, r := range infrastructureRules() {
		rules[r.ID()] = struct{}{}
	}
	for _, p := range infrastructurePolicies() {
		if _, ok := rules[p.RuleRef]; !ok {
			t.Errorf("policy %q references rule %q which is not registered", p.ID, p.RuleRef)
		}
	}
}
