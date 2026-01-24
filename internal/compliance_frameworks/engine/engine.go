// Package engine provides the OPA policy evaluation engine.
package engine

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/sigcomply/sigcomply-cli/internal/core/evidence"
)

// EvaluationMode defines how a policy evaluates evidence.
type EvaluationMode string

const (
	// EvalModeIndividual evaluates each resource individually.
	EvalModeIndividual EvaluationMode = "individual"
	// EvalModeBatched evaluates all resources of matching type together.
	EvalModeBatched EvaluationMode = "batched"
)

// PolicyMetadata contains metadata extracted from a Rego policy.
type PolicyMetadata struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Framework      string         `json:"framework"`
	Control        string         `json:"control"`
	Severity       evidence.Severity `json:"severity"`
	EvaluationMode EvaluationMode `json:"evaluation_mode"`
	ResourceTypes  []string       `json:"resource_types"`
}

// LoadedPolicy represents a policy loaded into the engine.
type LoadedPolicy struct {
	PolicyMetadata
	Module string // Raw Rego source
}

// Engine evaluates OPA/Rego policies against evidence.
type Engine struct {
	policies []LoadedPolicy
}

// New creates a new policy evaluation engine.
func New() *Engine {
	return &Engine{
		policies: []LoadedPolicy{},
	}
}

// LoadPolicy loads a Rego policy into the engine.
func (e *Engine) LoadPolicy(name, regoSource string) error {
	// First, validate the Rego syntax by preparing a query
	ctx := context.Background()

	// Try to compile the policy to validate syntax
	_, err := rego.New(
		rego.Query("data.sigcomply"),
		rego.Module(name+".rego", regoSource),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("invalid Rego policy %s: %w", name, err)
	}

	// Extract metadata from the policy
	metadata, err := e.extractMetadata(ctx, name, regoSource)
	if err != nil {
		return fmt.Errorf("failed to extract metadata from policy %s: %w", name, err)
	}

	e.policies = append(e.policies, LoadedPolicy{
		PolicyMetadata: *metadata,
		Module:         regoSource,
	})

	return nil
}

// extractMetadata extracts metadata from a Rego policy.
func (e *Engine) extractMetadata(ctx context.Context, name, regoSource string) (*PolicyMetadata, error) {
	// Query for metadata
	query, err := rego.New(
		rego.Query("data"),
		rego.Module(name+".rego", regoSource),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}

	results, err := query.Eval(ctx)
	if err != nil {
		return nil, err
	}

	metadata, err := e.findMetadataInResults(results)
	if err != nil {
		return nil, err
	}

	return e.parseMetadata(metadata), nil
}

// findMetadataInResults navigates OPA results to find the metadata object.
func (e *Engine) findMetadataInResults(results rego.ResultSet) (map[string]interface{}, error) {
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return nil, fmt.Errorf("no data found in policy")
	}

	data, ok := results[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected data format")
	}

	sigcomply, ok := data["sigcomply"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("no sigcomply namespace found")
	}

	// Find metadata in any sub-package
	for _, v := range sigcomply {
		if pkg, ok := v.(map[string]interface{}); ok {
			if m, ok := pkg["metadata"].(map[string]interface{}); ok {
				return m, nil
			}
		}
	}

	return nil, fmt.Errorf("no metadata found in policy")
}

// parseMetadata converts a metadata map to PolicyMetadata struct.
func (e *Engine) parseMetadata(metadata map[string]interface{}) *PolicyMetadata {
	pm := &PolicyMetadata{}

	if id, ok := metadata["id"].(string); ok {
		pm.ID = id
	}
	if n, ok := metadata["name"].(string); ok {
		pm.Name = n
	}
	if f, ok := metadata["framework"].(string); ok {
		pm.Framework = f
	}
	if c, ok := metadata["control"].(string); ok {
		pm.Control = c
	}
	if s, ok := metadata["severity"].(string); ok {
		pm.Severity = evidence.Severity(s)
	}
	if em, ok := metadata["evaluation_mode"].(string); ok {
		pm.EvaluationMode = EvaluationMode(em)
	}
	if rt, ok := metadata["resource_types"].([]interface{}); ok {
		for _, r := range rt {
			if rs, ok := r.(string); ok {
				pm.ResourceTypes = append(pm.ResourceTypes, rs)
			}
		}
	}

	return pm
}

// GetPolicies returns all loaded policies.
func (e *Engine) GetPolicies() []LoadedPolicy {
	return e.policies
}

// Evaluate runs all loaded policies against the provided evidence.
func (e *Engine) Evaluate(ctx context.Context, evidenceList []evidence.Evidence) ([]evidence.PolicyResult, error) {
	results := make([]evidence.PolicyResult, 0, len(e.policies))

	for i := range e.policies {
		policy := &e.policies[i]
		result, err := e.evaluatePolicy(ctx, policy, evidenceList)
		if err != nil {
			// Return error result for this policy
			results = append(results, evidence.PolicyResult{
				PolicyID:  policy.ID,
				ControlID: policy.Control,
				Status:    evidence.StatusError,
				Severity:  policy.Severity,
				Message:   fmt.Sprintf("Policy evaluation error: %v", err),
			})
			continue
		}
		results = append(results, *result)
	}

	return results, nil
}

// evaluatePolicy evaluates a single policy against evidence.
func (e *Engine) evaluatePolicy(ctx context.Context, policy *LoadedPolicy, evidenceList []evidence.Evidence) (*evidence.PolicyResult, error) {
	// Filter evidence to matching resource types
	matchingEvidence := e.filterEvidence(evidenceList, policy.ResourceTypes)

	result := &evidence.PolicyResult{
		PolicyID:  policy.ID,
		ControlID: policy.Control,
		Severity:  policy.Severity,
	}

	// If no matching resources, skip the policy
	if len(matchingEvidence) == 0 {
		result.Status = evidence.StatusSkip
		result.Message = "No matching resources to evaluate"
		return result, nil
	}

	var violations []evidence.Violation

	if policy.EvaluationMode == EvalModeBatched {
		// Batched: evaluate all resources together
		v, err := e.evaluateBatched(ctx, policy, matchingEvidence)
		if err != nil {
			return nil, err
		}
		violations = v
		result.ResourcesEvaluated = len(matchingEvidence)
	} else {
		// Individual: evaluate each resource separately
		for i := range matchingEvidence {
			v, err := e.evaluateIndividual(ctx, policy, &matchingEvidence[i])
			if err != nil {
				return nil, err
			}
			violations = append(violations, v...)
		}
		result.ResourcesEvaluated = len(matchingEvidence)
	}

	result.Violations = violations
	result.ResourcesFailed = len(violations)

	if len(violations) > 0 {
		result.Status = evidence.StatusFail
		result.Message = fmt.Sprintf("%d violation(s) found", len(violations))
	} else {
		result.Status = evidence.StatusPass
		result.Message = "All resources compliant"
	}

	return result, nil
}

// filterEvidence filters evidence to only include matching resource types.
func (e *Engine) filterEvidence(evidenceList []evidence.Evidence, resourceTypes []string) []evidence.Evidence {
	typeSet := make(map[string]bool)
	for _, rt := range resourceTypes {
		typeSet[rt] = true
	}

	result := make([]evidence.Evidence, 0)
	for i := range evidenceList {
		if typeSet[evidenceList[i].ResourceType] {
			result = append(result, evidenceList[i])
		}
	}
	return result
}

// evaluateIndividual evaluates a policy against a single piece of evidence.
func (e *Engine) evaluateIndividual(ctx context.Context, policy *LoadedPolicy, ev *evidence.Evidence) ([]evidence.Violation, error) {
	// Build input for OPA
	input, err := e.buildIndividualInput(ev)
	if err != nil {
		return nil, err
	}

	// Prepare and evaluate
	query, err := rego.New(
		rego.Query("data.sigcomply[_].violations"),
		rego.Module(policy.ID+".rego", policy.Module),
		rego.Input(input),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare policy: %w", err)
	}

	results, err := query.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	return e.extractViolations(results)
}

// evaluateBatched evaluates a policy against all matching evidence together.
func (e *Engine) evaluateBatched(ctx context.Context, policy *LoadedPolicy, evidenceList []evidence.Evidence) ([]evidence.Violation, error) {
	// Build batched input for OPA
	input, err := e.buildBatchedInput(evidenceList)
	if err != nil {
		return nil, err
	}

	// Prepare and evaluate
	query, err := rego.New(
		rego.Query("data.sigcomply[_].violations"),
		rego.Module(policy.ID+".rego", policy.Module),
		rego.Input(input),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare policy: %w", err)
	}

	results, err := query.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	return e.extractViolations(results)
}

// buildIndividualInput builds OPA input for individual evaluation mode.
func (e *Engine) buildIndividualInput(ev *evidence.Evidence) (map[string]interface{}, error) {
	var data map[string]interface{}
	if err := json.Unmarshal(ev.Data, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal evidence data: %w", err)
	}

	return map[string]interface{}{
		"resource_type": ev.ResourceType,
		"resource_id":   ev.ResourceID,
		"data":          data,
	}, nil
}

// buildBatchedInput builds OPA input for batched evaluation mode.
func (e *Engine) buildBatchedInput(evidenceList []evidence.Evidence) (map[string]interface{}, error) {
	resources := make([]map[string]interface{}, 0, len(evidenceList))

	for i := range evidenceList {
		ev := &evidenceList[i]
		var data map[string]interface{}
		if err := json.Unmarshal(ev.Data, &data); err != nil {
			return nil, fmt.Errorf("failed to unmarshal evidence data: %w", err)
		}

		resources = append(resources, map[string]interface{}{
			"resource_type": ev.ResourceType,
			"resource_id":   ev.ResourceID,
			"data":          data,
		})
	}

	return map[string]interface{}{
		"resources": resources,
	}, nil
}

// extractViolations extracts violations from OPA evaluation results.
func (e *Engine) extractViolations(results rego.ResultSet) ([]evidence.Violation, error) {
	violations := []evidence.Violation{}

	for _, result := range results {
		for _, expr := range result.Expressions {
			// Handle set of violations
			if set, ok := expr.Value.([]interface{}); ok {
				for _, item := range set {
					v, err := e.parseViolation(item)
					if err != nil {
						continue // Skip malformed violations
					}
					violations = append(violations, *v)
				}
			}
		}
	}

	return violations, nil
}

// parseViolation parses a single violation from OPA output.
func (e *Engine) parseViolation(item interface{}) (*evidence.Violation, error) {
	m, ok := item.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("violation is not a map")
	}

	v := &evidence.Violation{}

	if rid, ok := m["resource_id"].(string); ok {
		v.ResourceID = rid
	}
	if rt, ok := m["resource_type"].(string); ok {
		v.ResourceType = rt
	}
	if reason, ok := m["reason"].(string); ok {
		v.Reason = reason
	}
	if details, ok := m["details"].(map[string]interface{}); ok {
		v.Details = details
	}

	return v, nil
}
