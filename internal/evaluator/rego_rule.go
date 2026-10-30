package evaluator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// RegoRule wraps an OPA Rego module. The module is prepared once at
// New; each Evaluate call instantiates a fresh evaluator with the
// per-policy input. Rules are pure functions of the input: the module
// compiles against regoCapabilities, which has no network, environment,
// clock or randomness builtins.
type RegoRule struct {
	idValue   string
	query     rego.PreparedEvalQuery
	statusKey string
}

// NewRegoRule prepares the module for repeated evaluation. The query is
// a Rego reference, e.g. "data.sigcomply.rules.manual_presence.v1.result";
// the rule's result document must expose a "status" string and an
// optional "violations" array of {resource_id, reason, details}.
func NewRegoRule(id, module, query string) (*RegoRule, error) {
	r := rego.New(
		rego.Query(query),
		rego.Module(fmt.Sprintf("rule-%s.rego", id), module),
		rego.Capabilities(regoCapabilities()),
		rego.StrictBuiltinErrors(true),
	)
	prep, err := r.PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("evaluator: prepare rego rule %s: %w", id, err)
	}
	return &RegoRule{
		idValue:   id,
		query:     prep,
		statusKey: query,
	}, nil
}

// regoCapabilities is the builtin set a rule may call: OPA's builtins
// minus every one OPA marks non-deterministic. That removes the ones
// that reach the network (http.send, net.lookup_ip_addr, the JSON
// schema builtins that resolve remote $ref), read the CLI's environment
// (opa.runtime) or the clock and randomness (time.now_ns, rand.intn,
// uuid.rfc4122); rules get the run time as input.now instead. AllowNet
// is empty, so no host is reachable even if a network builtin came back.
// A rule.rego is repository code evaluated over evidence that may be
// sensitive, and the evidence must stay in the customer's storage.
// TestRegoBuiltinsGolden pins the resulting list.
func regoCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	kept := make([]*ast.Builtin, 0, len(caps.Builtins))
	for _, b := range caps.Builtins {
		if !b.Nondeterministic {
			kept = append(kept, b)
		}
	}
	caps.Builtins = kept
	caps.AllowNet = []string{}
	return caps
}

// ID returns the registered rule reference.
func (r *RegoRule) ID() string { return r.idValue }

// Evaluate marshals the rule input to JSON, hands it to OPA, and
// projects the returned document back into a RuleResult.
func (r *RegoRule) Evaluate(ctx context.Context, in core.RuleInput) (core.RuleResult, error) {
	input, err := toRegoInput(in)
	if err != nil {
		return core.RuleResult{}, fmt.Errorf("evaluator: rule %s: marshal input: %w", r.idValue, err)
	}
	rs, err := r.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return core.RuleResult{}, fmt.Errorf("evaluator: rule %s: eval: %w", r.idValue, err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return core.RuleResult{Status: core.StatusError, Diag: map[string]any{diagReason: "rego query produced no result"}}, nil
	}
	val := rs[0].Expressions[0].Value
	return projectRegoResult(val), nil
}

func toRegoInput(in core.RuleInput) (any, error) {
	// Convert slots to a slot → []payload-as-object structure so Rego
	// can index by field directly via input.slots.<name>[_].payload.X.
	slots := make(map[string]any, len(in.Slots))
	for name, recs := range in.Slots {
		out := make([]any, 0, len(recs))
		for i := range recs {
			rec := &recs[i]
			var payload any
			if len(rec.Payload) > 0 {
				if err := json.Unmarshal(rec.Payload, &payload); err != nil {
					return nil, fmt.Errorf("slot %q record %q: payload: %w", name, rec.ID, err)
				}
			}
			out = append(out, map[string]any{
				"id":           rec.ID,
				"identity_key": rec.IdentityKey,
				fieldSourceID:  rec.SourceID,
				"payload":      payload,
			})
		}
		slots[name] = out
	}
	return map[string]any{
		"policy_id": in.PolicyID,
		"slots":     slots,
		"params":    in.Params,
		"now":       in.Now.Format("2006-01-02T15:04:05Z07:00"),
	}, nil
}

func projectRegoResult(v any) core.RuleResult {
	doc, ok := v.(map[string]any)
	if !ok {
		return core.RuleResult{
			Status: core.StatusError,
			Diag:   map[string]any{diagReason: fmt.Sprintf("rego rule returned non-object: %T", v)},
		}
	}
	status, ok := doc["status"].(string)
	if !ok || status == "" {
		status = string(core.StatusError)
	}
	rawViolations, _ := doc["violations"].([]any) //nolint:errcheck // missing/wrong type → zero-length iteration, intended
	violations := make([]core.Violation, 0, len(rawViolations))
	for _, rv := range rawViolations {
		vm, ok := rv.(map[string]any)
		if !ok {
			continue
		}
		v := core.Violation{}
		if s, ok := vm["resource_id"].(string); ok {
			v.ResourceID = s
		}
		if s, ok := vm[diagReason].(string); ok {
			v.Reason = s
		}
		if d, ok := vm["details"].(map[string]any); ok {
			v.Details = d
		}
		violations = append(violations, v)
	}
	return core.RuleResult{
		Status:     core.PolicyStatus(status),
		Violations: violations,
	}
}
