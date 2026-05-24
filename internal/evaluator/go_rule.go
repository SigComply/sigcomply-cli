package evaluator

import (
	"context"

	"github.com/sigcomply/sigcomply-cli/internal/core"
)

// GoRule is a thin core.Rule implementation backed by a closure. It
// exists so framework packages can register hand-written Go rules
// without each defining its own type.
type GoRule struct {
	IDValue string
	Fn      func(ctx context.Context, in core.RuleInput) (core.RuleResult, error)
}

// ID returns the rule's registered identifier.
func (r *GoRule) ID() string { return r.IDValue }

// Evaluate delegates to the closure.
func (r *GoRule) Evaluate(ctx context.Context, in core.RuleInput) (core.RuleResult, error) {
	return r.Fn(ctx, in)
}

var _ core.Rule = (*GoRule)(nil)
