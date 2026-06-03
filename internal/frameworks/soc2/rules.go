package soc2

import "github.com/sigcomply/sigcomply-cli/internal/core"

// soc2 currently authors every policy with the pass_when DSL — the
// CC7.2 security-event alerting checks that once needed substring
// matching over CloudWatch metric-filter patterns are now plain
// anyWhere clauses over the security_alert evidence type's normalized
// event_class field (the AWS classification lives in the source
// plugin). No Go rule: escape hatches remain.
//
// rules returns the Go rule implementations referenced by RuleRef. It is
// empty today; the rule: infrastructure (GoRule/Rego) remains available
// for checks the DSL genuinely cannot express.
func rules() []core.Rule { return nil }
