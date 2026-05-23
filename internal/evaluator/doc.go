// Package evaluator is L5 of the SigComply CLI: runs each policy's
// rule against the records collected for it and emits a PolicyResult.
// Hosts the rule registry, the Rego runner, the Go rule runner, and
// the YAML DSL transpiler. Rules are pure functions over RuleInput;
// they do no I/O.
//
// See docs/architecture/02-layers.md for the full layer contract.
package evaluator
