// Package orchestrator is L9 of the SigComply CLI: wires L3 through
// L8 for the `sigcomply check` command — config load, registry init,
// plan, collect, evaluate, persist, aggregate, submit, render. The
// only layer that talks to the human, owns the exit codes, and
// performs CI environment detection.
//
// See docs/architecture/02-layers.md for the full layer contract.
package orchestrator
