// Package planner is L3 of the SigComply CLI: reads the project
// config plus the selected framework plus the registries and produces
// a fully resolved RunPlan — slot bindings, effective parameters,
// resolved exceptions, derived period. The planner does no external
// I/O; planning errors exit with code 3.
//
// See docs/architecture/02-layers.md for the full layer contract.
package planner
