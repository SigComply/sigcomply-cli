// Package registry is L2 of the SigComply CLI: in-process catalogs of
// the things that can be referenced by ID — frameworks, source
// plugins, rules, evidence types, and policies. Populated at process
// startup from the in-binary specs plus any project-local extensions
// under .sigcomply/, then immutable for the run.
//
// See docs/architecture/02-layers.md for the full layer contract.
package registry
