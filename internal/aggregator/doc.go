// Package aggregator is L6 of the SigComply CLI and the privacy
// boundary: projects []PolicyResult into the structurally counts-only
// SubmissionPayload that the cloud submitter consumes. No resource
// identifier crosses this boundary. The wire type has no Violations
// slice, no map[string]any, no interface{} fields — widening it
// requires a code change reviewed at this seam.
//
// See docs/architecture/02-layers.md and 06-aggregation.md.
package aggregator
