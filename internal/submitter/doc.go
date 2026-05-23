// Package submitter is L8 of the SigComply CLI: optional cloud
// submission. Acquires an OIDC token from the CI provider (GitHub
// Actions, GitLab CI) and POSTs the SubmissionPayload — and only the
// SubmissionPayload — to {cloud_base_url}/api/v1/runs. Submission
// failures are logged, never fatal.
//
// See docs/architecture/02-layers.md for the full layer contract.
package submitter
