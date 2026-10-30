// Package vaultkey owns the grammar for anything that becomes part of a
// vault object key: the identifiers operators and project-local files
// supply (source keys, catalog entries, policy IDs), and the one Join
// every vault-key builder uses.
//
// Only the local vault backend rejects path escapes; the S3, GCS and
// Azure backends concatenate the key as given, so a `/` or `..` in any
// segment would write outside the run folder. Validating each segment
// where the key is built covers inputs no loader thought to check.
package vaultkey

import (
	"fmt"
	"regexp"
	"strings"
)

// IDPattern is the grammar for an operator-supplied identifier that ends
// up inside a vault object key: a source key (`aws.iam`, optionally with
// an instance suffix `aws.iam[backup]`), a catalog entry, a project-local
// policy ID. Letters, digits, dot, dash and underscore, starting with a
// letter or digit. ':' is excluded because bindings use it to separate a
// source from a catalog entry (`manual.pdf:entry_id`).
var IDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._-]{1,64}\])?$`)

// ValidID reports whether id matches IDPattern.
func ValidID(id string) bool { return IDPattern.MatchString(id) }

// segmentPattern is what one path segment of a vault key may hold. It is
// looser than IDPattern because built segments combine IDs (an envelope
// file is `<type>__<source>[<instance>]_<entry>.json`), but it has no
// separator, no whitespace, no control or percent character.
var segmentPattern = regexp.MustCompile(`^[A-Za-z0-9._\[\]-]{1,255}$`)

// Join validates every segment and joins them with "/". A segment that
// is empty, "." or "..", or holds anything outside segmentPattern is an
// error naming it, so a bad identifier fails the write that would have
// used it instead of landing somewhere else in the bucket.
func Join(segments ...string) (string, error) {
	if len(segments) == 0 {
		return "", fmt.Errorf("vault key: no segments")
	}
	for _, s := range segments {
		if s == "." || s == ".." || !segmentPattern.MatchString(s) {
			return "", fmt.Errorf("vault key: invalid path segment %q (letters, digits, '.', '_', '-', '[' and ']' only)", s)
		}
	}
	return strings.Join(segments, "/"), nil
}

// JoinUnder is Join for a key below an already-built root such as a run
// folder ("soc2/2026-Q1/run_..."): the root's own segments are validated
// again along with the new ones.
func JoinUnder(root string, segments ...string) (string, error) {
	return Join(append(strings.Split(root, "/"), segments...)...)
}
