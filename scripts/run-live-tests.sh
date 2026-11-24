#!/usr/bin/env bash
# Runs `go test -tags live` for the live E2E workflow (.github/workflows/live-e2e.yml).
#
#   scripts/run-live-tests.sh <test regex> <package>...
#
# go test runs without -v, so the log holds only the summary and the
# failure messages of failing tests. Those messages are written to be safe
# for a public log (cmd/sigcomply/live_e2e_harness_test.go,
# sourcetest.PublicError). On a failure, the names of the failing tests,
# and nothing else, go to $GITHUB_OUTPUT as `failing` (space-separated), for
# the drift issue.
set -uo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <test regex> <package>..." >&2
    exit 2
fi
pattern="$1"
shift

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

go test -tags live -count=1 -timeout 80m -run "$pattern" "$@" 2>&1 | tee "$out"
code="${PIPESTATUS[0]}"

if [ "$code" -ne 0 ] && [ -n "${GITHUB_OUTPUT:-}" ]; then
    names="$(grep -oE -- '--- FAIL: [A-Za-z0-9_/.-]+' "$out" | sed 's/^--- FAIL: //' | sort -u | head -n 50 | tr '\n' ' ')"
    # Empty when the run failed outside a test (build error, panic): the
    # drift issue then says so itself.
    echo "failing=${names}" >>"$GITHUB_OUTPUT"
fi
exit "$code"
