#!/usr/bin/env bash
#
# contracts-diff.sh — WU-3.2. Fetch each vendor spec fresh into a temp dir
# (non-destructive) and structurally diff it against the committed snapshot in
# contracts/, classifying breaking vs non-breaking changes. This is the L3
# drift detector: it never blocks a PR; WU-3.3 runs it on a schedule and opens a
# GitHub issue on a breaking diff. Exit 0 = no breaking change; exit 1 = at
# least one breaking change (a removed/changed operation, shape, field, or enum
# value in a slice our plugins read).
#
# Requires: curl, python3, ruby (same as contracts-fetch.sh).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
FRESH="$(mktemp -d)"
trap 'rm -rf "$FRESH"' EXIT

echo "Fetching fresh specs into a temp dir…"
if ! CONTRACTS_DIR="$FRESH" ./scripts/contracts-fetch.sh >/dev/null 2>"$FRESH/fetch.err"; then
    echo "contracts-diff: fetch failed:" >&2
    cat "$FRESH/fetch.err" >&2
    exit 2
fi

echo "Diffing committed snapshots vs. fresh:"
breaking=0
while IFS= read -r committed; do
    rel="${committed#contracts/}"
    fresh="$FRESH/$rel"
    if [ ! -f "$fresh" ]; then
        echo "  $rel: BREAKING — no fresh counterpart (service or API version changed upstream)"
        breaking=1
        continue
    fi
    if ! python3 scripts/contracts/diff_contracts.py "$committed" "$fresh" "$rel"; then
        breaking=1
    fi
done < <(find contracts -name '*.json' | sort)

# New services present upstream but not yet committed (informational only).
while IFS= read -r f; do
    rel="${f#"$FRESH"/}"
    [ -f "contracts/$rel" ] || echo "  $rel: new upstream slice (not yet committed)"
done < <(find "$FRESH" -name '*.json' | sort)

if [ "$breaking" -ne 0 ]; then
    echo "contracts-diff: BREAKING drift detected — triage per docs/architecture/11-testing-strategy.md"
    exit 1
fi
echo "contracts-diff: no breaking drift"
