#!/usr/bin/env bash
#
# check-fixtures.sh — WU-0.3 secret/PII fixture gate.
#
# Greps test fixtures (testdata/) and vendor contract snapshots (contracts/)
# for real secrets and identity that should have been scrubbed to the stable
# placeholders defined in docs/architecture/11-testing-strategy.md §4. A hit
# fails the build: a fixture that leaks identity violates the non-custodial
# architecture, not just a style rule.
#
# Usage:
#   scripts/check-fixtures.sh             # scan all testdata/ dirs + contracts/
#   scripts/check-fixtures.sh <dir>...    # scan the given dirs (used by tests)
#
# Patterns must stay portable across GNU grep (CI: ubuntu-latest) and BSD grep
# (local: macOS): POSIX ERE only — no \b, no \d, no -P.
set -euo pipefail

# Reset $RED etc. only when stdout is a terminal so CI logs stay clean.
if [ -t 1 ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; NC=$'\033[0m'
else
    RED=''; GREEN=''; NC=''
fi

# Resolve scan targets. Explicit args win (test harness passes a temp dir);
# otherwise auto-discover every testdata/ dir plus contracts/ from repo root.
SCAN_DIRS=()
if [ "$#" -gt 0 ]; then
    SCAN_DIRS=("$@")
else
    ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    cd "$ROOT"
    while IFS= read -r d; do
        SCAN_DIRS+=("$d")
    done < <(find . -type d -name testdata -not -path '*/.git/*' | sort)
    [ -d contracts ] && SCAN_DIRS+=("contracts")
fi

if [ "${#SCAN_DIRS[@]}" -eq 0 ]; then
    echo "check-fixtures: no testdata/ or contracts/ to scan — OK"
    exit 0
fi

errors=0

# scan <label> <find-ere> <allow-ere>
#   find-ere  : ERE matching the disallowed value
#   allow-ere : ERE matching the stable placeholder(s) to ignore ("" = none)
# Decision is made on the extracted tokens (grep -o) so an allowed placeholder
# is never confused with a real value sharing the same line.
scan() {
    local label="$1" find_re="$2" allow_re="$3" tokens
    # --exclude '*.md': READMEs document the contract path scheme
    # (e.g. s3@2006-03-01.json) and are not fixtures/snapshots.
    tokens="$(grep -rIhoE --exclude='*.md' "$find_re" "${SCAN_DIRS[@]}" 2>/dev/null || true)"
    if [ -n "$allow_re" ]; then
        tokens="$(printf '%s\n' "$tokens" | grep -vE "$allow_re" || true)"
    fi
    tokens="$(printf '%s\n' "$tokens" | grep -v '^[[:space:]]*$' || true)"
    if [ -n "$tokens" ]; then
        errors=$((errors + 1))
        printf '%s✗ %s%s\n' "$RED" "$label" "$NC" >&2
        # Show file:line for the offending values (allow-filtered for noise).
        grep -rInE --exclude='*.md' "$find_re" "${SCAN_DIRS[@]}" 2>/dev/null \
            | { if [ -n "$allow_re" ]; then grep -vE "$allow_re"; else cat; fi; } >&2 || true
        printf '\n' >&2
    else
        printf '%s✓ %s%s\n' "$GREEN" "$label" "$NC"
    fi
}

# AWS access keys. AWS's own convention is that example keys contain
# "EXAMPLE" (e.g. AKIAEXAMPLE0000000000); treat any such token as a placeholder.
scan "AWS access keys (AKIA…)" \
    'AKIA[0-9A-Z]{16}' \
    'EXAMPLE'

# Bare 12-digit AWS account IDs. Placeholder is all-zeros.
scan "AWS account IDs (12 digits)" \
    '[0-9]{12}' \
    '^0{12}$'

# ARNs carrying a real (non-zero) account ID.
scan "ARNs with a real account ID" \
    'arn:aws[a-z0-9-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]{12}:' \
    ':000000000000:'

# Email addresses other than the example.* reserved domains.
scan "email addresses" \
    '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' \
    '@example\.(com|org|net)([^A-Za-z0-9.-]|$)'

# Bearer tokens / Authorization values. Placeholder is REDACTED.
scan "bearer tokens" \
    '[Bb]earer[[:space:]]+[A-Za-z0-9._/+=-]{8,}' \
    '[Bb]earer[[:space:]]+REDACTED'

if [ "$errors" -gt 0 ]; then
    printf '%scheck-fixtures: %d category(ies) leaked secrets/PII — scrub to placeholders (see docs/architecture/11-testing-strategy.md §4)%s\n' \
        "$RED" "$errors" "$NC" >&2
    exit 1
fi

printf '%scheck-fixtures: fixtures clean%s\n' "$GREEN" "$NC"
