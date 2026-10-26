---
name: review-testing
description: Testing lens for reviewing a diff or commit range - were tests written first, would they fail if the change were reverted, do they assert real behaviour rather than mocks, are edge cases and end-to-end flows covered, are they deterministic, and is every "it works" claim backed by a fresh run. Use as the testing lens in self-review, or on its own to check test quality before pushing.
argument-hint: "[commit range, default origin/main..HEAD]"
---

# Testing review lens

A test is only worth its cost if it fails when the behaviour breaks. Review the tests in the diff,
and the gaps in them, against the changed production code.

## Would it catch a regression?

- For each changed branch of production code, name the assertion that fails if that branch is
  reverted. A branch with no such assertion is a finding.
- Tautologies: a test that mocks the unit under test, or asserts the value it just set up.
- Assertions that pass on both the old and the new behaviour.
- Tests that pin wiring (which method was called) when they could check the outcome.
- Mocks only at real boundaries (network, clock, external services). Mocking the code's own
  collaborators hides integration bugs.

## Coverage of behaviour

- Edge values: empty, nil, zero, one, many, maximum, duplicates, Unicode, malformed input.
- Error paths: each error the code handles has a test that triggers it.
- End-to-end: a user-visible flow (command, page, API call, pipeline) has a test at the layer
  the workflow doc names, not only unit tests.
- Bug fixes: a regression test that fails without the fix.
- Security-relevant behaviour is tested both ways: what is allowed and what is refused.

## Reliability

- No real time, randomness, ordering or network without control: freeze clocks, seed random,
  stub network, sort before comparing.
- No sleeps used as synchronisation.
- Tests don't depend on each other or on leftover state.
- Fixtures are minimal and realistic; shared fixtures aren't changed in ways that silently
  weaken other tests.

## Hygiene

- Test names say what the test asserts.
- No test-only branches or hooks in production code.
- Coverage gates are met by testing behaviour, never by excluding files or adding trivial tests.
- No skipped or disabled tests without a written reason and a follow-up.

## Evidence for claims

Every claim that something passes or works rests on a run made after the last change, whose
output was read: the command, the exit code and the counts. "It should pass" is not evidence. If
the reviewer can't find such a run, run the tests (read-only commands are allowed) and report the
result.

## Output

As a lens inside `self-review`, use the `lens-reviewer` output format. When run on its own:

Per finding: severity, `file:line` (and commit), the missing or weak assertion, and a concrete
test to add or change. If there are no findings, say "No findings" and list what you checked.

Credits: adapted from the `test-driven-development` and `verification-before-completion` skills
in [obra/superpowers](https://github.com/obra/superpowers) (MIT).
