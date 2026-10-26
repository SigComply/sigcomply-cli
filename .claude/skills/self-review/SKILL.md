---
name: self-review
description: Multi-lens review, with full task context, of the unpushed commits on main (origin/main..HEAD). Picks the lenses that apply (correctness, testing, docs, security, performance, contracts, maintainability, task-specific), fans out one lens-reviewer subagent per lens, tries to refute every candidate finding with a finding-verifier, then fixes what survives in follow-up commits. Use after committing a task and before adversarial-review and push.
argument-hint: "[commit range, default origin/main..HEAD]"
---

# Self-review with context

You know why every line changed. Use that to check the change does what the plan says, through
several lenses at once. Then try hard to disprove each finding before acting on it.

**Don't manufacture findings.** A clean review is the normal result for a good change. Keep a
finding only if you could defend it with a real trigger, a real caller or a failing case. Don't
ask for more defensiveness than the surrounding code has. Equally, don't explain away a real
problem because fixing it is inconvenient.

## 1. Set up

The range is the argument if one was passed (for example just the fix commits), otherwise
`origin/main..HEAD`.

```sh
git fetch origin
git log --reverse --oneline <range>
git diff --stat <range>
```

Re-read the plan and its acceptance criteria. Two checks need the task context, so you do them
yourself before fanning out:

- Is every acceptance criterion met, and which test or run shows it?
- Is anything in the diff outside the plan? Unplanned changes either get a reason or get removed.

## 2. Pick the lenses

| Lens | Run when | Checklist |
|---|---|---|
| Correctness | Always | `references/correctness.md` |
| Testing | Always | `review-testing` skill |
| Docs | Always: checks that docs changed where needed, and how they read | `writing-docs` skill, "Reviewing docs" |
| Security | The diff touches input handling, auth, crypto, secrets, files or paths, shell, network, dependencies, CI workflows, or data that must not leave | `review-security` skill |
| Performance | Loops over data, queries, I/O, hot paths, large inputs, bundle size, CI run time | `review-performance` skill |
| Contracts and invariants | Wire formats, schemas, public APIs, CLI flags, config keys, anything another repo reads, any invariant in `AGENTS.md` | `references/contracts.md` |
| Maintainability | New modules or abstractions, or a large diff | `references/maintainability.md` |
| Task-specific | 1-3 lenses you derive from the plan's risks | Write a 3-6 question checklist into the brief |

Write the chosen lenses down, and a reason for each one you skip. A reason names the missing
surface ("no input handling in this diff"), not the size of the change.

## 3. Fan out

Spawn one `lens-reviewer` subagent per lens, all in one message. Each brief contains:

- the lens and the absolute path of its checklist;
- the repo path and the commit range;
- "Review each commit with `git show <sha>` and attribute every finding to a commit";
- the plan's acceptance criteria and main design decisions (this review has context; share it);
- the output format from the agent definition.

When the security lens runs, also run the built-in `security-review` skill yourself (it reviews
the unpushed changes on the branch). For a diff over about 500 lines or across many modules, also
run the built-in `code-review` skill at `high` effort.

## 4. Merge

Collect every finding into one numbered candidate list. Remove exact duplicates. Keep findings
that are distinct even if they sit on the same line. Keep coordinates (`file:line`, commit), and
write the description in your own words from the code.

## 5. Try to refute each finding

For every candidate except nits, spawn a `finding-verifier` subagent, all in one message. Give it the coordinates, the claim and the repo path. Check nits yourself.

Then judge the verdicts:

- A REFUTED verdict whose evidence is about a different code path doesn't count. Re-check it.
- A refutation that rests on "nothing calls this" or "no such input exists" gets re-searched with
  a different handle before you accept it. A wrong refutation silently deletes a real bug.
- UNCERTAIN: settle it yourself if that's cheap (read the code, run a test). Otherwise list it as
  an open question; ask the human only if it's a product decision.

## 6. Act

- CONFIRMED: make the smallest fix, test first if it's a behaviour bug. If the fix would grow the
  diff far beyond what the bug warrants, stop and tell the human.
- Fixes land as follow-up commits with normal commit rules. Re-run the gate afterwards.
- REFUTED: drop it.

## 7. Record

Keep a short record in the conversation for the final report:

- lenses run, and lenses skipped with reasons;
- the tally, for example "11 candidates: 3 confirmed and fixed, 7 refuted, 1 open";
- the fix commits.
