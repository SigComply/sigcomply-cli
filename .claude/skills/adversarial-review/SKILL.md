---
name: adversarial-review
description: Sends the unpushed commits to a reviewer subagent that has no task context and hunts for real defects, then triages each finding (valid, by design, out of scope, false positive) with evidence and fixes only the valid ones in follow-up commits. Use after self-review and before pushing to main.
argument-hint: "[commit range, default origin/main..HEAD]"
---

# Adversarial review without context

A reviewer who doesn't know the plan reads the code the way the next maintainer will. It can't
share your blind spots, because it doesn't have your reasons. Your job afterwards is to judge its
findings honestly: fix the real ones and reject the rest with evidence.

## 1. Freeze

The gate is green and every change is committed. Record the head: `git rev-parse HEAD`. The range
is the argument if one was passed, otherwise `origin/main..<head sha>`.

## 2. Spawn the reviewer

Spawn the `adversarial-reviewer` subagent. Don't use a fork; a fork inherits this conversation.
Send exactly this brief, with the placeholders filled in, and nothing else:

```
Repository: <absolute repo path>
Commits to review: <range>
Review these commits for real defects, following your instructions.
```

Don't add the plan, hints, or why a choice was made. Any of that is task context and defeats the
review. The reviewer still loads `AGENTS.md`; that is intended, because it holds the project's
rules, not the task's reasons.

For a high-risk change (security, a wire or storage contract, data loss, release or deploy
machinery), spawn two reviewers in parallel in one message, the second with `model: sonnet` (or `opus` if
you are running on Sonnet), so the two passes don't share one model's blind spots.

## 3. Triage every finding

Check each finding against the code yourself. Read the lines, run a test, or spawn a
`finding-verifier` subagent for anything you can't settle quickly. Then give it one verdict:

| Verdict | Meaning | Action |
|---|---|---|
| Valid | A real defect in these commits | Fix it |
| Valid, out of scope | Real, but it predates these commits or belongs to a different task | Don't fix now; list it as a follow-up in the report |
| By design | The behaviour is intended | Cite the plan line, doc or invariant that decides it. If a fresh reader tripped on it, consider a better name or a one-line comment. |
| False positive | The claimed problem can't happen | Cite the guard, test or framework behaviour that prevents it |

Severity and confidence in the report are the reviewer's opinion. Your verdict rests on evidence.
Don't drop a finding because it is inconvenient, and don't accept one because it sounds plausible.

## 4. Fix

- Fix valid findings in follow-up commits, test first for behaviour bugs. Mention the adversarial
  review in the commit body.
- Re-run the gate.
- If the fixes added logic (not only wording), run `self-review` on just the fix commits, then one
  more adversarial pass on them. Stop after two rounds and report whatever remains.

## 5. Record

For the final report, keep a table: finding (one line), verdict, evidence, and the fix commit or
the reason for no fix.
