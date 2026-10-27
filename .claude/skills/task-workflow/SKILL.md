---
name: task-workflow
description: The lifecycle every change in this repo follows, from request to pushed and green - research, plan, plan review, design, tests, code, refactor, docs, verification, commits, self-review with context, adversarial review without context, follow-up fixes, push. Use at the start of any task that will change files in the repo (feature, fix, refactor, config, CI, docs), and to resume one part-way.
argument-hint: "<what to build or fix>"
---

# Task workflow

Agents do all of the engineering here: research, architecture, design, code, tests, docs, review
and shipping. The human sets intent, approves the plan and makes the decisions listed under
"When to ask the human". Carry every task to pushed and green. Don't hand back half-done work.

This skill is the same in every SigComply repo. The repo-specific parts live in two places, and
you read both before step 1:

- `AGENTS.md`: commands, invariants and the docs map.
- The repo workflow doc that `AGENTS.md` names: gate commands, test layers, how to verify in the
  real product, what a push to `main` triggers, and the doc routing table.

## 0. Size the task

| Size | Looks like | What runs |
|---|---|---|
| Trivial | Typo, comment, one-line config with no behaviour change | Steps 8-10 (step 9: the gate, plus the real-product check if the workflow doc's check covers the change, such as a typo on a page), 12 (one adversarial pass), 13-14 |
| Standard | Anything that changes behaviour, tests, CI, or more than one file | Every step |
| Large | Several days of work, or several independent parts | Split into work units first. Each unit runs every step and ends in its own commits. Push after each unit. |

If a "trivial" task turns out to change behaviour, it is standard. Restart at step 1.

## 1. Research (fan out)

Spawn read-only subagents in parallel, all in one message. Pick the streams that apply:

- **Code map**: the files, callers and tests in the area you will change.
- **Precedent**: how the codebase already does the same kind of thing. Use at least two search
  handles (names, strings, file patterns). A sibling that breaks a documented rule is a bug, not
  precedent.
- **Governing docs**: invariants in `AGENTS.md`, the workflow doc, architecture docs for the area.
- **External**: library, API and tool docs, changelogs, known issues. Prefer primary sources.
- **Cross-repo**: contracts with sibling SigComply repos (see `AGENTS.md`).

Use `Explore` for wide sweeps and `general-purpose` for deep reads. Every brief follows
"Subagent briefs" below. Treat each report as a lead: re-check any claim the plan will rest on
before you rely on it. Two agents agreeing is not verification.

## 2. Plan (plan mode, think hard)

Enter plan mode with the `EnterPlanMode` tool. If your harness has no plan mode, write the plan
into the conversation, review it (step 3), and wait for the human's approval. Only in a headless
or scheduled run, with no human to answer, continue without approval unless a "When to ask the
human" trigger applies. Use ultrathink for
this step. The plan contains:

1. The problem in one sentence, without naming the solution, and the acceptance criteria.
2. The approach, and at least one alternative you rejected (always consider "smaller") with why.
3. Files and modules to change, and the design: interfaces, data shapes, wire contracts, error
   handling. Extend existing patterns before inventing new ones.
4. Tests: which unit tests and which end-to-end tests, at which layer (see the workflow doc).
5. Docs: which agent-internal docs and which customer-facing docs change (use the workflow doc's
   routing table), or "none" with the reason.
6. Verification: the gate commands and the real-product check.
7. Risks: invariants touched, security surface, cross-repo impact, what a push triggers.
8. The commit split.
9. The definition of done, copied verbatim from the end of this skill.

## 3. Review the plan

Never present a first draft. Spawn a fresh `Plan` subagent with the plan text and the repo path,
and nothing else from this conversation. Tell it to read `AGENTS.md` and the workflow doc first
(`Plan` subagents don't load them on their own). Ask it to check:

- **Premises**: verify the 3-8 claims the plan rests on, at the source.
- **Reuse**: does an existing function, module or pattern already do part of this?
- **Design**: is it the simplest design that meets the criteria, and does it fit the existing
  structure?
- **Conformance**: does the plan follow `AGENTS.md` rules and invariants and the workflow doc?
- **Completeness**: every acceptance criterion maps to a step; tests, docs, migrations and
  cross-repo changes are all there; nothing is over-built.

Change the plan itself to absorb the points you accept. Then present it with `ExitPlanMode`. Plan
approval is the human checkpoint for the task.

## 4. Record lasting design decisions

A design decision that outlives the task (a new boundary, a contract, a pattern others should
follow) goes in the relevant internal architecture doc, with the reason, in the same commits as
the code.

## 5. Tests first

Write the failing tests that describe the behaviour:

- Unit tests for logic.
- End-to-end tests for anything a user or another system sees (the workflow doc names the layer).
  Automated end-to-end tests are the proof that a flow works; a manual check in a browser or a
  terminal is extra evidence, never a substitute. A user-visible change without one is not done.
- A change to a contract with a sibling repo regenerates the shared golden fixture and updates the
  receiving repo's test in the same task (workspace contracts table; the workflow doc names them).
- For a bug, the first test reproduces it.

Run them and watch them fail for the right reason: a failed assertion, not a compile or setup
error. For each test, you should be able to name the production change it would catch.

## 6. Implement

Write the least code that makes the tests pass, in the style of the surrounding code. Hand
independent parts to parallel `general-purpose` subagents when that is faster. Give each one its
own files, or use worktree isolation if they would touch the same files. You integrate their
work and you own the result. Delegate wide reads so the main context stays focused.

## 7. Refactor

With the tests green, clean up. Run the built-in `simplify` skill on the change, apply what
improves it, and re-run the tests.

## 8. Docs

Docs are part of the change, in the same commits. Use the `writing-docs` skill. Update:

- **Agent-internal docs**: `AGENTS.md`, the workflow doc, architecture and how-to docs that the
  change makes wrong or incomplete. If an agent would be misled after your change, that doc is
  part of the change.
- **Customer-facing docs**: whatever the routing table in the workflow doc says this change
  touches.

## 9. Verify

Run the full gate from the workflow doc and read the results. Exit codes and output count, not
expectations. Then check the real product the way the workflow doc says: run the CLI, drive the
app in a browser, or run the pipeline. A change the workflow doc's check covers is not verified
until you have driven it. Steps 11 and 12 repeat this check for every fix that touches what it
covers, and use it to reproduce findings about runtime behaviour.

Where the workflow doc's check can only run after push, only with the human's approval, or only
by the human, record it as deferred to that run, and why. Mark a claim unverified only when the
check can't run at all or the human declines the run; give the reason.

## 10. Quick self-review, then commit

Read the whole diff (`git diff HEAD`) top to bottom against the plan. Look for debug leftovers,
commented-out code, stray TODOs, secrets, unrelated edits, docs that weren't updated, and tests
whose names don't match what they assert. Fix them.

Commit rules:

- One logical change per commit; a commit can be reverted on its own. Tests travel with the code.
- Subject: `<type>: <imperative summary>`, at most 72 characters. Types: `feat`, `fix`,
  `refactor`, `perf`, `test`, `docs`, `ci`, `chore`. Check the workflow doc: some repos derive
  releases from the type.
- Body: the why that the diff doesn't show. No body when the subject says it all.
- End with the attribution trailer your harness gives you (for example
  `Co-Authored-By: Claude <model> <noreply@anthropic.com>`).
- Stage explicit paths. Never `git add -A` on a tree you haven't read.
- Never bypass hooks (`--no-verify`, `LEFTHOOK=0`). A failing hook means something is wrong: fix
  the cause, or stop and tell the human.
- If `AGENTS.local.md` defines a preflight check (identity, remotes), run it before the first
  commit and again before pushing.

Don't push yet.

## 11. Self-review with context

Run the `self-review` skill on `origin/main..HEAD`. It fixes what it confirms in follow-up
commits.

## 12. Adversarial review without context

Run the `adversarial-review` skill. It sends the commits to a reviewer that knows nothing about
the task, triages each finding, fixes the valid ones in follow-up commits, and re-checks those
fixes, including in the real product.

## 13. Push and watch

Push once per task or work unit: `git push origin main`. The workflow doc says what a push
triggers (CI, deploy, release, pipeline runs). Watch it to the end. If it goes red because of
your commits, fixing it comes before anything else; the fix runs through this same workflow,
scaled to its size. If the failure predates your commits or comes from outside the repo (a flaky
job, an outage, a missing secret), re-run it once, then report it and ask.

Then run any real-product check that step 9 deferred to after the push, or ask the human for its
approval or result, as the workflow doc says. Report the result, or say it is still pending.

## 14. Report

Tell the human:

- the commits, with one line each;
- the verification evidence (commands and results, what you drove in the product, and what you
  drove again after review fixes);
- the review tally (lenses run, findings confirmed, refuted and fixed, adversarial triage);
- the docs you updated;
- anything skipped and why, and any follow-ups you did not do.

## Debugging

Use the same lifecycle with a different front end:

1. Reproduce first, with a failing test or a real run. No reproduction means no understanding yet.
2. Find the root cause. Trace the actual code path and test one hypothesis at a time. After three
   failed fixes, stop and re-plan instead of trying a fourth.
3. Plan the fix (steps 2-3; a trivial fix skips them per step 0).
4. Continue from step 5, with the reproduction as the first failing test.

## When to ask the human

Ask when:

- product or UX behaviour isn't settled by the request, the docs or the code;
- an action is irreversible or outward-facing and the workflow doc doesn't already cover it
  (paid CI runs, production data, secrets, releases outside the normal flow, deleting work you
  didn't create);
- requirements conflict, or the work would grow beyond what was asked;
- the approach turns out to be much more complex than planned.

Don't ask about things with a conventional default, facts you can check yourself, or permission
for steps this workflow already prescribes.

## Subagent briefs

Subagents don't see this conversation, and `Explore` and `Plan` don't load `AGENTS.md`. Every
brief states:

- the role ("research", "lens review", "verifier") and the one-line goal;
- read-only, or exactly which files it may edit; never commit, push or reset;
- the absolute repo path and the files to read first;
- the questions to answer;
- the report format: `file:line` coordinates and commands with output, each claim marked
  `verified:` or `inferred:`, and a word limit.

Take coordinates from a report, then check and write the conclusions yourself.

## Definition of done

Copy this into every plan:

- [ ] Tests written first; the full gate from the workflow doc is green.
- [ ] Verified in the real product, again after review fixes, or marked deferred or unverified
      with the reason.
- [ ] Agent-internal and customer-facing docs updated, or "none needed" stated with the reason.
- [ ] `self-review` and `adversarial-review` done; valid findings fixed in follow-up commits.
- [ ] Pushed to `main`; CI, and any deploy or release it triggers, observed green.
