---
name: writing-docs
description: How to write and review documentation in plain, readable technical language - customer-facing docs (README, guides, reference, in-app help text) and agent-internal docs (AGENTS.md, workflow and architecture docs). Covers picking the page type, rules against verbose AI-style prose, claim discipline for a compliance product, the Vale check, and a cold read by a fresh subagent. Use whenever you write or edit docs, and as the docs lens in self-review.
---

# Writing docs

Write for one reader doing one task. Say what they need, in plain words, and stop. AI-written
docs fail in a predictable way: long, padded, inflated and vague. Every rule below exists to
prevent that.

Find which docs a change touches in the routing table of the repo workflow doc (named in
`AGENTS.md`).

## Before you write

1. **Name the reader and the task.** "An engineer adding SigComply to a GitHub Actions pipeline"
   is a reader. "Users" is not.
2. **Pick one page type** (Diátaxis) and don't mix them:
   - *Tutorial*: a first success, step by step, for a newcomer.
   - *How-to*: numbered steps for one goal. Title starts with a verb. Prerequisites first.
   - *Reference*: facts to look up (flags, config keys, error codes). Short intro, then a table.
   - *Explanation*: what something is and why. Prose. No steps.
3. **Read two existing pages of the same type** in the repo and follow their shape.
4. **Outline first**: one line per heading. Then draft.

## Writing rules

1. Lead with the answer, the command or the result. Background comes after, and only if it
   changes what the reader does.
2. Address the reader as "you". Present tense, active voice. Name who acts: "The CLI signs the
   manifest", not "The manifest is signed".
3. One idea per sentence. Short sentences are fine.
4. Plain words: "use", not "utilize" or "leverage"; "is", not "serves as"; "has", not "boasts".
5. Be concrete: numbers, flag names, file paths, exact error text. Not "various", "several" or
   "significant".
6. Use the same word for the same thing every time. Repetition beats elegant variation.
7. Qualify at most once, and only when it's true. No "could potentially" or "may possibly".
8. No contrast against a claim nobody made ("not just X, but Y", "this isn't X, it's Y").
9. No dramatic closers or one-line paragraphs that repeat the point.
10. Don't list in threes by habit. List exactly the items that exist.
11. No "-ing" tails that add nothing: "..., ensuring", "..., highlighting", "..., enabling".
12. No openers or sign-offs: "Let's dive in", "In this guide we will", "Happy coding".
13. Don't describe the page ("This section covers...", "The table below shows...").
14. Don't write about time: "currently", "new", "now", "soon". Docs ship with a version.
15. Avoid em dashes. Use a period, comma, colon or parentheses.

### Banned words

Outside code and quotes, don't use: delve, crucial, pivotal, robust (figurative), seamless,
leverage, utilize, enhance, empower, streamline, unlock, game-changer, cutting-edge,
comprehensive, meticulous, landscape (figurative), tapestry, testament, underscore, showcase,
vibrant, garner, interplay, intricate, additionally, moreover, furthermore, "key" as an
adjective, "it's worth noting", "it's important to note". No marketing words: powerful,
effortless, best-in-class, world-class, revolutionary, bank-grade, military-grade.

`references/ai-tells.md` explains each AI-writing pattern with before-and-after examples. Read it
when a draft still sounds generated.

### Claims (compliance product)

- Every capability claim matches code that ships. Planned work is called planned, or left out.
- Never say SigComply "makes you compliant", "guarantees compliance" or "passes your audit". It
  collects evidence and evaluates policies; an auditor decides compliance.
- Name the limit where one exists.
- Don't add a fact, number or quote that isn't in the code, the spec or the user's input.

### Formatting

- Sentence-case headings, no emojis, no trailing punctuation.
- Numbered lists for steps. Bullets for parallel items. Prose for reasoning.
- Bold only for a UI label or one warning. Not as labels at the start of list items in customer
  docs; turn those into a table or prose.
- Commands, flags, paths, env vars and config keys in backticks. Every command is copy-pasteable,
  and you ran it as written before publishing.
- Put a warning right before the step it applies to, not at the end.

## Agent-internal docs

`AGENTS.md`, the workflow doc, skills and architecture docs are prompts for agents. Extra rules:

- Write rules as instructions ("Do X", "Never Y"), not background stories.
- Keep always-loaded files short. Put detail in a doc that loads when the task needs it, and link
  to it. Don't copy text between files; copies drift. Point to the one place that owns it.
- Cite other files by path and a searchable phrase, not by line number. Line numbers drift.
- No volatile state: CI status, counts, versions or "currently in progress" go stale. Describe
  the mechanism and how to check it live.
- When a doc and the code disagree, the code wins. Fix the doc in the same change.

## Before you finish

1. Delete every sentence the reader wouldn't miss.
2. Re-read for rules 8-13 and the banned words.
3. Run Vale on changed customer-facing Markdown files if the repo has a `.vale.ini`:
   `vale <files>`. CI fails on error-level alerts (`vale --minAlertLevel=error <files>`). Fix
   errors; fix warnings unless you can say why the text is right.
4. **Cold read.** For a new or substantially changed customer-facing page, spawn a fresh
   `general-purpose` subagent with only the page path and the reader's task. Ask it to say where
   it stalled, what the page assumed it knew, and which command or step it couldn't follow. Fix
   what it reports. A place where it stalls is as serious as a wrong command.

## Reviewing docs (docs lens in self-review)

Check, for each commit:

- Docs that the code change made wrong were updated: commands, flags, config keys, output,
  behaviour descriptions, architecture notes, `AGENTS.md`.
- Customer-facing docs cover new or changed user-visible behaviour, per the routing table.
- The writing rules, banned words and claim rules above hold for the changed text.
- Vale passes at error level on changed customer-facing Markdown.

Report per finding: `file:line`, the rule or the stale fact, and the fixed text.

Credits: the writing rules draw on [blader/humanizer](https://github.com/blader/humanizer) (MIT),
Wikipedia's "Signs of AI writing", Strunk's *The Elements of Style* (public domain), the Google
developer documentation style guide, and the Diátaxis framework.
