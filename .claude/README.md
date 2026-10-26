# Agent skills and subagents

These files define how AI coding agents work in this repo. `AGENTS.md` at the repo root is the
entry point and says when each one is used.

| Path | What it is |
|---|---|
| `skills/task-workflow/` | The lifecycle of every change: research, plan, review, tests, code, docs, verification, reviews, push |
| `skills/self-review/` | Multi-lens review of unpushed commits, with task context |
| `skills/adversarial-review/` | Review by a subagent with no task context, then triage of its findings |
| `skills/review-security/` | Security lens |
| `skills/review-testing/` | Testing lens |
| `skills/review-performance/` | Performance lens |
| `skills/writing-docs/` | Plain-language rules for customer-facing and internal docs; docs lens |
| `agents/lens-reviewer.md` | Read-only subagent that reviews through one lens |
| `agents/finding-verifier.md` | Read-only subagent that tries to refute one finding |
| `agents/adversarial-reviewer.md` | Read-only subagent that reviews commits with no task context |
| `settings.json` | Deny rules for force pushes and hook bypasses (`--no-verify`, `-n`), with the flag anywhere in the command. Best effort: other spellings (`git -c`, env vars) get past them; the rules in `AGENTS.md` and the git hooks are the real controls. |

Skills are plain Markdown. Claude Code loads them automatically; other agents can read
`skills/<name>/SKILL.md` directly.

## Shared across repos

Everything listed above is identical in all five SigComply repos (`sigcomply`, `sigcomply-cli`,
`sigcomply-evidence-spa`, `sigcomply-cli-testing-project-github`,
`sigcomply-cli-testing-project-gitlab`). Repo-specific rules belong in `AGENTS.md` and the repo
workflow doc, never in these files. When you change one of these files, make the same change in
the other four repos in the same task.

Personal settings go in `settings.local.json`, which the repo `.gitignore` excludes.

## Third-party material

- `skills/writing-docs/references/ai-tells.md` is vendored from
  [blader/humanizer](https://github.com/blader/humanizer) (MIT, see
  `skills/writing-docs/references/LICENSE-humanizer`).
- Other skills credit the sources they adapt at the end of each `SKILL.md`.
