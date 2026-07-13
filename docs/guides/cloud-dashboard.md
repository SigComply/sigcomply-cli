# Connect to SigComply Cloud

How to connect your project to the optional SigComply Cloud dashboard —
the paid tier that turns your CI runs into per-policy dashboards and
auditor reports. The CLI works fully without it; the vault on your own
storage is always the source of truth.

Back to the [docs hub](../README.md).

## What the dashboard is (and is not)

SigComply Cloud receives, per run, **aggregated counts only** — never raw
evidence, never identifiers. It renders per-policy pass/fail state,
compliance scores, and staleness, and gives auditors a portal to review
results and download reports.

What leaves your environment: a per-policy summary such as
`mfa_disabled_count: 3` plus pass/fail and score. What **never** leaves:
raw API responses, PDF bytes, violation lists with ARNs/emails/usernames,
signatures, and the per-run `manifest.json`. Those stay in your vault
forever. See [concepts.md](../concepts.md) for the non-custodial model.

The submission wire format is physically incapable of carrying an
identifier, and the Rails strong-params allow-list is a second backstop.

## Prerequisites

- A working local run — see [../quickstart.md](../quickstart.md).
- Your project running in CI (GitHub Actions or GitLab CI) with OIDC wired.
  See [ci-github.md](ci-github.md) or [ci-gitlab.md](ci-gitlab.md).

## The OIDC model (no API keys)

Cloud authentication uses **no API keys and no secrets you manage**. The
identity is the OIDC JWT your CI platform mints for the job, with audience
`https://api.sigcomply.com`. When you connect a project you paste its repo
URL, which registers the repo so tokens from its CI pipeline are matched to
your organization.

- **GitHub Actions**: add `permissions: { id-token: write, contents: read }`
  to the job. The runner mints the token; nothing else to configure.
- **GitLab CI**: add an `id_tokens:` block with `aud: https://api.sigcomply.com`.
  Read the [GitLab cloud-submission caveat](ci-gitlab.md) before you rely on
  it — the shipped template names the token in an env the CLI does not read.

Cloud submission **auto-enables** when the CLI runs in CI, an OIDC token is
present, and you have not passed `--no-cloud`.

## Step-by-step: connect a project

1. **Sign up** at the dashboard. The first user in a new organization
   becomes the **owner**.
2. **Create your organization** (done as part of sign-up).
3. **Connect a project.** Paste the project's GitHub or GitLab **repository
   URL**. This registers the repo so OIDC tokens from its CI match your org.
   - If you later **rename or move the repository, re-paste the new URL** —
     otherwise the OIDC identity no longer matches and submissions are
     rejected.
4. **Run in CI.** Your first successful submission from that repo's CI
   pipeline **automatically starts a 2-month, no-credit-card Pro trial**.
   All Pro features — the compliance dashboard and auditor portal — are
   available during the trial.
5. **View results.** The projects list and per-policy evaluations render
   the submitted counts, compliance scores, and staleness.
6. **Invite auditor seats** (owner only). The auditor receives a
   set-password email and logs into the auditor portal to review results
   and download reports. **Auditors cannot self-register** — they must be
   invited.

## After the trial

When the 2-month trial expires, submissions return **HTTP 402** with an
upgrade URL. Your CLI runs, vault writes, and signing continue to work
unchanged — only the cloud submission is gated. Upgrade to Pro from the URL
in the response (or from the dashboard) to resume submissions.

## Forcing or disabling submission

Submission is auto-detected in CI, but you can be explicit:

```bash
# Force submission (requires a valid OIDC token; errors if absent)
sigcomply check --cadence daily --cloud

# Never submit, even in CI
sigcomply check --cadence daily --no-cloud
```

To point at a non-default endpoint, use `--cloud-url <url>` or set
`cloud.base_url` in `.sigcomply.yaml`. To inspect exactly what would be
sent without posting it (an auditor escape hatch), use
`--capture-cloud-payload <file>`.

## Next steps

- [ci-github.md](ci-github.md) / [ci-gitlab.md](ci-gitlab.md) — wire OIDC in CI.
- [concepts.md](../concepts.md) — the non-custodial, counts-only model.
- [verify-evidence.md](verify-evidence.md) — verify the evidence behind the
  counts.
- [troubleshooting.md](troubleshooting.md) — "no cloud submission happening".
- Back to the [docs hub](../README.md).
