# Identity roster

How to designate the directory that lists your organization's people, and check that every account in your other systems belongs to one of them — and to no one who has left.

> Docs hub: [../README.md](../README.md)

## What the roster is, and why

Access-control criteria (SOC 2 CC6.2, ISO 27001 A.5.16 and A.5.18) ask two questions about every account in every system:

1. **Does it belong to a real person in the organization?**
2. **Has it been removed when that person left or was suspended?**

Checking accounts system by system can't answer either. A GitHub member with MFA on is still a problem if nobody knows who they are. The answer needs an outside reference: an authoritative list of people. SigComply calls that list the **roster**. You pick one directory as the roster, and the CLI checks the accounts in every *other* configured identity source against it.

The roster is personnel data, so the CLI reads only the fields it needs (id, email, name, employee id/type, status, service-account flag). As with all evidence, it stays in your vault and never reaches SigComply Cloud. The Cloud dashboard only gets the counts.

## Prerequisites

- A working `.sigcomply.yaml` with at least one account source configured — `github`, `gitlab`, `aws.iam`, `aws.identity_center`, `okta`, `azure.entra` or `gcp.directory` (see [Configure sources](configure-sources.md)).
- Read access to the directory you will designate as the roster.

## Choosing the roster source

Five sources can be the roster:

| Directory | Source ID | Roster credential |
|---|---|---|
| Okta | `okta` | API token that can read users (`okta.users.read`) |
| Microsoft Entra ID | `azure.entra` | Graph application permission `User.Read.All` — **no Entra ID P1/P2 needed** for the roster |
| Google Workspace / Cloud Identity | `gcp.directory` | Workspace admin context with Users → Read |
| Active Directory (on-prem) | `active_directory` | A non-admin bind user over LDAPS / StartTLS |
| AWS IAM Identity Center | `aws.identity_center` | `identitystore:ListUsers` + `sso:ListInstances` (a roster-only binding skips the permission-set traversal, so it needs none of the `sso:*` grant actions) |

Identity Center is the roster only when it is the directory of record. If an
upstream IdP SCIM-syncs into it, designate the upstream IdP instead and use
`aws.identity_center` as an *account* source — that is the case the rule below
is about.

**Pick the directory where accounts are created** — the one HR onboarding and offboarding actually touches first. In a hybrid setup where Active Directory syncs to Entra ID, which then provisions Okta, the origin is Active Directory. Designate that. A downstream copy can lag behind the origin, or miss someone the sync skipped.

Credentials and field mappings for each source are in the [configuration reference](../configuration.md): [Okta](../configuration.md#okta), [Entra ID](../configuration.md#azureentra--directory_user), [Google Workspace](../configuration.md#gcp), [Active Directory](../configuration.md#active-directory).

Only one roster source is supported per project, and it must be a plain source ID (no `[instance]` suffix).

## A directory cannot vouch for its own accounts

The roster must come from a system other than the one being checked. Once you designate a source as the roster, the CLI **never** checks that source's own accounts against the roster, because a directory that lists a person would trivially "prove" that person's account there.

What that means in practice:

- **If Okta is the roster**, GitHub, GitLab, AWS IAM, Entra and Google Workspace accounts are checked against it. Okta accounts are not.
- **Deprovisioning *inside* the roster directory is still manual evidence.** The CLI can't attest that a leaver was removed from Okta using Okta as the reference. Keep providing the manual evidence your framework's catalog asks for (for example a quarterly access review or offboarding records).

## Configure it

Start with the source and the one-line designation:

```yaml
sources:
  okta:
    org_url: https://acme.okta.com
  github:
    org: acme
  aws.iam:
    region: us-east-1

experimental:
  roster:
    source: okta
```

Accounts link to people by **email**, compared case-insensitively. Some accounts have no email, or a different one. Link them with `aliases`, and mark accounts that aren't people with `non_human`:

```yaml
experimental:
  roster:
    source: okta
    aliases:                          # account → the person's roster email
      github:
        jdoe: jane.doe@acme.com       # GitHub login
        octo-sam: sam@acme.com
      aws.iam:
        jane.doe: jane.doe@acme.com   # IAM UserName
    non_human:                        # bots, deploy users, break-glass accounts
      github: [acme-ci-bot]
      aws.iam: [terraform-deployer]
```

Rules for both maps:

- The top-level keys are **source keys exactly as written under `sources:`**, including any `[instance]` suffix on account sources (`"github[labs]"`).
- An account name matches the account's **id or username**, case-insensitively. It never matches a display name, because free-text names aren't unique.
- An alias must be a non-empty email. The same account listed twice with different emails is an error.

### GitHub and AWS accounts need aliases

Some sources can't supply an email, so their accounts link **only** through `aliases`:

- **GitHub** — the org-members API exposes no email. Alias each login.
- **AWS IAM** — IAM users carry no email. Alias each `UserName`. The AWS **root** account is recognized automatically and treated as non-human, so you don't need to list it. **If your humans sign in through IAM Identity Center rather than as IAM users, add `aws.identity_center` and delete the `aws.iam:` alias block** — SSO identities carry emails and link directly, which removes the whole class of silent alias typos described below.
- **GitLab** — member email is visible only to a group-owner or instance-admin token. With a lesser token, alias the usernames.

A misspelled login is silent in the config — it is a perfectly valid entry for an account that does not exist — so check the run output for `unused-alias:` lines after adding aliases (see [Troubleshooting](#troubleshooting)).

Okta, Entra ID, Google Workspace and AWS IAM Identity Center accounts carry emails and usually link without aliases.

### Overriding the roster for one policy

A per-policy binding overrides `source` for that one policy. Excluding the roster source from the accounts works as usual:

```yaml
policies:
  soc2.cc6.2.accounts_linked_to_roster:
    bindings:
      roster: [azure.entra]           # this policy uses Entra as its roster
```

Explicitly binding the roster source to the same policy's `accounts` slot is a configuration error.

## The policies

Each framework ships two roster policies. Both run daily and on push, and both skip until a roster is designated. Both check **accounts and cloud IAM grants** — see [Accounts and grants](#accounts-and-grants) below.

| Framework | Policy | Severity | Asserts |
|---|---|---|---|
| SOC 2 | `soc2.cc6.2.accounts_linked_to_roster` | high | Every active human identity — account or IAM grant — belongs to someone in the roster. |
| SOC 2 | `soc2.cc6.2.no_active_accounts_for_inactive_personnel` | critical | No active identity belongs to someone the roster marks inactive. |
| ISO 27001 | `iso27001.5.16.accounts_linked_to_roster` | high | Same as the SOC 2 linked check (A.5.16 identity management). |
| ISO 27001 | `iso27001.5.18.no_active_accounts_for_inactive_personnel` | critical | Same as the SOC 2 inactive check (A.5.18 access rights). |

**Linked to roster** looks at active accounts that aren't non-human (disabled accounts and declared bots are skipped). An account passes when its alias (or, failing that, its email) equals the email of **any** roster entry, whether that person is active, pending or inactive.

**No active accounts for inactive personnel** looks at active accounts whose alias or email equals the email of a roster entry with status `inactive` (suspended, disabled, deprovisioned or expired).

A person who is `pending` (provisioned but not yet able to sign in, such as a new joiner in Okta's STAGED state) counts as linked and isn't treated as inactive.

### Accounts and grants

The roster slot accepts two shapes of identity, and asks both the same question:

| Shape | Evidence type | Emitted by | Joins on |
|---|---|---|---|
| An account in another system | `directory_user`, `directory_user.v2` | GitHub, GitLab, AWS IAM, Okta, Entra, Workspace, AD | alias, else `email` |
| A cloud IAM role granted to a principal | `iam_binding` | `gcp.iam`, `aws.identity_center` | alias, else `principal_id` |

Both are checked by the *same two policies* — there is no separate grant policy. Adding a source that emits `iam_binding` widens what the existing checks see; it adds no new control, no new obligation, and nothing skips for a project that has no such source.

This matters because the two shapes hide different things. A cloud role can be granted to a principal that was never an account in any directory you collect — a personal Google account, a user from a partner's domain. It appears in no `directory_user` record, so an account-only check gives a clean run while an ex-contractor still holds `roles/storage.admin`. The binding itself is the evidence.

**Findings are per grant, not per person.** Someone holding three unlinked roles is three findings, because three grants have to be revoked.

**Which principals are checked.** Only those the roster could plausibly vouch for:

| Principal | `principal_type` | Checked? |
|---|---|---|
| `user:someone@…` | `user` | yes |
| `serviceAccount:…` | `service_account` | no — non-human by construction |
| `group:…` | `group` | no — see Limits |
| `domain:acme.com` | `domain` | no — names a domain, not a person |
| `allUsers`, `allAuthenticatedUsers` | `""` | **yes** — see below |

`allUsers` carries no prefix, so its `principal_type` is empty. An unclassifiable principal counts as a person on purpose: it can never match a roster entry, so it is reported. Dropping the most dangerous binding in GCP because its type was unrecognised is the failure mode worth avoiding.

### Reading violations

Violations name the identity as `source_id/id`, called the **account ref**:

```
identity github/octo-sam is not linked to anyone in the roster
identity aws.iam/AIDAEXAMPLE0000000000 belongs to sam@acme.com, who is inactive in the roster
identity gcp.iam/roles/editor|user:sam@personal.test is not linked to anyone in the roster
```

The ref is unique across sources, so GitHub `jdoe` and GitLab `jdoe` are reported separately. For `aws.iam` the id is the IAM `UserId`, not the user name. For `gcp.iam` the id is the grant — `<role>|<member>` — so the same person appears once per role they hold. The full violation list lives in your vault. The Cloud dashboard sees only the counts.

For each violation, either fix the account (remove it, or disable it where the person left) or fix the link (add an alias or a `non_human` entry). To accept a finding for a while, waive it with the account ref as `resource_id`:

```yaml
policies:
  soc2.cc6.2.accounts_linked_to_roster:
    exceptions:
      - scope: { resource_id: "github/octo-sam" }
        state: waived
        reason: "External contractor under MSA-2291; offboarding tracked in JIRA-812."
        approved_by: ciso@acme.com
        expires_at: 2026-12-31
```

### A Workspace roster still checks GCP grants

"A directory cannot vouch for its own accounts" is enforced per **source ID**, and `gcp.directory` (Google Workspace, which emits the roster) and `gcp.iam` (project IAM bindings) are different sources. So designating Workspace as your roster excludes only its own `directory_user` records — your GCP IAM grants are still checked against it. That is the intended asymmetry: Workspace saying "Jane is an employee" is exactly what should vouch for Jane holding `roles/editor`.

### Deleted vs. inactive people

The two policies catch leavers in different ways, depending on how the roster directory records a departure:

- **Suspended / disabled / deprovisioned** (the person is still listed, with status `inactive`): their remaining accounts elsewhere fail **no active accounts for inactive personnel**. Okta keeps DEPROVISIONED users listed, and the CLI reads them.
- **Deleted outright** (the person disappears from the directory: an Entra or Workspace deletion, an AD object deletion, an Okta hard delete): the roster no longer lists them, so their remaining accounts fail **linked to roster** instead.

So **waiving an unlinked account on the linked policy can hide a leaver** whose directory entry was deleted. Only waive accounts you have identified.

## Limits

- **No HR system.** The roster is a directory, not an HRIS (BambooHR, Workday, …). If your directory isn't kept in step with HR, the check is only as good as the directory.
- **Current state only.** Each run checks accounts as they are now. It doesn't measure how quickly an account was removed after a departure (for example "within 24 hours"). Keep that evidence manually.
- **One roster source, no instances.** A bracketed source (`"okta[emea]"`) can't be the roster, and two rosters can't be merged.
- **Email is the join key.** A roster entry with no email can't vouch for any account (fail-safe), and an identity with neither email nor alias is always unlinked. For an IAM grant the join uses `principal_id`, which for a `user:` member is already an email.
- **Group grants are reported, but not attributed to their members.** A role or permission set granted to a group produces an `iam_binding` whose `principal_type` is `group`, which the roster join treats as non-human and does not check — the people in that group are checked through their own user records instead. Expanding a group grant into one record per member would be worse, not better: `iso27001.5.3.no_broad_admin_bindings` exists to push admin grants *onto* groups, so attributing them back to individuals would report the recommended pattern as a violation. One exception is worth knowing: `aws.identity_center` **does** resolve Identity Center group membership for `directory_user.is_admin`, so a person who holds `AdministratorAccess` only through a group is still flagged as an admin by the admin-MFA policies. Review group membership itself separately.
- **GCP and AWS, not Azure yet.** `iam_binding` is emitted by `gcp.iam` (project IAM bindings) and by `aws.identity_center` (IAM Identity Center permission-set assignments — `principal_id` is the holder's email, so those grants join the roster with no aliases). Azure role assignments are the same cross-vendor shape and would be picked up by these policies the day a plugin emits them — no policy change needed. AWS *IAM-user* policy attachments are still not emitted; `aws.iam` reports privilege through `directory_user.is_admin` instead.
- **Each roster policy collects its own evidence.** Nothing is cached between policies, so the roster directory is read once per roster policy in a run — for a large Active Directory, that is one full paged search per policy.
- **Entra ID MFA policies still need P1/P2.** Reading the roster from `azure.entra` needs only `User.Read.All`. The MFA policies that bind the same source's `directory_user` records still need the Entra ID P1/P2 registration report.

## Troubleshooting

**The roster policies are skipped with "no roster source designated — set experimental.roster.source …".** No roster is designated, or the policy's `roster` binding is empty. Add `experimental.roster.source`.

**Exit `3` with an `experimental.roster` error.** The config is rejected before any collection. Common causes:

| Message contains | Fix |
|---|---|
| `experimental.roster.source is required` | Add `source:` to the block. |
| `bracketed multi-instance source IDs are not supported` | Use a plain source ID. |
| `is not configured in the sources: block` | Configure that source under `sources:`, or fix the typo. The same applies to keys under `aliases` / `non_human`. |
| `none of which a roster slot accepts` | The source can't be a roster (e.g. `github`). Use `okta`, `azure.entra`, `gcp.directory` or `active_directory`. |
| `alias must be a non-empty roster email` / `is listed more than once` | Fix the alias entry. |
| `cannot also feed the accounts checked against it` | A `bindings:` override puts the roster source on the `accounts` slot. Remove it. |

**Every GitHub or AWS account is unlinked.** Those sources carry no email. Add `aliases` (see above).

**A GCP IAM grant is unlinked but the person is in the roster.** The principal's address differs from their roster email (a personal or partner-domain account). Alias it under the `gcp.iam` source key: `aliases: { gcp.iam: { c@personal.test: carl@acme.com } }`.

**A warning `ignoring unrecognized key experimental.roster.<key>`.** A typo in the block. Unknown keys are tolerated so newer configs load on older CLIs, but they do nothing.

**A warning `unused-alias:` or `unused-non-human:` naming an account.** The account name is spelled in a way no collected account carries — the other half of the typo the exit `3` above catches on the *source* key. The run prints, after evaluation:

```
unused-alias: experimental.roster.aliases["github"]["jdoee"] matched no collected account — no record from github carries that id, username or principal_id
```

The entry did nothing: the account it was meant to link is still unlinked (or still counted as a person). Fix the spelling, or drop the entry if the account is gone. The name is matched against the account's **id**, its **username**, or — for an IAM grant — its **principal_id**, never a display name.

It is a warning, never a failure, and it is decided across the whole run: a name used by one roster policy is used. Two cases produce no warning at all even when an entry is wrong, because the run proved nothing about it — the roster policies were carried forward by their cadence, or they skipped (no roster designated, the source failed to collect). A run that collected no account at all reports every declared name.

These lines go to stdout, not the log, because the log redacts anything email-shaped and roster keys are often emails. They stay local: account names never reach the cloud payload.

**The roster policies report `error`.** The roster source failed to collect — a missing Okta token, an LDAPS certificate that doesn't verify, a Workspace 403 — and the result carries the source's own message. See the source's section in the [configuration reference](../configuration.md).

## See also

- [Configuration reference — `experimental.roster`](../configuration.md#experimentalroster--designating-the-identity-roster)
- [Configure sources](configure-sources.md)
- [Frameworks](../reference/frameworks.md)
- [Policy spec — multi-slot policies and `matches_in`](../architecture/03-policy-spec.md#multi-slot-policies)
- [Docs hub](../README.md)
