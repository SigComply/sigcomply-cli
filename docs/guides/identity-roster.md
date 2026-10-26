# Check accounts against your identity roster

Designate one directory as the list of your organization's people (the roster). The CLI then
checks that every active account and cloud IAM grant in your other sources belongs to someone on
the roster, and to no one the roster marks inactive. These checks cover SOC 2 CC6.2 and ISO 27001
A.5.16 and A.5.18.

## Prerequisites

- At least one account source configured: `github`, `gitlab`, `aws.iam`, `aws.identity_center`,
  `okta`, `azure.entra`, `gcp.directory` or `gcp.iam` ([Add an evidence source](configure-sources.md)).
- Read access to the directory you use as the roster.

## 1. Choose the roster source

| Directory | Source ID | Credential for the roster |
|---|---|---|
| Okta | `okta` | An API token that can read users |
| Microsoft Entra ID | `azure.entra` | Graph application permission `User.Read.All` (no Entra ID P1/P2 license needed) |
| Google Workspace | `gcp.directory` | A Workspace admin context that can read users |
| Active Directory | `active_directory` | A non-admin bind user over LDAPS or StartTLS |
| AWS IAM Identity Center | `aws.identity_center` | `identitystore:ListUsers` and `sso:ListInstances` |

Pick the directory where accounts are created, the one HR onboarding and offboarding touch first.
If Active Directory syncs to Entra ID, which provisions Okta, designate Active Directory. If an
upstream IdP syncs into IAM Identity Center, designate the IdP and keep `aws.identity_center` as
an account source.

Setup for each source: [sources reference](../reference/sources.md).

## 2. Designate it

List the roster source under `sources:` and name it in `experimental.roster.source`:

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

The roster source must be a plain source ID, without an `[instance]` suffix. The CLI never checks
the roster source's own accounts against itself; a directory cannot vouch for its own accounts.
Removal of leavers from the roster directory itself stays a manual evidence item, such as your
quarterly access review.

## 3. Link accounts that have no matching email

The CLI links an account to a person by email, ignoring case. Some sources carry no email:

- GitHub org members: alias each login.
- AWS IAM users: alias each `UserName`. The root account is treated as non-human automatically.
  If your people sign in through IAM Identity Center, add `aws.identity_center` instead; its
  users carry emails.
- GitLab: member emails are visible only to a group-owner or instance-admin token. With a lesser
  token, alias the usernames.

Okta, Entra ID, Google Workspace and IAM Identity Center accounts carry emails and usually link
without aliases. Add aliases, and mark accounts that are not people as `non_human`:

```yaml
experimental:
  roster:
    source: okta
    aliases:
      github:
        jdoe: jane.doe@acme.com
        octo-sam: sam@acme.com
      aws.iam:
        jane.doe: jane.doe@acme.com
    non_human:
      github: [acme-ci-bot]
      aws.iam: [terraform-deployer]
```

- Top-level keys are source keys exactly as written under `sources:`, including any `[instance]`
  suffix.
- An account name matches the account's ID or username (or, for an IAM grant, its principal),
  ignoring case. It never matches a display name.
- Each alias is a non-empty email. Listing the same account twice with different emails is an
  error.

## 4. Run the check

```bash
sigcomply check --cadence daily
```

Each framework ships two roster policies. Both run daily and on push, and both skip until a
roster is designated:

| Policy | Severity | Fails when |
|---|---|---|
| `soc2.cc6.2.accounts_linked_to_roster` | high | An active human account or grant links to no one on the roster. |
| `soc2.cc6.2.no_active_accounts_for_inactive_personnel` | critical | An active account or grant belongs to someone the roster marks inactive. |
| `iso27001.5.16.accounts_linked_to_roster` | high | Same as the SOC 2 linked check. |
| `iso27001.5.18.no_active_accounts_for_inactive_personnel` | critical | Same as the SOC 2 inactive check. |

A person who is pending (provisioned but not yet able to sign in) counts as linked and is not
inactive. Disabled accounts and `non_human` accounts are not checked.

## Verify

1. Look for `unused-alias:` or `unused-non-human:` lines in the run output. Each one names an
   entry that matched no collected account, usually a typo:

   ```text
   unused-alias: experimental.roster.aliases["github"]["jdoee"] matched no collected account — no record from github carries that id, username or principal_id
   ```

   Fix the spelling, or remove the entry if the account is gone.

2. Read the violations. Each names the identity as `source_id/id`:

   ```text
   identity github/octo-sam is not linked to anyone in the roster
   identity aws.iam/AIDAEXAMPLE0000000000 belongs to sam@acme.com, who is inactive in the roster
   identity gcp.iam/roles/editor|user:sam@personal.test is not linked to anyone in the roster
   ```

   For `aws.iam` the ID is the IAM `UserId`. For `gcp.iam` the ID is the grant (`<role>|<member>`),
   so a person appears once per role they hold.

3. For each violation, fix the account (remove it, or disable it if the person left) or fix the
   link (add an alias or a `non_human` entry). To accept one for a while, waive it by its
   `source_id/id`:

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

   A person deleted from the roster directory (rather than suspended) fails the linked check, not
   the inactive check. So a waiver on the linked policy can hide a leaver: waive only accounts you
   have identified.

## Fix configuration errors

A roster error stops the run before collection with exit code `3`:

| Message contains | Fix |
|---|---|
| `experimental.roster.source is required` | Add `source:` to the block. |
| `bracketed multi-instance source IDs are not supported` | Use a plain source ID as the roster. |
| `is not configured in the sources: block` | Configure that source under `sources:`, or fix the typo. Applies to keys under `aliases` and `non_human` too. |
| `none of which a roster slot accepts` | The source can't be a roster (for example `github`). Use `okta`, `azure.entra`, `gcp.directory`, `active_directory` or `aws.identity_center`. |
| `alias must be a non-empty roster email`, `is listed more than once` | Fix the alias entry. |
| `cannot also feed the accounts checked against it` | A `bindings:` override puts the roster source on the `accounts` slot. Remove it. |

Other symptoms:

- Roster policies skip with `no roster source designated`: add `experimental.roster.source`.
- Every GitHub or AWS IAM account is unlinked: add `aliases`.
- A GCP IAM grant is unlinked although the person is on the roster: the grant uses another
  address. Alias it under `gcp.iam`, for example `c@personal.test: carl@acme.com`.
- Roster policies report `error`: the roster source failed to collect. The result carries the
  source's own message.
- A surprising finding for someone who joined or left during the run: the CLI reads accounts and
  the roster minutes apart. Re-run before acting.

## Limits

- The roster is a directory, not an HR system. The check is as good as the directory.
- Each run checks current state. It does not measure how quickly an account was removed.
- One roster source per project.
- Grants to a group are not checked against the roster; the group's members are checked through
  their own accounts.
- Cloud IAM grants come from `gcp.iam` and `aws.identity_center` only.

## Next steps

- [Configuration reference](../configuration.md) for every `experimental.roster` key.
- [Add an evidence source](configure-sources.md).
