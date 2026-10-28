# Connect to SigComply Cloud

Send each CI run's pass/fail counts to the SigComply Cloud dashboard, generate reports from them,
and give your auditor read access. SigComply Cloud is a paid plan with a 2-month trial. The CLI
works fully without it: evidence and results always stay in your vault.

## What the CLI sends

Per run: the run's ID, framework, period, commit, branch, CLI version, repository and CI
provider, the count of policies in each status and the compliance score. Per policy: its ID and
mapped controls, status, severity, the number of resources evaluated and failed, a message built
from those counts, cadence data and whether the policy ran from automated or manual evidence.

The CLI never sends resource IDs, ARNs, emails, usernames, file contents, file hashes, violation
lists, envelopes or the run manifest. The payload type has no field that could hold them. To see
exactly what a run would send, write it to a file instead of posting it:

```bash
sigcomply check --capture-cloud-payload payload.json
```

## Prerequisites

- The project's repository on `github.com` or `gitlab.com` (GitHub Enterprise Server and
  self-managed GitLab can't connect), running SigComply in CI with OIDC:
  [GitHub Actions](ci-github.md) or [GitLab CI](ci-gitlab.md).
- An email address for the account owner.

## 1. Create an account

Sign up at <https://sigcomply.com/users/sign_up>. The first user of a new organization is its
owner. Every member of the organization sees a project's **Reports** tab and can generate
reports; only owners see the **Auditors** and **Settings** tabs.

## 2. Connect the repository

1. Go to **Projects** and select **New Project**.
2. Paste the repository URL in **Repository URL**: `https://github.com/<owner>/<repo>` or
   `https://gitlab.com/<group>/<subgroup>/<project>`.
3. Select **Create Project**.

SigComply Cloud has no API keys. It identifies a run by the OIDC token your CI mints: the
`repository` claim on GitHub Actions, the `project_path` claim on GitLab CI, matched without
regard to case. On the first accepted run it also records the repository's and owner's numeric
IDs, and later runs must match them. If you rename or move the repository, or recreate it, paste
the new URL in the project's **Settings** tab, or submissions are refused.

## 3. Turn on submission

Add to `.sigcomply.yaml`, commit and push:

```yaml
cloud:
  base_url: https://sigcomply.com
```

The CLI submits only when all of these hold:

- `cloud.base_url` is set (or `--cloud-url` is passed);
- the run is in CI (`CI`, `GITHUB_ACTIONS` or `GITLAB_CI` is set);
- an OIDC token is available: on GitHub Actions, the job has `permissions: id-token: write`; on
  GitLab CI, `SIGCOMPLY_ID_TOKEN` (or `ID_TOKEN`) holds an ID token with
  `aud: https://api.sigcomply.com`. The scaffolded workflows set both up.

`--no-cloud` turns submission off for one run. `--cloud` makes the CLI warn when the base URL or
the token is missing, instead of skipping without a message.

Only runs that cover every policy submit: `sigcomply check` with no filter, and
`sigcomply check --scheduled`. A run with `--cadence`, `--cadences`, `--on-push` or `--pr` checks
a subset, so it prints `cloud submission skipped: this run evaluates a subset of policies` and
sends nothing. The workflows `init-ci` writes submit from the daily scheduled run only.

## 4. Run and check the result

Start a CI run (for example the daily workflow). In the log, look for:

```text
submission accepted (HTTP 201)
```

The run then appears in the project's **Overview** tab, with the compliance score, the split
between automated and manual evidence, and a table of runs. Open a run to see each policy's
result.

Each submitted run is a full snapshot of the project, and the dashboard shows the latest one. In
a `--scheduled` run, a policy that is not due yet keeps its last result and is listed as
`carried_forward`. A manual policy whose folder for the current period is still empty is a
`fail` until the document is uploaded; the next daily run picks the upload up.

A failed submission never fails the run. The CLI logs a `submit:` warning with the HTTP status
and the response, and the exit code still reflects the policy results.

## 5. Trial and plan

Your organization's first authenticated run submission starts a 2-month Pro trial. No card is
needed. When the trial ends, the dashboard answers new submissions with HTTP `402`
(`subscription_required`) and an `upgrade_url`. Upgrade under **Settings > Subscription**.
Runs already submitted stay in the dashboard.

## 6. Generate a report

1. Open the project and select **Reports**, then **Generate Report**.
2. Choose the **Report Type**: compliance summary, drift analysis or control matrix.
3. Choose the **Format**: PDF, CSV or JSON.
4. Choose the **Reporting Basis**: period of time (results across the date range) or point in
   time (the latest run as of the end date), and set **From** and **To**.

Reports are built from the submitted counts. They are not an audit opinion.

## 7. Invite an auditor

1. Open the project and select **Auditors**, then **Grant Access**.
2. Enter the **Auditor Email** and, optionally, an **Expiration Date**.

The auditor receives an email to set a password, then sees that project's runs and results
read-only and can download its completed reports. Access is per project. Auditors can't sign up
on their own. To verify the evidence behind the counts, the auditor needs access to your vault:
see [Verify evidence](verify-evidence.md).

## Fix submission errors

The `submit:` warning in the CI log includes the HTTP status and an error `code`:

| Status | `code` | Cause | Fix |
|---|---|---|---|
| none | none | No `submit:` line and no `submission accepted`: the CLI skipped submission. | Set `cloud.base_url`. Run with `--cloud` to see which condition is missing. |
| 401 | `token_expired` | The token expired before the CLI posted it. | Re-run the job. |
| 401 | `invalid_signature` | The token's signature or signing key did not verify. | Re-run; if it persists, check the token comes from GitHub Actions or GitLab. |
| 401 | `validation_error` | The token is malformed, has the wrong issuer, or its audience is not `https://api.sigcomply.com`. | On GitLab, set `aud: https://api.sigcomply.com` on the ID token. |
| 403 | `unregistered_provider` | No active project in SigComply Cloud matches the token's repository. The message names the repository from the token. Matching ignores case. | Connect the repository (step 2), re-paste the URL after a rename, and check the project is active in **Settings**. |
| 403 | `repository_mismatch` | The token's repository or owner ID differs from the IDs the project recorded on its first accepted run, for example because the repository was deleted and recreated under the same name. | Update the repository URL in the project's **Settings** tab, which clears the recorded IDs, or contact support. |
| 402 | `subscription_required` | The trial ended and there is no Pro subscription. | Upgrade from the `upgrade_url`. |
| 413 | `payload_too_large` | The request body is over 4 MB. | Contact support. |
| 422 | `validation_failed` or a message | The payload was rejected, for example because its `run_id` was already used by another project in your organization, or its summary counts or score disagree with its policy list. Resending the same run to the same project is not an error: it answers `200` and keeps the first copy. | Re-run the job; each run gets a new run ID. Check the message. |
| 503 | `jwks_unavailable` | SigComply Cloud could not fetch your CI provider's signing keys to check the token. | Re-run the job later. |

More causes: [Troubleshooting](troubleshooting.md#cloud-submission).

## Next steps

- [Verify evidence](verify-evidence.md).
- [Concepts](../concepts.md): what the counts can and can't tell you.
