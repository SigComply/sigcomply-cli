# Connect to the SigComply dashboard

Send your scheduled runs' pass/fail counts to the SigComply dashboard, generate reports and give
your auditor read access. Evidence and results stay in your vault; only counts and run details are
sent ([what is sent](../how-it-works.md#what-leaves-your-pipeline)).

## Prerequisites

- The project's repository on `github.com` or `gitlab.com` (GitHub Enterprise Server and
  self-managed GitLab can't connect), running SigComply in CI with OIDC:
  [GitHub Actions](ci-github.md) or [GitLab CI](ci-gitlab.md).
- An email address for the account owner.

## 1. Create an account

Sign up at <https://sigcomply.com/users/sign_up>. The first user of a new organization is its
owner.

## 2. Connect the repository

1. Go to **Projects** and select **New Project**.
2. Paste the repository URL in **Repository URL**: `https://github.com/<owner>/<repo>` or
   `https://gitlab.com/<group>/<subgroup>/<project>`.
3. Select **Create Project**.
4. Copy the **Project ID** (it starts with `prj_`) from the project's page. You add it to
   `.sigcomply.yaml` in step 3.

If you rename, move or recreate the repository, paste the new URL in the project's **Settings**
tab, or its runs are refused.

The dashboard has no API keys: it accepts a run when your CI's OIDC token and the committed
`cloud.project_id` name the same project. The project ID is not a secret.

## 3. Turn on submission

Add to `.sigcomply.yaml`, commit and push:

```yaml
cloud:
  base_url: https://sigcomply.com
  project_id: prj_7Xq2mKp9RtV4wNc8Bz3a   # the Project ID from step 2
```

The base URL is `https://sigcomply.com`. The OIDC audience, `https://api.sigcomply.com`, is a
fixed identifier, not a web address, so the two differ on purpose.

Without `cloud.project_id`, `check` exits `3` before collecting, even locally.

The scaffolded workflows meet the other conditions: the run is in CI and can mint an OIDC token.
Only runs that cover every policy submit, which in those workflows is the daily scheduled run.
Pull request, merge request and filtered runs print `cloud submission skipped: ...` and send
nothing. The dashboard refuses runs from pull request and merge request events. Full rules:
[Commands](../reference/commands.md#sigcomply-check).

To see exactly what a run would send, write it to a file instead of posting it:

```bash
sigcomply check --capture-cloud-payload payload.json
```

## 4. Run and check the result

Start a CI run (the scheduled workflow, with **Run workflow** on GitHub or **Run pipeline
schedule** on GitLab). In the log, look for:

```text
submission accepted (HTTP 201)
```

The run then appears in the project's **Overview** tab, with the compliance score, the split
between automated and manual evidence, and a table of runs. Open a run to see each policy's
result.

A failed submission never fails the run. The CLI logs a `submit:` warning with the HTTP status
and the response, and the exit code still reflects the policy results. See
[Fix submission errors](#fix-submission-errors).

## 5. Generate a report

This needs SigComply Cloud (paid, or during the trial).

1. Open the project and select **Reports**, then **Generate Report**.
2. Choose the **Report Type**: compliance summary, drift analysis or control matrix.
3. Choose the **Format**: PDF, CSV or JSON.
4. Choose the **Reporting Basis**: period of time (results across the date range) or point in
   time (the latest run as of the end date), and set **From** and **To**.

Every member of the organization can generate reports. Reports are built from the submitted
counts. They are not an audit opinion.

## 6. Invite an auditor

This needs SigComply Cloud and an owner: only owners see the **Auditors** tab.

1. Open the project and select **Auditors**, then **Grant Access**.
2. Enter the **Auditor Email** and, optionally, an **Expiration Date**.

The auditor receives an email to set a password, then sees that project's runs and results
read-only and can download its completed reports. Access is per project. Auditors can't sign up
on their own. To verify the evidence behind the counts, the auditor needs access to your vault:
see [Verify evidence](verify-evidence.md).

## Trial and plans

Your organization's first authenticated run submission starts a 2-month trial of SigComply
Cloud. No card is needed. Upgrade under **Settings > Subscription**.

SigComply Cloud adds full run history, reports over your audit window, the Audit-window view, the
auditor portal and an email when scheduled runs stop arriving. The CLI works without the dashboard.

Your runs are always recorded, on every plan. When the trial ends without a paid plan, the
dashboard shows each project's latest status and the last 30 days of runs. Older runs are kept
and come back when you upgrade. Generating reports, inviting auditors and the auditor portal
pause until you upgrade. Auditors keep their access, and reports you already generated stay
available to download.

## Fix submission errors

The `submit:` warning in the CI log includes the HTTP status and an error `code`. The fix for
each is in [Troubleshooting](troubleshooting.md#a-submit-warning-with-an-http-status). The most
common:

| Status | `code` | Fix |
|---|---|---|
| none | none | No `submit:` line and no `submission accepted`: the CLI skipped submission. Set `cloud.base_url`, and run with `--cloud` to see which condition is missing. |
| 401 | `token_expired` | Re-run the job. |
| 403 | `project_mismatch` | Copy the **Project ID** from the project's page into `cloud.project_id`, and check the project's repository URL matches the repository the job runs in. |

## Next steps

- [Verify evidence](verify-evidence.md).
- [Concepts](../concepts.md): what the counts can and can't tell you.
