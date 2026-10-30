# Contributing to SigComply CLI

This page is for anyone changing the CLI's code or docs. AI agents start at
[`AGENTS.md`](./AGENTS.md); the gate, release rules and doc routing are in
[`docs/claude/development-workflow.md`](./docs/claude/development-workflow.md).

## Set up

1. Install [mise](https://mise.jdx.dev/), then run `mise install` in the repo root. It installs the
   Go, golangci-lint, Vale and gitleaks versions pinned in `mise.toml`, the same versions CI
   uses, and checks each download against `mise.lock`.
2. Install [lefthook](https://github.com/evilmartians/lefthook) and run `make hooks-install`. The
   hooks run formatting, vet, lint, tests and a secret scan (gitleaks) at commit and push.
3. Install `actionlint` if you edit `.github/workflows/`.
4. Build and run the CLI:

   ```sh
   make build
   ./bin/sigcomply version
   ```

## How changes land

- Maintainers commit straight to `main` after the gate, a manual run of the affected command and
  the review steps in the workflow doc pass. CI must be green after the push.
- Outside contributors open a pull request. The checklist in
  [`.github/pull_request_template.md`](./.github/pull_request_template.md) applies.

Every push to `main` that changes code cuts a public release, so `main` must stay green.

## Licensing your contribution

The CLI is licensed under the [Elastic License 2.0](./LICENSE). By opening a pull request or
otherwise submitting a contribution, you agree that:

- you wrote it, or have the right to submit it under these terms;
- it is licensed under the Elastic License 2.0;
- you grant SigComply a perpetual, worldwide, royalty-free, irrevocable license to use, modify,
  sublicense and distribute your contribution under any terms, including commercial ones.

You keep the copyright in your contribution. Earlier contributions were made under Apache-2.0;
see [`NOTICE`](./NOTICE).

## Commit messages

Use `<type>: <description>`, with a type such as `feat`, `fix`, `refactor`, `test`, `docs` or
`chore`. The type sets the release version: `feat` is a minor release and every other type is a
patch. A `<type>!:` subject, or the words "breaking change" anywhere in a subject, is a major
release, so write them only when you mean it.

## Before you commit

1. Write the test first, then the code. Keep commits small, with all tests passing.
2. Run `make test && make lint`.
3. Build the binary and run the command you changed (`sigcomply check`, `sigcomply evidence
   catalog -o json`, `sigcomply report`). Check its output, exit code, and vault files.
4. Update the docs the change makes wrong, in the same change. For customer-facing Markdown, run
   `vale --minAlertLevel=error <files>`.

Other checks, depending on the change:

| Command | Run it when |
|---|---|
| `make test-full` | You touch `sigcomply build`, `plugin/` or anything its heavy tests cover. CI always runs the full suite. |
| `make test-coverage` | You add a package or remove tests. CI fails below 80% total coverage. |
| `make test-contract` | You change a source plugin, a cassette or `contracts/`. |
| `make check-fixtures` | You add or change files under `testdata/` or `contracts/`. |
| `make test-live` | You need to check a source against the real API. Needs your own credentials; each test skips without them. Run it with only the test account's credentials set (see below). |

The test layers and their conventions are described in
[`docs/architecture/11-testing-strategy.md`](./docs/architecture/11-testing-strategy.md).

### Cloud credentials on your machine

`make test` uses fakes and recorded responses only. `make test-live`, the record drivers, and
`./bin/sigcomply check` with a cloud source or vault use any AWS, GCP, or Azure credentials they
find in your environment or home directory. To keep other accounts out of a run, use the `env -i`
wrapper in "Cloud credentials when running tests" in
[`docs/claude/development-workflow.md`](./docs/claude/development-workflow.md#cloud-credentials-when-running-tests),
and pass only the test account's variables.

## Adding a source plugin: required tests

A change that adds, or materially changes, a plugin under `internal/sources/` includes, in the
same change:

1. Unit tests for the mapper and `Collect`, against an in-memory fake API with a fixed clock.
2. A `*_conformance_test.go` that replays a scrubbed go-vcr cassette through
   `sourcetest.RunConformance`. Record cassettes with a `//go:build record` driver. GCP and Azure
   ARM packages keep theirs committed as `<service>_record_test.go`, so re-run that driver to
   re-record. Other sources have no committed driver: write one for the recording. Remove secrets and personal data before you commit; `make check-fixtures` checks this.
3. A `contracts/<provider>/<service>` spec snapshot, added to `scripts/contracts-fetch.sh`, so the
   weekly drift job covers the new API surface.

The step-by-step checklist is "Testing a source plugin (checklist)" in
[`docs/architecture/04-source-plugins.md`](./docs/architecture/04-source-plugins.md). Policies and
sources never reference each other: they meet only through evidence types (Invariant #4 in
`AGENTS.md`).

## Rules that apply to every change

- Never put a resource identifier (ARN, email, username, account ID) into the cloud submission
  payload. The [Sacred Invariants](./AGENTS.md#sacred-invariants) in `AGENTS.md` list the rules
  that need a maintainer's sign-off to change.
- Never commit secrets, real customer data, or personal email addresses. The repo is public.
- Report security issues privately, as described in [`SECURITY.md`](./SECURITY.md).
