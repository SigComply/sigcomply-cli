# Testing

- Test layers (L0 to L4b, binary end-to-end, cross-repo goldens), the system tiers from per-push
  to the release gate, cassettes, contract snapshots, live tests and coverage:
  [`docs/architecture/11-testing-strategy.md`](docs/architecture/11-testing-strategy.md).
- Binary end-to-end tests (the built CLI run as a process): `cmd/sigcomply/e2e_test.go`.
- Goldens other repos copy byte for byte, and how to regenerate each (the folder's README, or the
  test):

  | Golden | Copied to |
  |---|---|
  | `internal/sign/testdata/spa-golden/` (envelope vectors) | Evidence SPA `src/lib/verification/__fixtures__/golden/` |
  | `internal/planner/testdata/spa-golden/periods.json` | Evidence SPA `src/lib/__fixtures__/golden/periods.json` |
  | `internal/manualcatalog/testdata/<framework>_golden.json` | Evidence SPA `src/lib/__fixtures__/golden/` |
  | `internal/aggregator/testdata/cloud_golden.json` | the dashboard repo (path in `railsFixtureRelPath`, `internal/aggregator/golden_contract_test.go`) |

  After regenerating the SPA goldens, run `npm run check:goldens -- --copy` in the SPA checkout
  to copy all three; `npm run check:goldens` alone reports drift.
- Policy outcomes: every policy's verdict on a committed evidence fixture is pinned in
  `internal/frameworks/testdata/policy-outcomes/`; regenerate with
  `go test ./internal/frameworks/ -run TestPolicyOutcomesGolden -update` and review the diff.
- Cloud credentials: a developer machine may hold ambient AWS, GCP or Azure credentials. Unit,
  contract and binary E2E tests are hermetic; `make test-live` and a manual `sigcomply check`
  with a cloud source use what they find. Run them inside the `env -i` wrapper in
  [`docs/claude/development-workflow.md`](docs/claude/development-workflow.md) "Cloud credentials
  when running tests".
- Make targets, the per-commit gate and what CI runs:
  [`docs/claude/development-workflow.md`](docs/claude/development-workflow.md).
- Setting up and running the tests as a contributor: [`CONTRIBUTING.md`](CONTRIBUTING.md).
- The source-plugin test harness: [`internal/sources/sourcetest/README.md`](internal/sources/sourcetest/README.md).
