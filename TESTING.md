# Testing

- Test layers (L0 to L4b, binary end-to-end, cross-repo goldens), the system tiers from per-push
  to the release gate, cassettes, contract snapshots, live tests and coverage:
  [`docs/architecture/11-testing-strategy.md`](docs/architecture/11-testing-strategy.md).
- Binary end-to-end tests (the built CLI run as a process): `cmd/sigcomply/e2e_test.go`.
- Goldens other repos copy, and how to regenerate them: the README in
  `internal/sign/testdata/spa-golden/` and `internal/planner/testdata/spa-golden/`, and
  `internal/aggregator/golden_contract_test.go`.
- Make targets, the per-commit gate and what CI runs:
  [`docs/claude/development-workflow.md`](docs/claude/development-workflow.md).
- Setting up and running the tests as a contributor: [`CONTRIBUTING.md`](CONTRIBUTING.md).
- The source-plugin test harness: [`internal/sources/sourcetest/README.md`](internal/sources/sourcetest/README.md).
