# Changelog

All notable changes to the SigComply CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Per-release binaries and auto-generated notes are published on
[GitHub Releases](https://github.com/SigComply/sigcomply-cli/releases); this file
tracks the human-curated highlights.

## [Unreleased]

### Added

- `check` now prints a short banner naming the sources it will collect from (and
  their region/backend) before making any API call, so it's clear the run reaches
  real infrastructure. Credentials are never printed.
- `check` surfaces a concise, actionable reason line under each failing or errored
  policy in the terminal summary (e.g. `manual evidence not found; expected files
  in: <path>`), instead of only writing it to the vault `result.json`.
- `sigcomply init` now scaffolds a `manual.pdf` evidence source (local `./evidence`
  backend) so a framework's manual-evidence controls bind and report `fail`
  ("evidence not found") rather than erroring out.

### Changed

- CI examples and `init-ci` templates now default `SIGCOMPLY_VERSION` to a pinned
  release tag instead of `latest`, so a new release can't auto-propagate to every
  tester's next CI run. Set it to `latest` to opt back into always-newest.
- Error output no longer dumps the full command usage/flags block after a runtime
  error; the one-line message is shown on its own (`SilenceUsage`).

### Fixed

- A fresh `sigcomply init -f <framework> && sigcomply check` now exits `1`
  (findings to remediate), not `2`, and prints zero `[error]` lines.
- `init-ci` with a missing required `--ci` flag now exits `3` (configuration error)
  to match the exit-code taxonomy, instead of cobra's default `2`.
- `--cloud` with no `cloud.base_url` (or `--cloud-url`) configured now warns that
  submission was skipped, instead of silently doing nothing.
- Malformed-YAML config errors now include a plain-language hint (indentation,
  tabs, unknown keys) alongside the raw parser message.

## [0.64.38]

Baseline release for the beta-readiness changelog. For the complete history of
earlier tags, see the auto-generated notes on
[GitHub Releases](https://github.com/SigComply/sigcomply-cli/releases).

[Unreleased]: https://github.com/SigComply/sigcomply-cli/compare/v0.64.38...HEAD
[0.64.38]: https://github.com/SigComply/sigcomply-cli/releases/tag/v0.64.38
