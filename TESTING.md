# Testing

SigComply tests its evidence-source API integrations with a **layered
strategy** that keeps the per-PR path fast, free, and deterministic while
catching upstream API changes on a separate, mostly-free, scheduled path.

**Read the canonical reference first:**
[`docs/architecture/11-testing-strategy.md`](docs/architecture/11-testing-strategy.md).
It defines the regression-test-vs-drift-detector model, the six test
layers (L0–L4b), the repo split, and the cross-cutting conventions
(cassette/contract paths, redaction, build tags, coverage).

## The repo split in one line

| Layers | Where | What |
|--------|-------|------|
| **L0–L4a** | this repo (`sigcomply-cli/`) | invariants, mapping units, cassette+spec conformance, scheduled spec-diff drift, and free-account SaaS/Entra live tests |
| **L4b** | the E2E repos | provision minimal real cloud infra, run the **released binary**, assert per-policy outcomes, then destroy + sweep |

## E2E repositories (L4b)

These repos simulate real customer setups and run the full compliance
pipeline against real cloud infrastructure in CI:

- **GitHub Actions:** [`SigComply/sigcomply-cli-testing-project-github`](https://github.com/SigComply/sigcomply-cli-testing-project-github)
- **GitLab CI:** [`sigcomply/sigcomply-cli-testing-project-gitlab`](https://gitlab.com/sigcomply/sigcomply-cli-testing-project-gitlab)

## Running the CLI test suites

| Command | What it runs |
|---------|--------------|
| `make test-unit` | unit tests, `-short -race` (per-PR backbone: L0/L1/L2) |
| `make test-full` | full suite, `-race` |
| `make test-coverage` | full suite with the 80% coverage floor |
| `make lint` | `golangci-lint` |
| `make ci` | the per-PR gate (lint + tests + coverage) |

Live tests (L4a) are gated behind `//go:build live` and skip when the
required vendor token env vars are absent; they are excluded from the
per-PR suite and the coverage gate. See the canonical doc for details.
