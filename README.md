# sigcomply

> Zero-trust, non-custodial compliance engine — **"Evidence without Access."**

The `sigcomply` CLI runs locally in your CI/CD and turns infrastructure state
into signed compliance evidence — without giving any third party access to
your data, credentials, or production environment. Raw evidence stays in
your own storage; only aggregated counts and pass/fail scores are submitted
to the optional Compliance Dashboard.

Currently ships SOC 2 (Type II) policies; ISO 27001 is in early development.
Policies are open OPA/Rego — inspect, fork, and contribute.

## Install

```sh
go install github.com/SigComply/sigcomply-cli@latest
```

Pre-built binaries are published with each release on GitHub.

## Quick start

```sh
sigcomply check --framework soc2
```

Auto-detects collectors based on available credentials (`AWS_*`,
`GITHUB_TOKEN`, GCP ADC, …), evaluates the framework's policies locally,
writes signed `EvidenceEnvelope` files to your storage backend, and (in
CI with OIDC) submits aggregated results to the SigComply Cloud API.

## Project model

**One project = one source-control repository = one compliance framework.**
A project is the GitHub or GitLab repo you run `sigcomply` in. Its
`.sigcomply.yaml` selects exactly one framework (`framework: soc2`).
Customers pursuing multiple frameworks (e.g. SOC 2 + ISO 27001) use
multiple repos — one per framework — each with its own config, CI
workflow, and evidence vault.

## Manual evidence

For evidence that isn't an API call (declarations, training certificates,
HR exports), the CLI scans a folder in your storage:

```
{bucket}/{prefix}/{evidence_catalog_id}/{period_id}/
```

Upload any number of files — PDF, JPEG, PNG, GIF, TIFF, WebP, or BMP to the
folder above. Images are auto-converted to PDF; all files are merged into one
before evaluation. `sigcomply check` resolves each manual policy's folder from
the framework's catalog and the active period, then scans it.

Set the framework via `SIGCOMPLY_FRAMEWORK` or `framework:` in your config file
(default: `soc2`).

The optional [Evidence SPA](https://github.com/SigComply/sigcomply-evidence-spa)
is a standalone helper that generates PDFs for declaration- and checklist-style
entries — the CLI never talks to it. For all other manual evidence (HR exports,
training certificates, scanned documents) you produce the file yourself and
upload it to the folder above.

## CI/CD

Reusable workflow / CI component:

```yaml
# GitHub Actions
jobs:
  compliance:
    permissions: { id-token: write, contents: read }
    uses: SigComply/sigcomply-cli/.github/workflows/compliance.yml@v1
    with: { framework: soc2 }
```

```yaml
# GitLab CI
include:
  - component: gitlab.com/sigcomply/sigcomply-cli/compliance@v1
    inputs: { framework: soc2 }
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — system design, evidence flows, signing
- [docs/configuration.md](docs/configuration.md) — config file, env vars, flags
- [CLAUDE.md](CLAUDE.md) — context for AI coding assistants

## License

Apache-2.0 — see [LICENSE](LICENSE).
