# Frameworks

Reference for the compliance frameworks the CLI ships and how their policies map to controls.

Back to the [documentation hub](../README.md).

## Shipped frameworks

| ID | Standard | Status | Coverage |
|---|---|---|---|
| `soc2` | SOC 2 — 2017 Trust Services Criteria | Production-ready, **default** | 100+ automated policies + 40 manual catalog entries |
| `iso27001` | ISO/IEC 27001:2022 | Shipped | All 93 Annex A controls |

Select a framework in `.sigcomply.yaml` with the singular key `framework:` (never `frameworks:`):

```yaml
framework: soc2
```

`init` and `evidence catalog` also accept `-f/--framework`; `check` reads the framework from config only.

### `init-ci` is SOC 2 only in v1-alpha

`init-ci` does not yet ship ISO 27001 cadence templates. Running it for any framework other than `soc2` exits `3` (`framework %q not supported in v1-alpha`). See [Commands](commands.md#sigcomply-init-ci).

## HIPAA is not available

HIPAA is **not** a registered framework — there is no package, no policies, and no `hipaa` entry in the framework registry. Selecting `hipaa` (or any other unregistered name) fails identically at runtime.

## How policies map to controls

Each framework is a set of policies, and every policy declares an `evidence_mode` — the flow it consumes:

| `evidence_mode` | Source of evidence | How it is evaluated |
|---|---|---|
| `automated` | API source plugins (AWS, GCP, Azure, GitHub, GitLab, Okta) collect JSON, validated against an evidence-type schema | The declarative `pass_when` DSL |
| `manual` | Files uploaded to a bucket folder, resolved from a manual-evidence catalog entry | A PDF-presence check (file present, in the temporal window, valid PDF) |

Each policy maps to one or more framework controls (SOC 2 TSC criteria, or ISO 27001 Annex A controls). Automated policies produce their result from live infrastructure state; manual policies attest that the required evidence file exists for the audit period. Both evidence flows are explained in [Concepts](../concepts.md#the-two-evidence-flows).

## Inspecting a framework

- **Manual catalog** — list the manual-evidence entries for a framework (id, control, type, frequency, temporal rule, grace period, name, description, severity, TSC):

  ```bash
  sigcomply evidence catalog -f soc2
  sigcomply evidence catalog -f soc2 -o json
  ```

- **Automated policy definitions** — the open Go-native policy source lives under `internal/frameworks/<framework>/` in the [`sigcomply-cli`](https://github.com/SigComply/sigcomply-cli) repository (e.g. `internal/frameworks/soc2/`). Each policy is a Go builder carrying its `pass_when` clause, so the exact logic behind every check is readable.

## See also

- [Commands](commands.md) — the `evidence catalog` and `check` reference.
- [Concepts](../concepts.md) — the two evidence flows and the aggregation boundary.
- [Configuration](../configuration.md) — per-policy and per-control customization.
- [Documentation hub](../README.md).
