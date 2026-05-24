# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in SigComply CLI, please report
it privately via [GitHub Security Advisories](https://github.com/SigComply/sigcomply-cli/security/advisories/new)
rather than opening a public issue.

We take security reports seriously and will acknowledge receipt within
48 hours and provide an estimated timeline for a fix.

## Supported Versions

Pre-1.0: the latest tagged release receives security fixes. Older
pre-releases are not supported.

Post-1.0 (planned): the current major version and the previous major
version receive security fixes for two years from the previous major's
release. SOC 2 / ISO 27001 evidence retention requirements (typically
7 years) mean the on-disk vault format is supported for a longer window
than the binary itself.

## Scope

In scope:
- The CLI binary (`sigcomply`) and its in-tree source plugins
- The vault format and per-file Ed25519 signing
- The cloud submission payload contract (privacy boundary)
- The OPA/Rego rule runner and any framework-shipped rules

Out of scope (report upstream):
- Vulnerabilities in transitive Go dependencies (open a Dependabot PR
  or report to the upstream project)
- Vulnerabilities in OPA itself (report to open-policy-agent/opa)
- Vulnerabilities in cloud-provider SDKs (report to the SDK vendor)

## Threat Model

The CLI is designed under "Evidence without Access": raw evidence
never leaves the customer environment. Threats that violate this
boundary — e.g. a bug that causes resource identifiers to land in
the cloud SubmissionPayload — are treated as critical.

The signing model is about preserving integrity, not preventing fraud.
A customer running the CLI against fabricated infrastructure can
produce signed evidence of a fabricated reality; this is out of scope
for any compliance tool and explicitly called out in auditor-facing
material.
