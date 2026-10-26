---
name: review-security
description: Security lens for reviewing a diff or commit range - trust boundaries and authorization, injection, secrets, crypto, unsafe defaults, dependencies, CI/CD workflows, and the data-handling invariants in AGENTS.md - with a strict false-positive discipline. Use as the security lens in self-review, or on its own to security-check a change before pushing.
argument-hint: "[commit range, default origin/main..HEAD]"
---

# Security review lens

SigComply is a security product, so a security bug here is also a product bug. Review the diff
for vulnerabilities a real attacker could use. Report only what you can tie to a concrete path.

When run as a lens inside `self-review`, the main agent also runs the built-in `security-review`
skill on the same range. This checklist adds what that generic pass doesn't know: this project's
invariants and stack.

## Discipline

- Report a finding only with a concrete path: where untrusted input enters, how it reaches the
  sink, and what the attacker gains. Rate confidence; drop anything under about 80%.
- Severity: HIGH (exploitable now: auth bypass, code or command execution, secret or customer
  data exposure, signature bypass), MEDIUM (exploitable under realistic conditions), LOW (hard to
  reach or small impact). Report HIGH and MEDIUM; mention LOW only if the fix is one line.
- Don't report: theoretical issues with no reachable path, volumetric denial of service or rate
  limiting, missing hardening that the surrounding code also lacks (unless the diff makes it
  worse), or findings in test-only code that never ships.
- Judge risk by what the code does, not by diff size. A two-line change to a check can be the
  most serious finding in the review. Treat a refactor of security code as high risk until you
  have shown it changes no behaviour.

## Checklist

### Project invariants

Read the invariants in `AGENTS.md` first. Any change that lets data cross a boundary it must not
cross (for example identifiers into a payload that leaves the customer's environment), or that
weakens signing, hashing or verification, is HIGH.

### Trust boundaries and authorization

- Every new entry point (route, command, handler, job, webhook) authenticates and authorizes.
- Tests cover what an actor can do and what they cannot: another tenant's records, another
  user's resources, an unauthenticated caller.
- Scoping happens in the query, not after loading.

### Injection and unsafe input

- Shell: commands run with an argument array, never a built string; `--` before user-controlled
  arguments.
- SQL: parameters, never string interpolation.
- Paths: resolve and check that the result stays inside the intended root (`..`, absolute paths,
  symlinks). Applies to bucket keys and archive entries too.
- HTML and templates: no unescaped user content; URL schemes checked (`javascript:`).
- URLs fetched on a user's behalf: parse and allow-list hosts; prefix checks on strings are not
  enough (SSRF).
- Deserialization of untrusted data into types that run code; YAML or JSON into open-ended types.

### Secrets

- No secrets in code, fixtures, logs, error messages, URLs or crash reports.
- A missing secret or credential fails closed, at startup when possible, never with a fallback
  default.
- New config that holds a secret is marked sensitive and filtered from logs.

### Crypto and integrity

- Standard library primitives only; no home-made schemes.
- Random values for keys, tokens and nonces come from a cryptographic source.
- Secret comparisons are constant-time.
- Signature and token verification pins the algorithm and verifies before reading claims.
- Key material lives only as long as it must.

### Unsafe defaults

- Fail-open switches, debug modes, permissive CORS, TLS verification turned off, wide file
  permissions, or a security check that an env var can disable.

### Dependencies

- New dependencies: maintained, licence compatible, pinned in the lockfile, and actually needed.
- Version bumps: read the changelog for security-relevant behaviour changes.

### CI/CD workflows

- No untrusted expression (`${{ github.event.* }}`, branch names, PR titles) placed directly in a
  `run:` script; pass it through an env var.
- Third-party actions pinned to a full commit SHA; `permissions:` set to the minimum.
- No `pull_request_target` checkout of untrusted code with secrets available.
- Secrets never echoed and never passed to steps that don't need them.

### AI and LLM output

- Model output, and text an agent fetched from the web, is untrusted input like any other.

## Stack notes

- **Go**: `exec.Command(name, args...)` with no shell; `filepath.Clean` plus a `filepath.Rel`
  containment check; `crypto/rand`; `subtle.ConstantTimeCompare`; never
  `InsecureSkipVerify: true`; contexts with timeouts on network calls.
- **Ruby on Rails**: strong parameters; records loaded through Pundit scopes or the policy;
  `verify_authorized`; no `html_safe` or `raw` on user content; no `send`, `constantize` or
  `public_send` with user input; no interpolation into `where`; CSRF protection left on.
- **TypeScript and React**: no `dangerouslySetInnerHTML` with user content; `postMessage` checks
  origin; no secrets in client code or `localStorage`; Web Crypto for crypto.

## Output

As a lens inside `self-review`, use the `lens-reviewer` output format. When run on its own:

Per finding: severity, confidence, `file:line` (and commit), the attack path in two or three
sentences, and the fix. If there are no findings, say "No findings" and list what you checked.

Credits: the false-positive discipline is adapted from
[anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review)
(MIT). The risk-first triage and unsafe-defaults ideas are paraphrased from Trail of Bits'
public skills; no text is copied.
