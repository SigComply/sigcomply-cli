# Contracts and invariants lens

A contract is anything another program, repo, user or stored file depends on. Find each one the
diff touches, then check both sides.

## Find the contracts

- Wire formats and API payloads; request and response shapes; status codes.
- Database schema, migrations, stored file formats, signed or hashed data.
- CLI commands, flags, exit codes and output that scripts parse; config keys and env vars.
- CI templates, workflow inputs and published artifacts that sibling repos consume.
- The invariants listed in `AGENTS.md`. Read them; they are the project's hard rules.

## Check each one

- Both sides change together. If the other side lives in a sibling repo, the plan says how and
  when that repo is updated, and the order of pushes doesn't break either side in between.
- Field names, types, units, optionality and defaults match exactly on both sides.
- Removing or renaming something: every reader was found with at least two search handles.
- Shared test fixtures or golden files that pin the contract were updated, not bypassed.
- An invariant still holds on every path the diff adds, including error paths.
- Customer-visible contract changes (flags, config keys, output) appear in customer-facing docs
  and the changelog, if the repo keeps one.
