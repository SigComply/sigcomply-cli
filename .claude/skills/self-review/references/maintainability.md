# Maintainability lens

The question is whether the next agent can change this code safely. Don't raise anything a
linter or formatter already enforces.

## Reuse and precedent

- Does an existing function, module or pattern already do what the new code does? Search with at
  least two handles before claiming it doesn't. Only propose reusing code you have read.
- Does the new code follow the documented conventions and the way its neighbours do the same
  thing? If it deliberately differs, is the reason written down?

## Shape

- Each new abstraction earns its place: it has more than one user, or removes real
  duplication. One caller plus "might be useful later" is not enough.
- Functions do one thing at one level of detail. Deep nesting and long parameter lists are signs
  to split.
- No speculative options, flags or extension points nobody asked for.

## Names

- Each name says what the thing does. A `get` or `find` that mutates, or a predicate narrower than
  its name, is a finding. Public and persisted names matter most.
- The same concept uses the same word everywhere. Check with grep; the less common spelling is
  usually the finding.
- Test names describe what the test asserts.

## Comments

- Comments explain why, an invariant or a trap. Delete comments that restate the code.
- No change history in comments ("was X, now Y"); that belongs in the commit message.
