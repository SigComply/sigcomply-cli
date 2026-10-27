# Correctness lens

Read every changed line, then the whole function and its callers. Look for:

## Line by line

- Copy-paste left half-edited: the wrong variable, field or key in one branch.
- Inverted conditions, off-by-one bounds, a wrong default for a boolean or an option.
- Arguments in the wrong order; keys that don't match between writer and reader.
- Leftover debug output, commented-out code, dead code the change orphaned.
- Comments that now contradict the code.

## Error paths and edge values

- Errors that are swallowed, logged and ignored, or turned into a success value.
- nil, null, empty, zero, negative, very large, duplicate and Unicode inputs.
- Partial failure halfway through: what state is left behind? Can the operation be retried safely?
- Timeouts and cancellation on every call that leaves the process.
- Races: two runs, two requests or two goroutines touching the same state; check-then-act.

## End to end

- Trace one real input from the entry point (command, request, event, job) through every layer
  to the result. Does each caller pass what the callee expects, in the shape and units it expects?
- Interrupted and repeated runs, and neighbouring flows that share state with this one.
- For a change the workflow doc's real-product check covers, does the real-product record in your
  brief show every acceptance criterion driven, or recorded as deferred or unverified with a
  reason? Anything else fails this lens. Judge from the record; don't start the product yourself.

## Claims

- Every claim in a comment, log message, error message, doc or commit message is true for the
  code as written.
- Absolutes ("always", "never", "only", "cannot") hold for every path, not just the one tested.
