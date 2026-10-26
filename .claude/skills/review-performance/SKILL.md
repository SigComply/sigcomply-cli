---
name: review-performance
description: Performance lens for reviewing a diff or commit range - queries in loops, unbounded reads, missing pagination and indexes, I/O without timeouts, memory growth, wasted work in hot paths, frontend bundle and render cost, and CI run time - with measurement required for any claimed gain. Use as the performance lens in self-review, or on its own before pushing a change that handles data at scale.
argument-hint: "[commit range, default origin/main..HEAD]"
---

# Performance review lens

Find work that grows badly with real input sizes. Report a finding only when you can say what
input size triggers it and roughly what it costs. Don't ask for optimizations with no
measurement behind them.

## Checklist

### Data access

- Queries or API calls inside a loop (N+1). The query count must not grow with collection size.
- Reads with no limit: whole tables, all pages of an API, every object in a bucket. Paginate
  with a limit and a stable order.
- New query patterns: is there an index that serves them? Check with the database's plan output
  (`EXPLAIN ANALYZE`) when in doubt.
- Caches: the key includes everything that changes the result (tenant, user, version).

### I/O and concurrency

- Every network call has a timeout, and retries back off.
- No external I/O inside a database transaction.
- Large files and responses are streamed, not loaded whole into memory.
- Concurrency is bounded; goroutines, workers or promises can't grow without limit, and they
  stop on cancellation.

### CPU and memory

- Algorithmic cost at realistic sizes: nested loops over two large collections, repeated sorting
  or parsing inside a loop.
- Allocation in hot paths; buffers and slices that grow without bound.

### Frontend

- Bundle size: new heavy dependencies, imports that pull a whole library for one function.
- Renders: work in render paths, unstable keys, state updates that re-render large trees.
- Work that belongs in a worker or behind lazy loading.

### CI and pipelines

- New jobs or steps: run time and cost; caching; work that runs on every push but only matters
  on some.

## Measure, don't guess

- A performance claim in a commit message or doc needs a number: a benchmark, a timing, a query
  plan, a bundle size, before and after.
- An optimization that makes the code harder to read needs that number to justify it. Without
  one, prefer the simple version.

## Stack notes

- **Go**: `go test -bench . -benchmem` before and after (compare with `benchstat`); `pprof` for
  CPU and memory; watch for goroutine leaks and missing `context` cancellation.
- **Ruby on Rails**: `includes`/`preload` for associations, `strict_loading` to catch N+1 in
  tests, `find_each` for large sets, counter caches, slow work moved to background jobs.
- **React and Vite**: `vite build` output sizes; memoize only where a measured render cost
  justifies it; split code for routes that most users never open.

## Output

As a lens inside `self-review`, use the `lens-reviewer` output format. When run on its own:

Per finding: severity, `file:line` (and commit), the trigger size and estimated cost, and the
fix. If there are no findings, say "No findings" and list what you checked.

Credits: the measure-first approach is adapted from the `performance-optimization` skill in
[addyosmani/agent-skills](https://github.com/addyosmani/agent-skills) (MIT).
