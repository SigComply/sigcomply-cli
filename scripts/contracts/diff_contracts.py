#!/usr/bin/env python3
"""Structural diff of two contract-slice JSON files (OpenAPI or Smithy).

Classifies each change for L3 drift triage:
  - BREAKING: something our mapper relies on was removed or changed — a removed
    operation/shape/property/enum value, or a changed scalar/type. These are
    what break a plugin reading the vendor's response.
  - additions (non-breaking): new keys/elements — we ignore unknown fields.

The "info" metadata block (title/version/x-source) is ignored. Output is a
report on stdout; exit status is 1 when any breaking change is found, else 0.
Both OpenAPI and Smithy slices are deterministic JSON we control, so a no-op
re-fetch diffs clean.

Usage: diff_contracts.py <old.json> <new.json> <label>
"""
import json
import sys

breaking = []
additions = []


def jkey(v):
    return json.dumps(v, sort_keys=True)


def walk(old, new, path):
    if type(old) is not type(new):
        breaking.append(f"changed (type) {path}: {type(old).__name__}->{type(new).__name__}")
        return
    if isinstance(old, dict):
        for k in old:
            p = f"{path}/{k}"
            if k not in new:
                breaking.append(f"removed {p}")
            else:
                walk(old[k], new[k], p)
        for k in new:
            if k not in old:
                additions.append(f"added {path}/{k}")
    elif isinstance(old, list):
        olds = {jkey(x) for x in old}
        news = {jkey(x) for x in new}
        for x in olds - news:
            breaking.append(f"removed (list elem) {path}: {x[:80]}")
        for _ in news - olds:
            additions.append(f"added (list elem) {path}")
    elif old != new:
        breaking.append(f"changed {path}: {json.dumps(old)[:60]} -> {json.dumps(new)[:60]}")


def main():
    old_path, new_path, label = sys.argv[1:4]
    old = json.load(open(old_path))
    new = json.load(open(new_path))
    # Ignore the metadata block — version/title churn is not a contract change.
    for doc in (old, new):
        doc.pop("info", None)
    walk(old, new, "")

    if not breaking and not additions:
        print(f"  {label}: no change")
        return 0
    print(f"  {label}: {len(breaking)} breaking, {len(additions)} additions")
    for b in breaking:
        print(f"    BREAKING {b}")
    return 1 if breaking else 0


if __name__ == "__main__":
    sys.exit(main())
