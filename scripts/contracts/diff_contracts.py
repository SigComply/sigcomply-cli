#!/usr/bin/env python3
"""Structural diff of two contract-slice JSON files (OpenAPI or Smithy).

Classifies each change for L3 drift triage:
  - BREAKING: something our mapper relies on was removed or changed — a removed
    operation/shape/property/enum value, or a changed scalar/type. These are
    what break a plugin reading the vendor's response.
  - additions (non-breaking): new keys/elements — we ignore unknown fields.

The "info" metadata block (title/version/x-source) is ignored. So is noise that
says nothing about the shapes our plugins read (see IGNORED_KEYS and
normalize_refs): Smithy endpoint-resolution rules, which the AWS SDK handles
and AWS regenerates often; documentation strings; and the depth of relative
$ref paths, which changes when a vendor moves its spec folders. Output is a
report on stdout; exit status is 1 when any breaking change is found, else 0.
Both OpenAPI and Smithy slices are deterministic JSON we control, so a no-op
re-fetch diffs clean.

Usage: diff_contracts.py <old.json> <new.json> <label>
"""
import json
import sys

breaking = []
additions = []

# Keys skipped wherever they appear. Endpoint rules (endpointBdd and its older
# endpointRuleSet form) route requests to a host; the SDK we pin evaluates
# them, and a change never alters a response shape. Namespaced Smithy trait
# IDs cannot collide with a field name.
IGNORED_KEYS = {
    "smithy.rules#endpointBdd",
    "smithy.rules#endpointRuleSet",
    "smithy.rules#endpointTests",
    "smithy.api#documentation",
}

# Prose keys, skipped only when the value is text. A vendor field that happens
# to be called "description" is a schema (an object) and is still compared.
PROSE_KEYS = {"description", "enumDescriptions"}


def is_prose(v):
    return isinstance(v, str) or (isinstance(v, list) and all(isinstance(x, str) for x in v))

REF_KEYS = ("$ref",)


def normalize_refs(v):
    """Strip leading ../ from every $ref so a spec moved one folder deeper or
    shallower ("../../common-types/x.json" -> "../../../common-types/x.json")
    diffs clean, while a ref to a different target still shows."""
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if k in REF_KEYS and isinstance(x, str):
                while x.startswith("../"):
                    x = x[3:]
                out[k] = x
            else:
                out[k] = normalize_refs(x)
        return out
    if isinstance(v, list):
        return [normalize_refs(x) for x in v]
    return v


def strip_ignored(v):
    if isinstance(v, dict):
        return {
            k: strip_ignored(x)
            for k, x in v.items()
            if k not in IGNORED_KEYS and not (k in PROSE_KEYS and is_prose(x))
        }
    if isinstance(v, list):
        return [strip_ignored(x) for x in v]
    return v


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
    old = normalize_refs(strip_ignored(old))
    new = normalize_refs(strip_ignored(new))
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
