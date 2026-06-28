#!/usr/bin/env python3
"""Slice a GCP Discovery Document down to the response schemas a plugin reads.

Keeps the named seed schemas plus their transitive "$ref" closure (the shape
graph) and drops the huge resources/methods/parameters sections — shape drift
lives in `schemas`. Output feeds L3 drift diffing (diff_contracts.py).

Usage: slice_discovery.py <in.json> <out.json> SeedSchema1 SeedSchema2 ...
"""
import json
import re
import sys

ref_re = re.compile(r'"\$ref"\s*:\s*"([^"]+)"')


def refs_in(obj):
    return set(ref_re.findall(json.dumps(obj)))


def strip_descriptions(obj):
    # Descriptions are prose (and carry GCP's example emails, which the fixture
    # gate forbids) — irrelevant to shape-drift detection.
    if isinstance(obj, dict):
        obj.pop("description", None)
        for v in obj.values():
            strip_descriptions(v)
    elif isinstance(obj, list):
        for x in obj:
            strip_descriptions(x)


def main():
    in_path, out_path = sys.argv[1:3]
    seeds = sys.argv[3:]
    d = json.load(open(in_path))
    schemas = d["schemas"]
    for s in seeds:
        if s not in schemas:
            sys.exit(f"slice_discovery: seed schema not found: {s}")

    needed = set()
    frontier = set(seeds)
    while frontier:
        name = frontier.pop()
        if name in needed or name not in schemas:
            continue
        needed.add(name)
        frontier |= refs_in(schemas[name])

    out_schemas = {n: schemas[n] for n in sorted(needed)}
    strip_descriptions(out_schemas)
    out = {
        "discoveryVersion": d.get("discoveryVersion", "v1"),
        "name": d.get("name", ""),
        "version": d.get("version", ""),
        "x-slice": "response-schema closure consumed by internal/sources/gcp",
        "schemas": out_schemas,
    }
    json.dump(out, open(out_path, "w"), indent=2, sort_keys=False)
    print(f"  {out_path}: {len(needed)} schemas")


if __name__ == "__main__":
    main()
