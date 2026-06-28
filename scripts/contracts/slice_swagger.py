#!/usr/bin/env python3
"""Slice an Azure ARM Swagger (OpenAPI 2.0) doc down to the response definitions
a source plugin reads, plus their transitive "#/definitions/" closure.

Azure RPs publish huge multi-file swaggers; we keep only the shape graph behind
the resources our armXXX clients deserialize (descriptions stripped — prose, and
Azure embeds example values the fixture gate forbids). Feeds L3 drift diffing.

Usage: slice_swagger.py <in.json> <out.json> <title> <x-source> <x-slice> Def1 Def2 ...
"""
import json
import re
import sys

ref_re = re.compile(r'"#/definitions/([^"]+)"')


def refs_in(obj):
    return set(ref_re.findall(json.dumps(obj)))


def strip_descriptions(obj):
    if isinstance(obj, dict):
        obj.pop("description", None)
        for v in obj.values():
            strip_descriptions(v)
    elif isinstance(obj, list):
        for x in obj:
            strip_descriptions(x)


def main():
    in_path, out_path, title, source, slice_desc = sys.argv[1:6]
    seeds = sys.argv[6:]
    d = json.load(open(in_path))
    defs = d.get("definitions", {})
    for s in seeds:
        if s not in defs:
            sys.exit(f"slice_swagger: definition not found: {s}")

    needed = set()
    frontier = set(seeds)
    while frontier:
        name = frontier.pop()
        if name in needed or name not in defs:
            continue
        needed.add(name)
        frontier |= refs_in(defs[name])

    out_defs = {n: defs[n] for n in sorted(needed)}
    strip_descriptions(out_defs)
    out = {
        "swagger": d.get("swagger", "2.0"),
        "info": {
            "title": title,
            "version": d.get("info", {}).get("version", "unknown"),
            "x-source": source,
            "x-slice": slice_desc,
        },
        "definitions": out_defs,
    }
    json.dump(out, open(out_path, "w"), indent=2, sort_keys=False)
    print(f"  {out_path}: {len(needed)} definitions")


if __name__ == "__main__":
    main()
