#!/usr/bin/env python3
"""Slice an OpenAPI 3 spec down to the operations a source plugin calls.

Extracts each listed operation's 200 application/json response schema plus the
transitive #/components/schemas closure, emitting a small self-contained doc for
the L2 fixture-vs-spec test (sourcetest.NewSpecValidator) and L3 drift diffing.

Usage:
  slice_openapi.py <in.json> <out.json> <title> <x-source> <x-slice> METHOD:/path ...
"""
import json
import re
import sys

ref_re = re.compile(r'"#/components/schemas/([^"]+)"')


def refs_in(obj):
    return set(ref_re.findall(json.dumps(obj)))


def main():
    in_path, out_path, title, source, slice_desc = sys.argv[1:6]
    ops = sys.argv[6:]
    spec = json.load(open(in_path))
    all_schemas = spec["components"]["schemas"]

    paths = {}
    for op in ops:
        method, _, p = op.partition(":")
        method = method.lower()
        if p not in spec["paths"] or method not in spec["paths"][p]:
            sys.exit(f"slice_openapi: operation not found: {op}")
        operation = spec["paths"][p][method]
        resp = operation["responses"].get("200") or operation["responses"].get("201")
        if not resp:
            sys.exit(f"slice_openapi: no 200/201 response for {op}")
        sch = resp["content"]["application/json"]["schema"]
        paths.setdefault(p, {})[method] = {
            "operationId": operation.get("operationId"),
            "responses": {"200": {
                "description": resp.get("description", "ok"),
                "content": {"application/json": {"schema": sch}},
            }},
        }

    needed = set()
    frontier = refs_in(paths)
    while frontier:
        name = frontier.pop()
        if name in needed:
            continue
        needed.add(name)
        if name not in all_schemas:
            sys.exit(f"slice_openapi: schema not found: {name}")
        frontier |= refs_in(all_schemas[name])

    out = {
        "openapi": spec["openapi"],
        "info": {
            "title": title,
            "version": spec.get("info", {}).get("version", "unknown"),
            "x-source": source,
            "x-slice": slice_desc,
        },
        "paths": paths,
        "components": {"schemas": {n: all_schemas[n] for n in sorted(needed)}},
    }
    json.dump(out, open(out_path, "w"), indent=2, sort_keys=False)
    print(f"  {out_path}: {len(needed)} schemas")


if __name__ == "__main__":
    main()
