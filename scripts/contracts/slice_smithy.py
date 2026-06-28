#!/usr/bin/env python3
"""Slice an AWS Smithy 2.0 model down to the operations a source plugin calls.

Keeps the named operations plus the transitive shape closure (everything
reachable via "target" references) and a service shape trimmed to just those
operations. Documentation/examples traits are stripped — they carry AWS's
canonical 123456789012 example account (which the fixture gate forbids) and are
irrelevant to shape-drift detection. Output feeds L3 `smithy diff`.

Usage:
  slice_smithy.py <in.json> <out.json> Op1 Op2 ...
"""
import json
import re
import sys

target_re = re.compile(r'"target"\s*:\s*"([^"]+)"')
# Traits irrelevant to shape-drift detection that also carry AWS's canonical
# example account IDs / ARNs (which the fixture gate forbids): prose docs,
# request/response examples, and the endpoint-resolution + smoke-test traits.
DROP_TRAITS = {
    "smithy.api#documentation",
    "smithy.api#examples",
    "smithy.rules#endpointRuleSet",
    "smithy.rules#endpointTests",
    "smithy.test#smokeTests",
}


def refs_in(obj):
    return set(target_re.findall(json.dumps(obj)))


def strip_traits(obj):
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            if k in DROP_TRAITS:
                del obj[k]
            else:
                strip_traits(obj[k])
    elif isinstance(obj, list):
        for x in obj:
            strip_traits(x)


def main():
    in_path, out_path = sys.argv[1:3]
    op_names = sys.argv[3:]
    d = json.load(open(in_path))
    shapes = d["shapes"]

    svc_id = next((k for k, v in shapes.items() if v.get("type") == "service"), None)
    if not svc_id:
        sys.exit("slice_smithy: no service shape")
    namespace = svc_id.split("#", 1)[0]
    op_ids = [f"{namespace}#{name}" for name in op_names]
    for op in op_ids:
        if op not in shapes:
            sys.exit(f"slice_smithy: operation not found: {op}")

    needed = set()
    frontier = set(op_ids)
    while frontier:
        name = frontier.pop()
        if name in needed or name not in shapes:
            continue
        needed.add(name)
        frontier |= refs_in(shapes[name])

    svc = dict(shapes[svc_id])
    svc["operations"] = [{"target": op} for op in sorted(op_ids)]
    svc.pop("resources", None)

    out_shapes = {svc_id: svc}
    for n in sorted(needed):
        out_shapes[n] = shapes[n]
    strip_traits(out_shapes)

    out = {"smithy": d.get("smithy", "2.0"), "shapes": out_shapes}
    json.dump(out, open(out_path, "w"), indent=1, sort_keys=False)
    print(f"  {out_path}: {len(out_shapes)} shapes")


if __name__ == "__main__":
    main()
