"""0.41.7: main.py was split into modules. This test holds the application's contract to what it was before the split
(tests/fixtures/routes.json, written from the unsplit 0.41.6): every route with its methods, path, handler and the
whole tree of its dependencies (the permission checks among them), the middleware chain, and the order of every pair
of routes that can match the same request — FastAPI takes the first match, so swapping `/api/tokens/{tid}` and
`/api/tokens/alerts` would change behaviour without changing any line of a handler.

Regenerate only on purpose (a route added or removed): WRITE_ROUTES=/some/path/routes.json pytest -k what_they_were,
then copy it to tests/fixtures/routes.json"""
import json
import os
import re

import main

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "routes.json")


def _deps(dependant):
    out = []
    for d in dependant.dependencies:
        name = getattr(d.call, "__name__", repr(d.call))
        out.append(name)
        out.extend(f"{name}>{x}" for x in _deps(d))
    return out


def _flat(routes):
    """FastAPI 0.142 keeps an included router as one `_IncludedRouter` entry in app.routes; matching goes through it in
    that position. Unfold it in place, so the list is the real matching order (the machine API's routes included)."""
    for r in routes:
        if hasattr(r, "original_router"):
            yield from _flat(r.original_router.routes)
        else:
            yield r


def snapshot():
    routes = []
    for r in _flat(main.app.routes):
        if hasattr(r, "methods") and hasattr(r, "dependant"):
            routes.append({"methods": sorted(r.methods), "path": r.path, "name": r.name, "deps": _deps(r.dependant)})
        elif hasattr(r, "path"):
            routes.append({"methods": sorted(getattr(r, "methods", None) or []), "path": r.path, "name": getattr(r, "name", ""), "deps": []})
    middleware = [m.cls.__name__ for m in main.app.user_middleware]
    return {"routes": routes, "middleware": middleware}


def _seg_overlap(a, b):
    sa, sb = a.strip("/").split("/"), b.strip("/").split("/")
    if any(":path}" in s for s in sa + sb):
        return a.split("{")[0].startswith(b.split("{")[0]) or b.split("{")[0].startswith(a.split("{")[0])
    if len(sa) != len(sb):
        return False
    return all(x == y or x.startswith("{") or y.startswith("{") for x, y in zip(sa, sb))


def test_routes_and_dependencies_are_what_they_were():
    now = snapshot()
    if os.environ.get("WRITE_ROUTES"):          # a path: the repository is mounted read-only in run_tests.sh
        json.dump(now, open(os.environ["WRITE_ROUTES"], "w"), indent=1, ensure_ascii=False)
        return
    was = json.load(open(FIXTURE))
    key = lambda r: (tuple(r["methods"]), r["path"])
    before, after = {key(r): r for r in was["routes"]}, {key(r): r for r in now["routes"]}
    assert sorted(before) == sorted(after), f"routes added: {sorted(set(after) - set(before))}, removed: {sorted(set(before) - set(after))}"
    for k in before:
        assert after[k]["name"] == before[k]["name"], (k, before[k]["name"], after[k]["name"])
        assert after[k]["deps"] == before[k]["deps"], f"{k}: dependencies changed {before[k]['deps']} → {after[k]['deps']}"
    assert now["middleware"] == was["middleware"]


def test_overlapping_routes_keep_their_order():
    was = json.load(open(FIXTURE))
    order_now = {(tuple(r["methods"]), r["path"]): i for i, r in enumerate(snapshot()["routes"])}
    rs = was["routes"]
    flipped = []
    for i in range(len(rs)):
        for j in range(i + 1, len(rs)):
            a, b = rs[i], rs[j]
            if set(a["methods"]) & set(b["methods"]) and a["path"] != b["path"] and _seg_overlap(a["path"], b["path"]):
                ka, kb = (tuple(a["methods"]), a["path"]), (tuple(b["methods"]), b["path"])
                if order_now[ka] > order_now[kb]:
                    flipped.append((a["path"], b["path"]))
    assert not flipped, f"routes that can match the same request changed order: {flipped}"


def test_the_fixture_is_not_trivial():
    was = json.load(open(FIXTURE))
    assert len(was["routes"]) >= 120 and was["middleware"]
    guarded = [r for r in was["routes"] if any(re.search(r"require_|_owner_only|current_", d) for d in r["deps"])]
    assert len(guarded) >= 90, "the snapshot must carry the permission dependencies, or it guards nothing"


def test_every_name_main_had_is_still_there():
    """sdk_api reaches main through __import__("main") — after the split it found no archive_value, and the token-watch
    notifier, wrapped in a broad except, would have gone silent. Every top-level name of the unsplit main.py of 0.41.6
    (definitions and imports) must still resolve as main.<name>."""
    names = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "main-names-0.41.6.json")))
    assert len(names) > 240
    missing = [n for n in names if not hasattr(main, n)]
    assert not missing, missing
