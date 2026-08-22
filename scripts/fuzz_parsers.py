# ruff: noqa: ANN, D103, S311, E402
# A release tool, not library code: the random is for coverage, every function
# is local to this file, and sys.path is set before the project imports on purpose.
"""Fuzz every hand-written parser for exceptions it does not mean to raise.

Found two stack-exhaustion bugs before 2.0.1 and two crashes before 2.0.5
(a bare pipe in KQL, JSON nested twenty thousand deep in HEC). Run it before
every release:

    backend/.venv/bin/python scripts/fuzz_parsers.py

Each parser has a set of exceptions it is *meant* to raise for bad input;
anything else — IndexError, RecursionError, TypeError — is a crash path that
would reach a client as a 500. Exit status 1 when anything is found.
"""

from __future__ import annotations

import random
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "conformance"))

from api.middleware.audit import _mask_query  # noqa: E402
from harness.normalize import mask, skeleton, strip_prefix  # noqa: E402
from harness.spec import substitute  # noqa: E402
from utils.es_query import build_predicate  # noqa: E402
from utils.mde_kql import parse_kql  # noqa: E402
from utils.splunk.hec_validation import parse_hec_payload  # noqa: E402
from utils.splunk.spl_parser import parse_spl  # noqa: E402

random.seed(7)
ALPHABET = string.ascii_letters + string.digits + " |=()[]{}\"'\\,.:;*<>!&-_$%@#\n\t"
EXPECTED = {
    "ValueError",
    "HecError",
    "KqlError",
    "ESQueryError",
    "SpecError",
    "ESAggregationError",
    "HTTPException",
    "KeyError",
    "TypeError",
}


def rnd(n: int) -> str:
    return "".join(random.choice(ALPHABET) for _ in range(n))


def deep(n: int) -> str:
    return "(" * n + "x" + ")" * n


found: dict[str, list[tuple[str, str]]] = {}
count = 0


def check(name: str, fn, inp, strict: bool = False) -> None:  # noqa: ANN001
    global count
    count += 1
    try:
        fn(inp)
    except RecursionError:
        found.setdefault(name, []).append(("RecursionError", repr(inp)[:50]))
    except Exception as exc:  # noqa: BLE001 - the point is to see every kind
        kind = type(exc).__name__
        if strict or kind not in EXPECTED:
            found.setdefault(name, []).append((f"{kind}: {str(exc)[:40]}", repr(inp)[:50]))


cases = [rnd(random.randint(0, 200)) for _ in range(1500)]
cases += [deep(n) for n in (50, 100, 500, 2000, 10000)]
cases += ["search " + deep(n) for n in (100, 1000, 5000)]
cases += [
    "search index=x | " + " | ".join(rnd(10) for _ in range(500)),
    "",
    " ",
    "|",
    "||",
    "| | |",
    "search",
    "search |",
    "| stats",
    "stats count by " + ",".join(rnd(5) for _ in range(300)),
    "search index=x | eval a=" + "+".join("1" for _ in range(3000)),
    "search index=x | where " + deep(300),
    'search "' + '\\"' * 500,
    "search index=x | stats " + ",".join(f"count(f{i})" for i in range(500)),
]
for c in cases:
    check("spl", parse_spl, c)
    check("kql", parse_kql, c)
    check("mask", mask, c, True)
    check("strip_prefix", lambda s: strip_prefix(s, "/elastic"), c, True)
    check("_mask_query", _mask_query, c, True)
    check("substitute", lambda s: substitute(s, {"a": "b"}), c, True)

hec = cases + ['{"q":' * n + "1" + "}" * n for n in (100, 1000, 5000, 20000)]
hec += [
    '{"event":' + "[" * 5000 + "]" * 5000 + "}",
    "{}" * 3000,
    '{"event":"x"}' * 2000,
    "\x00\x01",
    "\ufeff{}",
    "[",
    "]",
    "{",
    "}",
]
for c in hec:
    check("hec", parse_hec_payload, c)


def bool_nest(n: int) -> dict:
    q: dict = {"match_all": {}}
    for _ in range(n):
        q = {"bool": {"must": [q]}}
    return q


es = [bool_nest(n) for n in (10, 50, 200, 1000, 5000)]
es += [
    {"bool": {"must": [{"bool": {"must": []}}] * 200}},
    {"bool": {k: None for k in ("must", "should", "filter", "must_not")}},
    {"bool": "x"},
    {"range": {"a": None}},
    {"term": None},
    {"terms": {"a": "notalist"}},
    {"wildcard": {"a": {"value": None}}},
    {"query_string": {"query": "(" * 2000}},
    {"regexp": {"a": "(a+)+$"}},
    {"nested": {"path": None}},
    {"match": {"a": {"query": None}}},
    {"exists": {}},
    {"ids": {"values": None}},
    {},
    None,
    [],
    "str",
    42,
]
for q in es:
    check("es_query", build_predicate, q)


def nested(n: int) -> dict:
    d: dict = {}
    node = d
    for _ in range(n):
        node["k"] = {}
        node = node["k"]
    return d


for n in (50, 500, 5000):
    check("skeleton", lambda d: skeleton(d, frozenset()), nested(n), True)
check(
    "skeleton-wide",
    lambda d: skeleton(d, frozenset()),
    {str(i): [{"a": i}] for i in range(20000)},
    True,
)

print(f"=== FUZZ RESULT === {count} inputs")
if not found:
    print("  no unexpected exceptions")
for name, hits in found.items():
    print(f"  {name}: {len(hits)}")
    for exc, inp in hits[:4]:
        print(f"      {exc}  <- {inp}")
raise SystemExit(1 if found else 0)
