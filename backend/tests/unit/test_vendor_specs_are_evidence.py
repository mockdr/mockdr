"""Every vendored spec must be readable evidence.

The whole repository rests on "no evidence, no route": a route, field or
wording is kept because a vendor spec under ``data/vendor-specs`` says so.
A failed download saved under a spec's name reads as evidence to a human
and as nothing to a comparator — `sentinel__DataConnectors.json` held the
14 bytes ``404: Not Found`` for weeks.  A file that cannot be parsed is
worse than a missing one, because an audit that globs the directory counts
it as judged.
"""
from __future__ import annotations

import json
from pathlib import Path

SPECS = Path(__file__).resolve().parents[3] / "data" / "vendor-specs"


def test_the_directory_is_where_it_is_expected() -> None:
    assert SPECS.is_dir(), f"{SPECS} is missing"
    assert sorted(SPECS.rglob("*.json")), (
        "no vendored specs found — the path is probably wrong"
    )


def test_every_vendored_spec_parses_and_says_something() -> None:
    """One test over all of them: the autouse re-seed makes 176 of them slow."""
    unusable: list[str] = []
    for spec in sorted(SPECS.rglob("*.json")):
        raw = spec.read_text(encoding="utf-8")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            unusable.append(
                f"{spec.name}: not JSON ({exc}); first bytes {raw[:40]!r} — "
                "a download that failed is not a specification",
            )
            continue
        if parsed in ({}, [], None):
            unusable.append(f"{spec.name}: parses but holds nothing")
    assert not unusable, "\n".join(unusable)
