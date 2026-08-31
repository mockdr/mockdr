"""A schema name a router uses must name a fixture that exists.

`restrict_s1` and `restrict_item` reduce a response to the fields its
schema declares. Handed a name with no fixture behind it they find no
template and return the record untouched — the whole reduction silently
skipped, with nothing in the answer to show it.

That is how `PUT /exclusions` and `PUT /restrictions` came to answer
`siteId`, a field their schema does not declare and their own read path
does not return: both named `…Schema_many_200` where the only fixture is
`…SchemaGet_many_200`. Read and write disagreeing about a tenant field is
worse than either being wrong on its own.

The fixtures live under `infrastructure/`, which is committed, so this
runs where it matters rather than only where the swagger happens to be.
"""
from __future__ import annotations

import re
from pathlib import Path

from utils.s1_fixtures import _fixture

_ROOT = Path(__file__).resolve().parents[3]
#: A quoted `<module>.schemas_<Name>` literal, and any `definition=` argument.
_NAMED = re.compile(r'["\']([A-Za-z_][\w.]*\.schemas_\w+)["\']')
_DEFINITION = re.compile(r'definition\s*=\s*["\']([^"\']+)["\']')


def _names() -> set[str]:
    found: set[str] = set()
    for folder in ("api", "application"):
        for path in (_ROOT / folder).rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            found |= set(_NAMED.findall(text))
            found |= set(_DEFINITION.findall(text))
    return found


def test_the_sweep_has_something_to_sweep() -> None:
    """A sweep over nothing passes for the wrong reason."""
    assert len(_names()) >= 15


def test_every_name_resolves_to_a_fixture() -> None:
    unresolved = sorted(n for n in _names() if not _fixture(n).get("data"))
    assert unresolved == []
