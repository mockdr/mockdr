"""FQL spells a wildcard with the star before the value: ``hostname:*'*prod*'``.

The parser read that star as part of the value, so every wildcard query — the
form a Falcon console builds for any "contains" search — matched nothing and
answered 200 with an empty list.
"""

from __future__ import annotations

import pytest

from utils.cs_fql import apply_fql

_HOSTS = [
    {"hostname": "SERVER-PROD-01", "agent_version": "23.2.1.1", "severity": 34},
    {"hostname": "WIN-DESKTOP-9", "agent_version": "7.0.0.1", "severity": 80},
    {"hostname": "mac-laptop", "agent_version": "23.2.1.1", "severity": 10},
]


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("hostname:*'*PROD*'", ["SERVER-PROD-01"]),
        ("hostname:*'SERVER*'", ["SERVER-PROD-01"]),
        ("hostname:*'*'", ["SERVER-PROD-01", "WIN-DESKTOP-9", "mac-laptop"]),
        ("hostname:!*'*PROD*'", ["WIN-DESKTOP-9", "mac-laptop"]),
        # The quoted-pattern form keeps working, as do the plain operators.
        ("hostname:'*PROD*'", ["SERVER-PROD-01"]),
        ("hostname:'mac-laptop'", ["mac-laptop"]),
        ("hostname:!'mac-laptop'", ["SERVER-PROD-01", "WIN-DESKTOP-9"]),
        ("agent_version:*'23*'", ["SERVER-PROD-01", "mac-laptop"]),
        ("severity:>50", ["WIN-DESKTOP-9"]),
        ("agent_version:*'23*'+severity:<50", ["SERVER-PROD-01", "mac-laptop"]),
    ],
)
def test_wildcard_forms(query: str, expected: list[str]) -> None:
    assert [h["hostname"] for h in apply_fql(_HOSTS, query)] == expected
