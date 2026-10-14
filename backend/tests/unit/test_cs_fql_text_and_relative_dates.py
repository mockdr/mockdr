"""FQL's ``~`` text match and its ``'now-24h'`` relative timestamps.

Two pieces of Falcon's filter language the parser did not know:

* ``~`` is a case-insensitive text match and ``!~`` its negation.
  CrowdStrike's falcon-mcp FQL guides document both ("~: field_name:~'partial'
  (text match, case insensitive)", "!~: field_name:!~'exclude' (not text
  match)", ``falcon_mcp/resources/detections.py``; ``hostname:~'server'`` in
  ``resources/hosts.py``), and PSFalcon's Filtering-Results wiki lists ``~``
  as "Case insensitive" with ``name:~'value*'`` as an example. The term
  grammar had no ``~``, so such a filter was refused as invalid.
* A timestamp may be relative: ``timestamp:>'now-24h'``,
  ``last_seen:>'now-7d'`` — "Relative dates supported ... (lowercase 'now',
  quoted)" in the same guides, with days and hours as the units
  (``'now-Nd', 'now-Nh'``, ``resources/intel.py``). The value was compared
  as a string, and ``'now-24h'`` sorts after every ISO timestamp, so ``>``
  matched nothing and ``<`` matched everything.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from utils.cs_fql import FqlError, apply_fql

_HOSTS = [
    {"hostname": "SERVER-PROD-01", "os_version": "Windows Server 2022"},
    {"hostname": "web-server-02", "os_version": "Ubuntu 22.04"},
    {"hostname": "mac-laptop", "os_version": "macOS 14"},
]


def _ago(**delta: float) -> str:
    return (datetime.now(UTC) - timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class TestTextMatch:
    """``~`` matches without regard to case; ``!~`` excludes the same set."""

    @pytest.mark.parametrize(("query", "expected"), [
        ("hostname:~'server'", ["SERVER-PROD-01", "web-server-02"]),
        ("hostname:~'SERVER'", ["SERVER-PROD-01", "web-server-02"]),
        ("os_version:~'windows'", ["SERVER-PROD-01"]),
        ("hostname:~'web*'", ["web-server-02"]),
        ("hostname:!~'server'", ["mac-laptop"]),
        ("hostname:~'server'+os_version:~'ubuntu'", ["web-server-02"]),
    ])
    def test_query(self, query: str, expected: list[str]) -> None:
        assert [h["hostname"] for h in apply_fql(_HOSTS, query)] == expected

    def test_it_is_not_an_invalid_expression(self) -> None:
        try:
            apply_fql(_HOSTS, "hostname:~'server'")
        except FqlError:  # pragma: no cover - the defect this guards
            pytest.fail("~ was refused as an invalid filter")


class TestRelativeDates:
    """``now-<n>d`` and ``now-<n>h`` name an instant, compared as one."""

    _ALERTS = [
        {"id": "fresh", "timestamp": _ago(hours=2)},
        {"id": "yesterday", "timestamp": _ago(hours=30)},
        {"id": "old", "timestamp": _ago(days=10)},
    ]

    @pytest.mark.parametrize(("query", "expected"), [
        ("timestamp:>'now-24h'", ["fresh"]),
        ("timestamp:<'now-24h'", ["yesterday", "old"]),
        ("timestamp:>='now-7d'", ["fresh", "yesterday"]),
        ("timestamp:<='now-7d'", ["old"]),
        ("timestamp:>'now-1h'", []),
        ("timestamp:>'now-30d'", ["fresh", "yesterday", "old"]),
    ])
    def test_query(self, query: str, expected: list[str]) -> None:
        assert [a["id"] for a in apply_fql(self._ALERTS, query)] == expected

    def test_a_record_without_a_timestamp_does_not_match(self) -> None:
        assert apply_fql([{"id": "x", "timestamp": "not a date"}],
                         "timestamp:>'now-24h'") == []

    def test_absolute_timestamps_still_compare(self) -> None:
        assert [a["id"] for a in apply_fql(
            self._ALERTS, f"timestamp:>'{_ago(days=2)}'")] == ["fresh", "yesterday"]
