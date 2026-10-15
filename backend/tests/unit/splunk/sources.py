"""A table of data for the pipeline commands that read beyond their rows.

``lookup``, ``inputlookup``, ``tstats`` and ``append`` read through a
:class:`~utils.splunk.spl_sources.SearchSources`; these tests hand them this
one, so what they read is written next to what they are expected to answer.
"""
from __future__ import annotations

from typing import Any

from utils.splunk.spl_exec import execute_pipeline
from utils.splunk.spl_parser import parse_spl
from utils.splunk.spl_sources import EventSelector, LookupTable

Rows = list[dict[str, Any]]


class FakeSources:
    """Lookups by name, a list of events, and subsearches run on both."""

    def __init__(
        self, tables: dict[str, LookupTable] | None = None, events: Rows | None = None,
    ) -> None:
        """Hold the tables and events the search may read."""
        self.tables = tables or {}
        self.event_rows = events or []
        self.selectors: list[EventSelector] = []

    def lookup(self, name: str) -> LookupTable | None:
        """The table registered under *name*."""
        return self.tables.get(name)

    def events(self, selector: EventSelector) -> Rows:
        """The events the selector's index and time window admit."""
        self.selectors.append(selector)
        picked = []
        for event in self.event_rows:
            if selector.index and str(event.get("index", "")).lower() != selector.index.lower():
                continue
            stamp = float(event.get("_time", 0))
            if selector.earliest and stamp < selector.earliest:
                continue
            if selector.latest and stamp > selector.latest:
                continue
            picked.append(dict(event))
        return picked

    def subsearch(self, spl: str) -> tuple[Rows, list[dict[str, str]]]:
        """Run *spl* over the same sources."""
        query = parse_spl(spl)
        rows = [] if spl.lstrip().startswith("|") else self.events(EventSelector(
            index=query.index,
        ))
        return execute_pipeline(rows, query, sources=self)


def run(spl: str, sources: FakeSources, rows: Rows | None = None,
        window: tuple[float, float] = (0.0, 0.0)) -> tuple[Rows, list[dict[str, str]]]:
    """Run a pipeline against *sources*."""
    return execute_pipeline(list(rows or []), parse_spl(spl), sources=sources,
                            time_window=window)


def out(spl: str, sources: FakeSources, rows: Rows | None = None,
        window: tuple[float, float] = (0.0, 0.0)) -> Rows:
    """The rows a pipeline produces, raising if it did not run."""
    produced, messages = run(spl, sources, rows, window)
    fatal = [m for m in messages if m["type"] == "FATAL"]
    if fatal:
        raise AssertionError(f"unexpected failure: {fatal[0]['text']}")
    return produced


def failure(spl: str, sources: FakeSources, rows: Rows | None = None) -> str:
    """The FATAL text a pipeline produces."""
    _rows, messages = run(spl, sources, rows)
    fatal = [m for m in messages if m["type"] == "FATAL"]
    assert fatal, "expected the search to fail"
    return fatal[0]["text"]
