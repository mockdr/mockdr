"""What the SPL pipeline reads beyond the rows it was handed.

Most commands transform the rows in front of them. A few read something
else: ``inputlookup`` and ``lookup`` read a lookup table, ``tstats`` reads
the index (or a data model over it) itself, and ``append`` runs a whole
second search. The executor stays free of repositories — the application
layer hands it a :class:`SearchSources` — so the engine can still be driven
from a unit test with a table of its own.
"""
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Protocol

Rows = list[dict[str, Any]]


@dataclass
class LookupTable:
    """A resolved lookup: its fields, its rows, and how matching works.

    The matching settings are transforms.conf's, with its defaults.
    """

    name: str
    fields: list[str]
    rows: Rows = field(default_factory=list)
    max_matches: int = 1000
    min_matches: int = 0
    default_match: str = ""
    case_sensitive_match: bool = True


@dataclass(frozen=True)
class EventSelector:
    """Which indexed events a generating command reads.

    The builtin selectors of a search clause, and the time window as epoch
    seconds (0 for unbounded).
    """

    index: str = ""
    sourcetype: str = ""
    source: str = ""
    host: str = ""
    earliest: float = 0.0
    latest: float = 0.0


class SearchSources(Protocol):
    """The data a search can reach beyond its own rows."""

    def lookup(self, name: str) -> LookupTable | None:
        """The table a lookup name resolves to, or None if there is none."""

    def events(self, selector: EventSelector) -> Rows:
        """Indexed events, newest first, as the search clause reads them."""

    def subsearch(self, spl: str) -> tuple[Rows, list[dict[str, str]]]:
        """Run a subsearch's SPL; its rows and its messages."""


#: The sources of the search being executed, if it was given any.
SOURCES: ContextVar[SearchSources | None] = ContextVar("spl_sources", default=None)

#: The time window the search was dispatched with, as epoch seconds. A
#: generating command that reads the index honours it, as the search
#: clause does.
TIME_WINDOW: ContextVar[tuple[float, float]] = ContextVar(
    "spl_time_window", default=(0.0, 0.0),
)

#: How deep in subsearches the search being executed is.
SUBSEARCH_DEPTH: ContextVar[int] = ContextVar("spl_subsearch_depth", default=0)

#: How many subsearches the outermost search has run so far, shared with
#: every subsearch it starts; None outside a search.
SUBSEARCH_COUNT: ContextVar[list[int] | None] = ContextVar(
    "spl_subsearch_count", default=None,
)

#: The messages of the search being executed, which a command adds to when
#: it reports an error the search survives; None outside a search.
MESSAGES: ContextVar[list[dict[str, str]] | None] = ContextVar(
    "spl_messages", default=None,
)


def report(level: str, text: str) -> None:
    """Add a message to the running search without stopping it.

    splunkd reports some failures as an ``ERROR`` beside the results rather
    than as the ``FATAL`` that ends a search: ``inputlookup`` of a table there
    is none of yields no rows and says why, and the commands after it run.
    """
    messages = MESSAGES.get()
    if messages is not None:
        messages.append({"type": level, "text": text})
