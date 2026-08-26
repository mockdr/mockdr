"""SPL (Search Processing Language) parser.

Parses the search clause into a boolean expression tree and the pipeline into
an **ordered** list of commands, so ``| head 1 | sort _time`` and
``| sort _time | head 1`` mean what they mean in Splunk.

The previous parser flattened the pipeline into a fixed set of flags applied in
a hard-coded order, silently dropped every command it did not recognise, and
kept only the first ``where`` clause. A query asking for ``| stats count``
therefore came back as the full unfiltered event set with no indication that
the command had been ignored — the failure a mock exists to surface.

Commands the executor implements are listed in :data:`KNOWN_COMMANDS`; anything
else is recorded in :attr:`SPLQuery.errors` so the job can report it the way
splunkd reports an unknown search command.
"""
from __future__ import annotations

import re
import time
from calendar import monthrange
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from utils.splunk.spl_expr import Node, SPLExprError, parse_search

__all__ = [
    "KNOWN_COMMANDS",
    "current_time",
    "parse_sort_keys",
    "SPLCommand",
    "SPLQuery",
    "parse_spl",
    "resolve_relative_time",
]

# Commands the executor implements. Anything outside this set is reported
# rather than silently ignored.
KNOWN_COMMANDS = frozenset({
    "bin", "bucket", "convert", "dedup", "eval", "eventstats", "fields",
    "filldown", "fillnull", "head", "makeresults", "mvexpand", "rare",
    "regex", "rename", "rex", "search", "sort", "spath", "stats",
    "streamstats", "table", "tail", "timechart", "top", "where",
})

# Field names that carry meaning in the search clause rather than being an
# ordinary event field.
_BUILTIN_SEARCH_FIELDS = {
    "index", "sourcetype", "source", "host", "earliest", "latest",
}


@dataclass
class SPLCommand:
    """One command in the pipeline, in the order it was written."""

    name: str
    arg: str


@dataclass
class SPLQuery:
    """A parsed SPL query."""

    index: str = ""
    sourcetype: str = ""
    source: str = ""
    host: str = ""
    earliest_time: str = ""
    latest_time: str = ""
    field_filters: dict[str, str] = field(default_factory=dict)
    search_expr: Node | None = None
    commands: list[SPLCommand] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    raw_search: str = ""
    is_notable: bool = False
    #: The first command the parser did not recognise, if any. splunkd
    #: answers such a dispatch with 400 rather than running what it could.
    unknown_command: str = ""
    #: Whether the time bounds came from the search string rather than from
    #: the request's own earliest_time/latest_time parameters. splunkd
    #: announces the first case with an INFO message and the second silently.
    from_search_string: bool = False

    # -- compatibility accessors ----------------------------------------
    # The pipeline is authoritative; these read it back for callers and tests
    # that ask about a single command.

    def _first(self, name: str) -> str | None:
        return next((c.arg for c in self.commands if c.name == name), None)

    @property
    def head(self) -> int:
        """First ``head`` limit in the pipeline, or 0."""
        arg = self._first("head")
        return _as_int(arg) if arg is not None else 0

    @property
    def tail(self) -> int:
        """First ``tail`` limit in the pipeline, or 0."""
        arg = self._first("tail")
        return _as_int(arg) if arg is not None else 0

    @property
    def table_fields(self) -> list[str]:
        """Fields named by the first ``table``/``fields`` command."""
        arg = self._first("table") or self._first("fields")
        return _split_fields(arg) if arg else []

    @property
    def stats_count_by(self) -> str:
        """The first ``stats ... by`` grouping field, if any."""
        arg = self._first("stats")
        if not arg:
            return ""
        match = re.search(r"\bby\s+(.+)$", arg, re.IGNORECASE)
        return _split_fields(match.group(1))[0] if match else ""

    @property
    def sort_field(self) -> str:
        """Primary sort field, or an empty string."""
        keys = self.sort_keys
        return keys[0][0] if keys else ""

    @property
    def sort_descending(self) -> bool:
        """Whether the primary sort key is descending."""
        keys = self.sort_keys
        return keys[0][1] if keys else False

    @property
    def sort_keys(self) -> list[tuple[str, bool]]:
        """Sort fields as ``(field, descending)``, in precedence order."""
        arg = self._first("sort")
        return parse_sort_keys(arg) if arg else []

    @property
    def where_clauses(self) -> list[tuple[str, str]]:
        """Simple ``field=value`` pairs, for callers that only need those."""
        pairs: list[tuple[str, str]] = []
        for command in self.commands:
            if command.name != "where":
                continue
            for match in re.finditer(
                r'(\w+)\s*=\s*(?:"([^"]*)"|(\S+))', command.arg,
            ):
                pairs.append((match.group(1), match.group(2) or match.group(3)))
        return pairs

    @property
    def renames(self) -> dict[str, str]:
        """All ``rename`` mappings, merged in pipeline order."""
        result: dict[str, str] = {}
        for command in self.commands:
            if command.name == "rename":
                result.update(_parse_rename(command.arg))
        return result

    @property
    def evals(self) -> dict[str, str]:
        """All ``eval`` assignments as raw expression text."""
        result: dict[str, str] = {}
        for command in self.commands:
            if command.name == "eval":
                name, expr = _split_assignment(command.arg)
                if name:
                    result[name] = expr
        return result


def _as_int(text: str) -> int:
    try:
        return int(text.strip())
    except (TypeError, ValueError):
        return 0


def _split_fields(text: str) -> list[str]:
    return [f.strip() for f in re.split(r"[,\s]+", text.strip()) if f.strip()]


def parse_sort_keys(arg: str) -> list[tuple[str, bool]]:
    """Parse ``sort`` into ordered ``(field, descending)`` pairs.

    Splunk allows several fields and a per-field direction, e.g.
    ``sort sourcetype, -_time``; only the whole argument was previously read
    as one field name, so any multi-field sort became a no-op.
    """
    keys: list[tuple[str, bool]] = []
    for part in re.split(r"\s*,\s*|\s+", arg.strip()):
        token = part.strip()
        if not token or token.isdigit():
            continue  # a leading count, e.g. `sort 10 -_time`
        descending = token.startswith("-")
        name = token.lstrip("+-").strip()
        # `sort desc(field)` / `sort asc(field)`
        wrapper = re.fullmatch(r"(?i)(asc|desc)\((.+)\)", name)
        if wrapper:
            descending = wrapper.group(1).lower() == "desc"
            name = wrapper.group(2).strip()
        if name:
            keys.append((name, descending))
    return keys


def _parse_rename(arg: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for clause in arg.split(","):
        match = re.match(r'\s*(\S+)\s+as\s+"?([^",]+)"?\s*$', clause, re.IGNORECASE)
        if match:
            result[match.group(1).strip('"')] = match.group(2).strip()
    return result


def _split_assignment(arg: str) -> tuple[str, str]:
    match = re.match(r"\s*(\w+)\s*=\s*(.+)$", arg, re.DOTALL)
    return (match.group(1), match.group(2).strip()) if match else ("", "")


def _split_pipeline(source: str) -> list[str]:
    """Split on ``|`` that is not inside quotes or parentheses."""
    segments: list[str] = []
    current: list[str] = []
    depth = 0
    in_quotes = False
    index = 0
    while index < len(source):
        char = source[index]
        if char == "\\" and in_quotes and index + 1 < len(source):
            current.append(char)
            current.append(source[index + 1])
            index += 2
            continue
        if char == '"':
            in_quotes = not in_quotes
        elif not in_quotes and char in "([":
            depth += 1
        elif not in_quotes and char in ")]":
            depth = max(depth - 1, 0)
        elif char == "|" and not in_quotes and depth == 0:
            segments.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    segments.append("".join(current))
    return segments


def parse_spl(query: str) -> SPLQuery:
    """Parse an SPL query string.

    Args:
        query: Raw SPL query string.

    Returns:
        A :class:`SPLQuery` holding the search clause and the ordered pipeline.
    """
    result = SPLQuery(raw_search=query)

    expanded = query.strip()
    if "`notable`" in expanded:
        expanded = expanded.replace("`notable`", "search index=notable")
        result.is_notable = True

    segments = _split_pipeline(expanded)
    search_clause = segments[0].strip()
    if search_clause.lower().startswith("search "):
        search_clause = search_clause[7:]

    _parse_search_clause(search_clause, result)

    for segment in segments[1:]:
        text = segment.strip()
        if not text:
            continue
        name, _, arg = text.partition(" ")
        name = name.lower().strip()
        if name not in KNOWN_COMMANDS:
            # splunkd refuses the dispatch outright for this one: it is not a
            # search that ran badly, it is not a search it can parse.
            result.unknown_command = name
            result.errors.append(f"Unknown search command '{name}'.")
            continue
        result.commands.append(SPLCommand(name, arg.strip()))

    return result


def _parse_search_clause(clause: str, result: SPLQuery) -> None:
    """Pull the builtin selectors out of the search clause, then parse the rest.

    ``index``/``sourcetype``/``source``/``host`` and the time modifiers choose
    which events are read, so they are lifted out here; whatever remains is a
    boolean expression evaluated per event.
    """
    if not clause.strip():
        return

    terms = _split_top_level_terms(clause)
    # A selector may only be hoisted out of a flat conjunction. Under NOT or OR
    # it is not a selector at all: `NOT sourcetype=x` was being lifted as
    # `sourcetype == x`, inverting the query into its own opposite.
    hoistable = not any(
        term.upper() in ("NOT", "OR") or "(" in term for term in terms
    )

    remainder_parts: list[str] = []
    negated = False
    for segment in terms:
        if segment.upper() == "NOT":
            negated = True
            remainder_parts.append(segment)
            continue

        match = re.fullmatch(
            r'\s*(\w+)\s*=\s*(?:"([^"]*)"|(\S+))\s*', segment,
        )
        if match:
            key = match.group(1).lower()
            value = match.group(2) if match.group(2) is not None else match.group(3)
            if key in ("earliest", "latest"):
                # Time modifiers are never row predicates, so they leave the
                # expression entirely.
                if not negated:
                    _assign_builtin(key, value, result)
                negated = False
                continue
            if key in _BUILTIN_SEARCH_FIELDS:
                if hoistable and "*" not in value:
                    _assign_builtin(key, value, result)
            else:
                result.field_filters[match.group(1)] = value
        negated = False
        remainder_parts.append(segment)

    remainder = " ".join(p.strip() for p in remainder_parts if p.strip())
    if not remainder:
        return
    try:
        result.search_expr = parse_search(remainder)
    except SPLExprError as exc:
        result.errors.append(f"Invalid search expression: {exc}")


def _assign_builtin(key: str, value: str, result: SPLQuery) -> None:
    if key == "index":
        result.index = value
    elif key == "sourcetype":
        result.sourcetype = value
    elif key == "source":
        result.source = value
    elif key == "host":
        result.host = value
    elif key == "earliest":
        result.earliest_time = value
        result.from_search_string = True
    elif key == "latest":
        result.latest_time = value
        result.from_search_string = True


def _split_top_level_terms(clause: str) -> list[str]:
    """Split a search clause on whitespace outside quotes and parentheses."""
    terms: list[str] = []
    current: list[str] = []
    depth = 0
    in_quotes = False
    for char in clause:
        if char == '"':
            in_quotes = not in_quotes
        elif not in_quotes and char == "(":
            depth += 1
        elif not in_quotes and char == ")":
            depth = max(depth - 1, 0)
        if char.isspace() and not in_quotes and depth == 0:
            if current:
                terms.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        terms.append("".join(current))
    return terms


def current_time() -> float:
    """The instant ``now`` stands for; one place, so a test can pin it."""
    return time.time()


def resolve_relative_time(time_str: str, now: float | None = None) -> float:
    """Convert a Splunk relative time string to epoch seconds.

    Handles the whole time-modifier grammar a dashboard uses: an offset
    (``-1h``, ``-7d``, ``-1mon``, and the bare ``-h`` that means ``-1h``), a
    snap to the start of a unit (``@d``, ``@mon``, ``@w1``), and further
    offsets applied after the snap (``-1d@d+3h``). ``now`` and an epoch
    literal are accepted as they are.

    Args:
        time_str: Splunk time modifier string.
        now:      The instant to resolve against. A search resolves both of
                  its bounds against one reading of the clock, so
                  ``earliest=-5m latest=-5m`` names a single instant rather
                  than a window a few microseconds wide.

    Returns:
        Epoch seconds as float, or 0.0 when the string cannot be understood.
    """
    if now is None:
        now = current_time()
    if not time_str:
        return 0.0

    text = time_str.strip()
    if text.lower() == "now":
        return now

    try:
        return float(text)
    except ValueError:
        pass

    head, snapped, tail = text.partition("@")
    moment = _apply_offsets(now, head.strip())
    if moment is None:
        return 0.0
    if not snapped:
        return moment

    match = _SNAP_UNIT_RE.match(tail.strip())
    if not match:
        return 0.0
    moment = _snap(moment, match.group(1))
    if moment is None:
        return 0.0
    # `-1d@d+3h`: whatever follows the snap unit shifts the snapped instant.
    return _apply_offsets(moment, tail.strip()[match.end():]) or 0.0


#: The unit right after ``@``, optionally a weekday number for ``w``.
_SNAP_UNIT_RE = re.compile(r"([A-Za-z]+\d?)")

#: One ``+1h`` / ``-30m`` term; the count defaults to 1, as ``-h`` does.
_OFFSET_RE = re.compile(r"([+-])(\d*)([A-Za-z]+)")


def _apply_offsets(moment: float, text: str) -> float | None:
    """Apply every offset term in *text* to *moment*, left to right.

    Returns:
        The shifted instant, or ``None`` if *text* is not offsets.
    """
    if not text:
        return moment
    position = 0
    while position < len(text):
        match = _OFFSET_RE.match(text, position)
        if not match:
            return None
        sign, count, unit = match.groups()
        shifted = _shift(moment, (1 if sign == "+" else -1) * int(count or 1), unit.lower())
        if shifted is None:
            return None
        moment = shifted
        position = match.end()
    return moment


#: Units whose length is fixed, so a duration in seconds is exact.
_FIXED_UNITS: dict[str, int] = {
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
    "d": 86400, "day": 86400, "days": 86400,
    "w": 604800, "week": 604800, "weeks": 604800,
}

#: Units that are calendar arithmetic — a month is not 30 days, and treating
#: it as one put ``-1mon`` on a different day every month.
_CALENDAR_MONTHS: dict[str, int] = {
    "mon": 1, "month": 1, "months": 1,
    "q": 3, "qtr": 3, "quarter": 3, "quarters": 3,
    "y": 12, "yr": 12, "year": 12, "years": 12,
}


def _shift(moment: float, amount: int, unit: str) -> float | None:
    """Move *moment* by *amount* of *unit*, or ``None`` for an unknown unit."""
    fixed = _FIXED_UNITS.get(unit)
    if fixed is not None:
        return moment + amount * fixed
    months = _CALENDAR_MONTHS.get(unit)
    if months is None:
        return None
    return _add_months(moment, amount * months)


def _add_months(moment: float, months: int) -> float:
    """Add calendar months, clamping the day to the target month's length."""
    stamp = datetime.fromtimestamp(moment, tz=UTC)
    total = stamp.month - 1 + months
    year = stamp.year + total // 12
    month = total % 12 + 1
    day = min(stamp.day, monthrange(year, month)[1])
    return stamp.replace(year=year, month=month, day=day).timestamp()


def _snap(moment: float, unit: str) -> float | None:
    """Snap *moment* down to the start of *unit*, the way ``@`` does.

    Splunk snaps on the calendar, not on a multiple of seconds. Modulo
    arithmetic gets the sub-day units right by accident and everything above
    them wrong: the epoch fell on a Thursday, so ``@w`` landed on a Thursday
    rather than the preceding Sunday, and ``@mon`` snapped to a multiple of
    30 days rather than to the first of the month.
    """
    unit = unit.lower()
    fixed = _FIXED_UNITS.get(unit)
    if fixed is not None and unit not in ("w", "week", "weeks"):
        return moment - (moment % fixed)

    stamp = datetime.fromtimestamp(moment, tz=UTC)
    midnight = stamp.replace(hour=0, minute=0, second=0, microsecond=0)

    if unit in ("w", "week", "weeks") or _WEEKDAY_RE.fullmatch(unit):
        # `@w0` is Sunday and `@w` means `@w0`; Python counts Monday as 0.
        wanted = int(unit[1:]) if len(unit) > 1 and unit[1:].isdigit() else 0
        current = (midnight.weekday() + 1) % 7
        return (midnight - timedelta(days=(current - wanted) % 7)).timestamp()

    months = _CALENDAR_MONTHS.get(unit)
    if months is None:
        # Ignoring an unreadable snap would hand back the unsnapped instant,
        # which is a different window from the one that was asked for.
        return None
    if months == 12:
        return midnight.replace(month=1, day=1).timestamp()
    if months == 3:
        return midnight.replace(month=(stamp.month - 1) // 3 * 3 + 1, day=1).timestamp()
    return midnight.replace(day=1).timestamp()


#: ``@w0`` … ``@w6`` — the weekday to snap back to.
_WEEKDAY_RE = re.compile(r"w[0-6]")

