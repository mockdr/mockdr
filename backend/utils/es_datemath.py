"""Elasticsearch date math — ``now-30d``, ``now/d``, ``2026-01-01||+1M/M``.

Every Kibana time picker, every detection rule and every SIEM dashboard
expresses its window in this grammar rather than as an absolute timestamp.
A range clause carrying it used to be compared as a *string*, so
``"2026-08-06T16:16:51.000Z" >= "now-30d"`` was false for every document and
the search answered ``200`` with an empty result set.

Grammar (Elasticsearch "Date math" reference):

* an anchor — either ``now`` or a date terminated by ``||``,
* zero or more offsets — ``+1h``, ``-30d``, where the count defaults to 1,
* an optional rounding — ``/d`` — which truncates to that unit.

Units are ``y`` years, ``M`` months, ``w`` weeks, ``d`` days, ``h``/``H``
hours, ``m`` minutes and ``s`` seconds — ``M`` and ``m`` differ by case.

Rounding direction depends on the comparison the caller is making, which is
what makes ``@timestamp:{gte: "now/d"}`` mean *since midnight* while
``lte: "now/d"`` means *through the end of today* (Elasticsearch's "Date math
and rounding" table for the range query).
"""
from __future__ import annotations

import re
from calendar import monthrange
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

#: Rounding truncates to the start of the unit; ``up`` then advances to the
#: last millisecond the unit still covers.
_MILLI = timedelta(milliseconds=1)

_ANCHOR_NOW = "now"
_ANCHOR_SEP = "||"

#: ``([+-/])(digits)(unit)`` — the rounding operator takes no count.
_OP_RE = re.compile(r"([+\-/])(\d*)([yMwdhHms])")

#: Used only to name the unit an unparseable expression tripped over.
_LOOSE_OP_RE = re.compile(r"[+\-/]\d*(\S)")

_SIMPLE_UNITS: dict[str, str] = {
    "w": "weeks",
    "d": "days",
    "h": "hours",
    "H": "hours",
    "m": "minutes",
    "s": "seconds",
}


class DateMathError(ValueError):
    """Raised when an expression is date math but not a grammar the DSL allows.

    Elasticsearch answers such a range with a 400 naming the offending unit;
    accepting it silently would mean an unbounded window nobody asked for.
    """


def current_time() -> datetime:
    """The instant ``now`` stands for.

    One function, so a test can pin the clock the way the documented
    expectations were taken.
    """
    return datetime.now(tz=UTC)


def is_date_math(value: Any) -> bool:
    """Whether *value* is written in the date-math grammar.

    A plain timestamp is not: it compares correctly as a string already, and
    re-parsing it would only add a way to be wrong.
    """
    if not isinstance(value, str):
        return False
    return value.startswith(_ANCHOR_NOW) or _ANCHOR_SEP in value


def _zone(time_zone: str | None) -> tzinfo:
    """Resolve a ``time_zone`` parameter, falling back to UTC.

    Kibana sends IANA names (``Europe/Berlin``); the DSL also allows fixed
    offsets (``+02:00``). An unknown zone is not worth a 500 from a mock.
    """
    if not time_zone:
        return UTC
    if time_zone in ("Z", "UTC", "+00:00", "-00:00"):
        return UTC
    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", time_zone)
    if match:
        sign = 1 if match.group(1) == "+" else -1
        delta = timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))
        return UTC if not delta else _FixedOffset(sign * delta, time_zone)
    try:
        return ZoneInfo(time_zone)
    except (ZoneInfoNotFoundError, ValueError):
        return UTC


class _FixedOffset(tzinfo):
    """A fixed UTC offset, for the ``+02:00`` spelling of ``time_zone``."""

    def __init__(self, offset: timedelta, name: str) -> None:
        self._offset = offset
        self._name = name

    def utcoffset(self, dt: datetime | None) -> timedelta:
        return self._offset

    def tzname(self, dt: datetime | None) -> str:
        return self._name

    def dst(self, dt: datetime | None) -> timedelta:
        return timedelta(0)


def parse_datetime(value: Any) -> datetime | None:
    """Parse a stored field value as an instant, or ``None`` if it is not one.

    Accepts what a ``date`` field accepts: ISO-8601 (``Z`` or an offset, with
    or without a time), and epoch milliseconds — the two forms the seeded
    records and the ingest APIs actually produce.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        # A date field stores epoch millis; seconds would put every record in
        # 1970 and silently empty every time filter.
        try:
            return datetime.fromtimestamp(value / 1000, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        # An all-digit string is epoch millis, which is how Beats and the
        # bulk API spell a date.
        if text.lstrip("-").isdigit():
            return parse_datetime(int(text))
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _add_months(moment: datetime, months: int) -> datetime:
    """Add *months*, clamping the day the way ``java.time`` does.

    31 January plus one month is 28 (or 29) February, not 3 March.
    """
    total = moment.month - 1 + months
    year = moment.year + total // 12
    month = total % 12 + 1
    day = min(moment.day, monthrange(year, month)[1])
    return moment.replace(year=year, month=month, day=day)


def _apply_offset(moment: datetime, sign: int, count: int, unit: str) -> datetime:
    """Apply one ``+1h`` / ``-30d`` style offset."""
    if unit == "y":
        return _add_months(moment, sign * count * 12)
    if unit == "M":
        return _add_months(moment, sign * count)
    return moment + sign * count * timedelta(**{_SIMPLE_UNITS[unit]: 1})


def _round_down(moment: datetime, unit: str) -> datetime:
    """Truncate *moment* to the start of *unit*."""
    if unit == "y":
        return moment.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    if unit == "M":
        return moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if unit == "w":
        # ISO weeks start on Monday, which is where Elasticsearch rounds to.
        start = moment.replace(hour=0, minute=0, second=0, microsecond=0)
        return start - timedelta(days=start.weekday())
    if unit == "d":
        return moment.replace(hour=0, minute=0, second=0, microsecond=0)
    if unit in ("h", "H"):
        return moment.replace(minute=0, second=0, microsecond=0)
    if unit == "m":
        return moment.replace(second=0, microsecond=0)
    return moment.replace(microsecond=0)


def _next_unit(moment: datetime, unit: str) -> datetime:
    """The start of the unit after the one *moment* (already rounded) begins."""
    if unit == "y":
        return _add_months(moment, 12)
    if unit == "M":
        return _add_months(moment, 1)
    if unit == "w":
        return moment + timedelta(days=7)
    return moment + timedelta(**{_SIMPLE_UNITS[unit]: 1})


def resolve(
    expression: str,
    *,
    now: datetime | None = None,
    round_up: bool = False,
    time_zone: str | None = None,
) -> datetime | None:
    """Resolve a date-math *expression* to an instant.

    Args:
        expression: ``now-30d``, ``now/d``, ``2026-01-01||+1M/M`` …
        now:        The instant ``now`` stands for; defaults to the real one.
        round_up:   With a ``/unit`` rounding, return the last millisecond the
                    unit covers instead of its first — what ``gt`` and ``lte``
                    need.
        time_zone:  Zone the rounding happens in; UTC when absent.

    Returns:
        The resolved instant, or ``None`` if *expression* is not date math at
        all.

    Raises:
        DateMathError: If it is date math but malformed — an unknown unit, a
            counted rounding, or an anchor that is not a date.
    """
    if not is_date_math(expression):
        return None

    zone = _zone(time_zone)

    if expression.startswith(_ANCHOR_NOW):
        anchor = (now or current_time()).astimezone(zone)
        rest = expression[len(_ANCHOR_NOW):]
    else:
        head, _, rest = expression.partition(_ANCHOR_SEP)
        parsed = parse_datetime(head)
        if parsed is None:
            raise DateMathError(f"failed to parse date field [{head}]")
        anchor = parsed.astimezone(zone)

    moment = anchor
    position = 0
    while position < len(rest):
        match = _OP_RE.match(rest, position)
        if not match:
            # Anything the grammar does not cover: refuse rather than guess at
            # a window the client did not ask for.
            # Name the offending unit the way Elasticsearch does:
            # "unit [q] not supported for date math [-30q]".
            loose = _LOOSE_OP_RE.match(rest, position)
            offender = loose.group(1) if loose else rest[position:]
            raise DateMathError(
                f"unit [{offender}] not supported for date math [{rest}]",
            )
        operator, count, unit = match.group(1), match.group(2), match.group(3)
        if operator == "/":
            if count:
                raise DateMathError(f"rounding is not supported with a count in [{rest}]")
            # Operations apply left to right, and a later offset shifts the
            # already-rounded instant: `now/d+2h` is 02:00 today for a lower
            # bound and 01:59:59.999 tomorrow for an upper one.
            moment = _round_down(moment, unit)
            if round_up:
                moment = _next_unit(moment, unit) - _MILLI
        else:
            moment = _apply_offset(moment, 1 if operator == "+" else -1, int(count or 1), unit)
        position = match.end()

    return moment.astimezone(UTC)


#: Which way each range operator rounds a ``/unit`` expression, per the
#: "Date math and rounding" table: the bound always moves so that the whole
#: rounded interval is either included or excluded.
ROUNDS_UP: dict[str, bool] = {"gt": True, "gte": False, "lt": False, "lte": True}
