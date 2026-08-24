"""Validating a Kibana ``_find`` query the way Kibana validates it.

Kibana runs the query string through an io-ts codec before it looks at any
data, and reports *every* value it could not accept in one message, joined
with commas in the codec's own field order. Two more checks follow: a
``perPage`` above the cap, and — only once nothing else has fired — the
Elasticsearch-level complaint about a negative ``from`` or ``size``.

mockdr accepted almost all of it silently. ``severity=nonsens`` came back as
``200`` with no cases, which a client reads as "there are none" rather than
as the typo it is; ``sortField=nope`` came back sorted by something else
entirely. Every message and every precedence below is measured against
Kibana 8.15.
"""
from __future__ import annotations

from collections.abc import Mapping

#: Kibana's cap, and the message it refuses a larger page with.
MAX_PER_PAGE = 100

#: The fields a case list may be sorted by. `owner`, `totalComment` and `id`
#: are refused there, though they are perfectly good case fields.
SORT_FIELDS: frozenset[str] = frozenset({
    "createdAt", "updatedAt", "closedAt", "title", "status", "severity", "category",
})

STATUSES: frozenset[str] = frozenset({"open", "in-progress", "closed"})
SEVERITIES: frozenset[str] = frozenset({"low", "medium", "high", "critical"})
SORT_ORDERS: frozenset[str] = frozenset({"asc", "desc"})

#: Every query key the endpoint takes. Anything else is `invalid keys`.
KNOWN_KEYS: frozenset[str] = frozenset({
    "assignees", "category", "defaultSearchOperator", "from", "to", "owner",
    "reporters", "search", "searchFields", "severity", "sortField", "sortOrder",
    "status", "tags", "page", "perPage", "customFields",
})

#: The order Kibana reports value errors in — its codec's declaration order,
#: measured by sending every one of them at once.
_VALUE_ORDER: tuple[str, ...] = (
    "customFields", "status", "severity", "defaultSearchOperator", "searchFields",
    "sortField", "sortOrder", "page", "perPage",
)

#: Which values each of those accepts. `customFields`, `searchFields` and
#: `defaultSearchOperator` take shapes this mock does not model, so any scalar
#: is refused — which is what Kibana does with the scalar a client sends.
_ENUMS: dict[str, frozenset[str]] = {
    "status": STATUSES,
    "severity": SEVERITIES,
    "sortField": SORT_FIELDS,
    "sortOrder": SORT_ORDERS,
    "defaultSearchOperator": frozenset({"AND", "OR"}),
}

_NUMERIC = ("page", "perPage")


class FindQueryError(ValueError):
    """Raised when a ``_find`` query is not one Kibana would run."""


def _invalid(field: str, value: str) -> str:
    """Kibana's io-ts wording for a value outside a codec."""
    return f'Invalid value "{value}" supplied to "{field}"'


def validate_find_query(params: Mapping[str, str]) -> None:
    """Refuse a query Kibana would refuse, with the message it would send.

    Args:
        params: The raw query string, as sent.

    Raises:
        FindQueryError: Carrying Kibana's own message.
    """
    problems: list[str] = []
    for field in _VALUE_ORDER:
        value = params.get(field)
        if value is None:
            continue
        allowed = _ENUMS.get(field)
        if allowed is not None:
            if value not in allowed:
                problems.append(_invalid(field, value))
        elif field in _NUMERIC:
            if not _is_number(value):
                problems.append(f"{_invalid(field, value)},cannot parse to a number")
        else:
            # A field whose value is an object in the codec; a scalar never
            # satisfies it.
            problems.append(_invalid(field, value))

    per_page = _as_number(params.get("perPage"), 20)
    if per_page is not None and per_page > MAX_PER_PAGE:
        problems.append(
            f"The provided perPage value is too high. "
            f"The maximum allowed perPage value is {MAX_PER_PAGE}.",
        )
    if problems:
        raise FindQueryError(",".join(problems))

    unknown = [key for key in params if key not in KNOWN_KEYS]
    if unknown:
        # Kibana names them all, comma-separated, in the order they arrived.
        raise FindQueryError(f'invalid keys "{",".join(unknown)}"')

    # Only once nothing above has fired does the query reach Elasticsearch,
    # which is where a negative window is caught.
    page = _as_number(params.get("page"), 1)
    size = per_page if per_page is not None else 20
    if size < 0:
        raise FindQueryError(
            _shard_failure(f"[size] parameter cannot be negative, found [{int(size)}]"),
        )
    if page is not None and page < 1:
        offset = int((page - 1) * size)
        raise FindQueryError(
            _shard_failure(f"[from] parameter cannot be negative but was [{offset}]"),
        )


def _shard_failure(reason: str) -> str:
    """The message Kibana relays when Elasticsearch refuses the window.

    It carries the exception type and then repeats itself under "Root
    causes", which is the shape a client's log ends up with.
    """
    return (
        f"{reason}: illegal_argument_exception\n\tRoot causes:\n"
        f"\t\tillegal_argument_exception: {reason}"
    )


def _is_number(value: str) -> bool:
    """Whether Kibana's numeric codec would take this."""
    return _as_number(value, None) is not None


def _as_number(value: str | None, default: float | None) -> float | None:
    """Read a numeric parameter, or the default when it is absent."""
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
