"""Refusing what Kibana refuses, in the words Kibana refuses it with.

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


#: The Detection Rules API validates with zod rather than io-ts, so it words
#: everything differently and reports its fields in this order.
_RULE_FIELD_ORDER: tuple[str, ...] = ("sort_field", "sort_order", "page", "per_page")

#: What that endpoint will sort by. Both spellings of several fields are
#: allowed, which is a hint at how long it has been carrying them.
RULE_SORT_FIELDS: tuple[str, ...] = (
    "created_at", "createdAt", "enabled",
    "execution_summary.last_execution.date",
    "execution_summary.last_execution.metrics.execution_gap_duration_s",
    "execution_summary.last_execution.metrics.total_indexing_duration_ms",
    "execution_summary.last_execution.metrics.total_search_duration_ms",
    "execution_summary.last_execution.status",
    "name", "risk_score", "riskScore", "severity", "updated_at", "updatedAt",
)

RULE_SORT_ORDERS: tuple[str, ...] = ("asc", "desc")

#: The lower bound each numeric parameter has there.
_RULE_MINIMUMS: dict[str, int] = {"page": 1, "per_page": 0}

#: The message the route raises after the schema has passed, when only one of
#: the sort pair was given. It travels in an envelope of its own.
SORT_PAIR_MESSAGE = 'when "sort_order" and "sort_field" must exist together or not at all'


class RulesQueryError(ValueError):
    """Raised when a rules ``_find`` query is not one Kibana would run.

    ``sort_pair`` marks the one failure that arrives in a different envelope:
    the schema's errors come back as Kibana's usual ``statusCode``/``error``
    object, while this one is ``{"message": [...], "status_code": 400}``.
    """

    def __init__(self, message: str, *, sort_pair: bool = False) -> None:
        """Record the message and which envelope carries it."""
        super().__init__(message)
        self.sort_pair = sort_pair


def _enum_problem(field: str, value: str, allowed: tuple[str, ...]) -> str:
    """Zod's wording for a value outside an enum, listing what it takes."""
    expected = " | ".join(f"'{option}'" for option in allowed)
    return f"{field}: Invalid enum value. Expected {expected}, received '{value}'"


def validate_rules_find_query(params: Mapping[str, str]) -> None:
    """Refuse a rules ``_find`` query the way the Detection Rules API does.

    ``sort_order=sideways`` and a lone ``sort_field`` both came back as 200
    here: the first sorted the other way round without saying so, the second
    is a pairing Kibana refuses outright.

    Raises:
        RulesQueryError: Carrying Kibana's own message.
    """
    problems: list[str] = []
    for field in _RULE_FIELD_ORDER:
        value = params.get(field)
        if value is None:
            continue
        if field == "sort_field" and value not in RULE_SORT_FIELDS:
            problems.append(_enum_problem(field, value, RULE_SORT_FIELDS))
        elif field == "sort_order" and value not in RULE_SORT_ORDERS:
            problems.append(_enum_problem(field, value, RULE_SORT_ORDERS))
        elif field in _RULE_MINIMUMS:
            number = _as_number(value, None)
            if number is None:
                problems.append(f"{field}: Expected number, received nan")
            elif number < _RULE_MINIMUMS[field]:
                problems.append(
                    f"{field}: Number must be greater than or equal to "
                    f"{_RULE_MINIMUMS[field]}",
                )
    if problems:
        raise RulesQueryError("[request query]: " + ", ".join(problems))

    # Checked by the route itself, once the schema is satisfied.
    if bool(params.get("sort_field")) != bool(params.get("sort_order")):
        raise RulesQueryError(SORT_PAIR_MESSAGE, sort_pair=True)


# ---------------------------------------------------------------------------
# Creating a case
# ---------------------------------------------------------------------------

#: The order the case codec reports its fields in — the six required ones
#: first, then the optional ones. Measured by sending an empty body.
_CASE_FIELD_ORDER: tuple[str, ...] = (
    "description", "tags", "title", "connector", "settings", "owner",
    "severity", "assignees", "category", "customFields",
)

_CASE_REQUIRED: frozenset[str] = frozenset({
    "description", "tags", "title", "connector", "settings", "owner",
})

#: What each member has to be. `status` is deliberately absent: a case is
#: created open, and asking for another one is an `invalid keys` error rather
#: than a state to honour.
_CASE_TYPES: dict[str, type | tuple[type, ...]] = {
    "description": str, "tags": list, "title": str, "connector": dict,
    "settings": dict, "owner": str, "severity": str, "assignees": list,
    "category": (str, type(None)), "customFields": list,
}

#: The plugins that own cases. An owner outside them is a 403, not a 400:
#: Kibana reads it as a case you may not create rather than as a bad value.
CASE_OWNERS: frozenset[str] = frozenset({"securitySolution", "cases", "observability"})


class CaseBodyError(ValueError):
    """Raised when a case body is not one Kibana would accept.

    ``forbidden`` marks the owner check, which answers 403 where every other
    failure here answers 400.
    """

    def __init__(self, message: str, *, forbidden: bool = False) -> None:
        """Record the message and which status carries it."""
        super().__init__(message)
        self.forbidden = forbidden


def validate_case_body(body: Mapping[str, object]) -> None:
    """Refuse a case body the way the Cases API refuses it.

    mockdr took a case with a severity outside the enum, a title that was a
    number, and a `status` no client may set at creation — all with 200, so
    the case existed and nobody learned of the typo.

    Raises:
        CaseBodyError: Carrying Kibana's own message.
    """
    problems: list[str] = []
    for field in _CASE_FIELD_ORDER:
        if field not in body:
            if field in _CASE_REQUIRED:
                problems.append(f'Invalid value "undefined" supplied to "{field}"')
            continue
        value = body[field]
        expected = _CASE_TYPES[field]
        if isinstance(value, bool) or not isinstance(value, expected):
            problems.append(_invalid(field, str(value)))
        elif field == "severity" and value not in SEVERITIES:
            problems.append(_invalid(field, str(value)))
    if problems:
        raise CaseBodyError(",".join(problems))

    unknown = [key for key in body if key not in _CASE_TYPES]
    if unknown:
        raise CaseBodyError(f'invalid keys "{",".join(unknown)}"')

    owner = body.get("owner")
    if owner not in CASE_OWNERS:
        raise CaseBodyError(
            f'Unauthorized to create case with owners: "{owner}"', forbidden=True,
        )
