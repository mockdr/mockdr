"""Refusing what Kibana refuses, in the words Kibana refuses it with.

mockdr accepted almost all of it silently. ``severity=nonsens`` came back as
``200`` with no cases, which a client reads as "there are none" rather than
as the typo it is; ``sortField=nope`` came back sorted by something else
entirely; a case was created with a severity outside the enum, and an
exception list with a type a real Kibana refuses.

Kibana speaks **four** validation dialects, and they differ in wording, in
precedence, and in the envelope they arrive in:

* **io-ts** on the Cases API — every value it could not accept in one
  message, joined with commas in the codec's field order, then the page cap,
  then Elasticsearch's own complaint about a negative window.
* **io-ts with a prefix** on the exception lists — the same shape behind
  ``[request query]`` or ``[request body]``, and paging that starts at 1.
* **zod** on the Detection Rules — its own wording, no page cap, unknown keys
  taken, and one rule the schema cannot express (a ``sort_field`` without its
  ``sort_order``) that the route raises afterwards.
* **@kbn/config-schema** on the Endpoint routes — the member named in the
  bracket, the *first* failure only, a key it has no definition for refused,
  and pages counted from 0.

What a route raises after its schema is satisfied comes back in a different
envelope again: ``{message, status_code}`` rather than Boom's
``{statusCode, error, message}``. Every message and every precedence here is
measured against Kibana 8.15.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Finding cases (io-ts)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Finding rules (zod)
# ---------------------------------------------------------------------------

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
# Creating a case (io-ts)
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


# ---------------------------------------------------------------------------
# Exception lists (io-ts, behind a prefix)
# ---------------------------------------------------------------------------

#: A third dialect: io-ts again, but every message carries the `[request
#: query]` or `[request body]` prefix the Cases API leaves off. The mock
#: answered these in FastAPI's words, or not at all.
_QUERY_PREFIX = "[request query]: "
_BODY_PREFIX = "[request body]: "

#: Where an exception list lives. Not a namespace Kibana knows is a value
#: error, not an empty result.
EXCEPTION_NAMESPACES: frozenset[str] = frozenset({"single", "agnostic"})

#: What an exception list can be. `nonsense` used to create one here.
EXCEPTION_TYPES: frozenset[str] = frozenset({
    "detection", "rule_default", "endpoint", "endpoint_trusted_apps",
    "endpoint_events", "endpoint_host_isolation_exceptions", "endpoint_blocklists",
})

#: The fields the saved object is indexed on, and so the ones it sorts by.
#: Anything else is refused with a message of its own, without the prefix.
EXCEPTION_SORT_FIELDS: frozenset[str] = frozenset({
    "name", "created_at", "updated_at", "description", "list_id", "type",
    "tie_breaker_id", "_score",
})

#: The order this codec reports its fields in.
_EXCEPTION_QUERY_ORDER: tuple[str, ...] = (
    "namespace_type", "page", "per_page", "sort_order",
)

#: What `/api/exception_lists/_find` takes.  Not `list_id`: that belongs to
#: `/api/exception_lists/items/_find`, which finds the items *of* a list, and
#: the list search refuses it outright — `invalid keys "list_id"`, measured
#: on 8.15.  mockdr accepted it and filtered by it, so a client narrowing the
#: list search by list_id got a narrowed answer here and a 400 in production.
_EXCEPTION_QUERY_KEYS: frozenset[str] = frozenset({
    "namespace_type", "page", "per_page", "filter", "sort_field",
    "sort_order",
})

_EXCEPTION_BODY_KEYS: frozenset[str] = frozenset({
    "name", "description", "list_id", "type", "namespace_type", "tags", "meta",
    "version", "os_types",
})

_EXCEPTION_BODY_REQUIRED: tuple[str, ...] = ("description", "name", "type")


class ExceptionListError(ValueError):
    """Raised when an exception-list request is not one Kibana would run.

    ``route_error`` marks what the route raises after the codec is satisfied.
    Those come back in the Security Solution's own ``{message, status_code}``
    envelope rather than Boom's, and carry no prefix.
    """

    def __init__(self, message: str, *, route_error: bool = False) -> None:
        """Record the message and which envelope carries it."""
        super().__init__(message)
        self.route_error = route_error


def _positive_integer(value: str) -> bool:
    """Whether this is a whole number of at least one.

    `page` and `per_page` both start at 1 here — a `per_page` of 0 is a value
    error, where the Cases API takes it and returns an empty page.
    """
    try:
        return float(value) >= 1 and float(value).is_integer()
    except (TypeError, ValueError):
        return False


def validate_exception_find_query(params: Mapping[str, str]) -> None:
    """Refuse an exception-list ``_find`` query the way Kibana refuses it.

    Raises:
        ExceptionListError: Carrying Kibana's own message.
    """
    problems: list[str] = []
    for field in _EXCEPTION_QUERY_ORDER:
        value = params.get(field)
        if value is None:
            continue
        if field == "namespace_type" and value not in EXCEPTION_NAMESPACES:
            problems.append(_invalid(field, value))
        elif field == "sort_order" and value not in SORT_ORDERS:
            problems.append(_invalid(field, value))
        elif field in ("page", "per_page") and not _positive_integer(value):
            problems.append(_invalid(field, value))
    if problems:
        raise ExceptionListError(_QUERY_PREFIX + ",".join(problems))

    unknown = [key for key in params if key not in _EXCEPTION_QUERY_KEYS]
    if unknown:
        raise ExceptionListError(f'{_QUERY_PREFIX}invalid keys "{",".join(unknown)}"')

    sort_field = params.get("sort_field")
    if sort_field and sort_field not in EXCEPTION_SORT_FIELDS:
        # Raised by the search itself, after the codec is satisfied, so it
        # carries no prefix.
        raise ExceptionListError(f"Unknown sort field {sort_field}", route_error=True)


def validate_exception_list_body(body: Mapping[str, object]) -> None:
    """Refuse an exception-list body the way Kibana refuses it.

    Raises:
        ExceptionListError: Carrying Kibana's own message.
    """
    problems: list[str] = []
    for field in _EXCEPTION_BODY_REQUIRED:
        if field not in body:
            problems.append(f'Invalid value "undefined" supplied to "{field}"')
    for field, allowed in (("type", EXCEPTION_TYPES),
                           ("namespace_type", EXCEPTION_NAMESPACES)):
        value = body.get(field)
        if value is not None and value not in allowed:
            problems.append(_invalid(field, str(value)))
    for field in ("name", "description", "list_id"):
        value = body.get(field)
        if value is not None and not isinstance(value, str):
            problems.append(_invalid(field, str(value)))
    if problems:
        raise ExceptionListError(_BODY_PREFIX + ",".join(problems))

    unknown = [key for key in body if key not in _EXCEPTION_BODY_KEYS]
    if unknown:
        raise ExceptionListError(f'{_BODY_PREFIX}invalid keys "{",".join(unknown)}"')


# ---------------------------------------------------------------------------
# Endpoint routes (@kbn/config-schema)
# ---------------------------------------------------------------------------

#: A fourth dialect. The Endpoint routes validate with @kbn/config-schema,
#: which names the member in the bracket — `[request query.pageSize]` — stops
#: at the *first* failure, and refuses a key it has no definition for.
_SCHEMA_TYPE_NAMES: dict[type, str] = {
    str: "string", int: "number", float: "number", bool: "boolean",
    list: "array", dict: "object", type(None): "null",
}


class SchemaField(NamedTuple):
    """One member of a config-schema, and what it will take.

    Attributes:
        name:      The member's name.
        kind:      ``number``, ``string``, ``array`` or ``boolean``.
        required:  Whether its absence is a failure.
        minimum:   Lowest number it takes, if it is one.
        maximum:   Highest number it takes.
        min_items: Fewest members an array may have.
        one_of:    The values it will equal, if it is a union of literals.
    """

    name: str
    kind: str = "string"
    required: bool = False
    minimum: float | None = None
    maximum: float | None = None
    min_items: int | None = None
    one_of: tuple[str, ...] = ()


class ConfigSchemaError(ValueError):
    """Raised when a request does not satisfy a config-schema."""


#: `GET /api/endpoint/metadata`. `page` counts from 0 here, unlike every
#: other paged endpoint in this file.
ENDPOINT_METADATA_QUERY: tuple[SchemaField, ...] = (
    SchemaField("page", "number", minimum=0),
    SchemaField("pageSize", "number", minimum=1, maximum=10000),
    SchemaField("kuery"),
    SchemaField("hostStatuses", "array"),
    SchemaField("sortField", one_of=(
        "enrolled_at", "metadata.host.hostname", "host_status",
        "metadata.Endpoint.policy.applied.name",
        "metadata.Endpoint.policy.applied.status", "metadata.host.os.name",
        "metadata.host.ip", "metadata.agent.version", "last_checkin",
    )),
    SchemaField("sortDirection", one_of=("asc", "desc")),
)

#: The body every response action takes.
ENDPOINT_ACTION_BODY: tuple[SchemaField, ...] = (
    SchemaField("endpoint_ids", "array", required=True, min_items=1),
    SchemaField("alert_ids", "array"),
    SchemaField("case_ids", "array"),
    SchemaField("comment"),
    SchemaField("parameters", "object"),
    SchemaField("agent_type", one_of=("endpoint", "sentinel_one", "crowdstrike")),
)

#: `GET /api/endpoint/action_status`.
ENDPOINT_ACTION_STATUS_QUERY: tuple[SchemaField, ...] = (
    SchemaField("agent_ids", "array", required=True),
)


def _union_failure(where: str, name: str, allowed: tuple[str, ...]) -> str:
    """config-schema's message for a value outside a union of literals."""
    lines = "\n".join(
        f"- [{where}.{name}.{index}]: expected value to equal [{option}]"
        for index, option in enumerate(allowed)
    )
    return f"[{where}.{name}]: types that failed validation:\n{lines}"


def validate_config_schema(
    values: Mapping[str, object], fields: tuple[SchemaField, ...], *, where: str,
    from_query: bool = False,
    undeclared: bool = True,
) -> None:
    """Refuse a request the way ``@kbn/config-schema`` refuses it.

    It stops at the first failure and names the member in the bracket, which
    is what a client parsing the message keys on.

    Args:
        values:     The query or body, as sent.
        fields:     The schema, in declaration order.
        where:      ``request query`` or ``request body``.
        from_query: Whether every value arrived as a string, as it does in a
                    query string — a number is then whatever parses as one.
        undeclared: Whether to refuse a member the schema does not declare.
                    The response actions check their own `parameters` block
                    between the declared members and this, so they ask for
                    the two halves in turn.

    Raises:
        ConfigSchemaError: Carrying Kibana's own message.
    """
    for field in fields:
        if field.name not in values:
            if field.required:
                missing = (
                    "expected at least one defined value but got [undefined]"
                    if from_query and field.kind == "array"
                    else f"expected value of type [{field.kind}] but got [undefined]"
                )
                raise ConfigSchemaError(f"[{where}.{field.name}]: {missing}")
            continue
        _check_field(values[field.name], field, where=where, from_query=from_query)

    if not undeclared:
        return
    declared = {field.name for field in fields}
    for key in values:
        if key not in declared:
            raise ConfigSchemaError(
                f"[{where}.{key}]: definition for this key is missing",
            )


def _check_field(
    value: object, field: SchemaField, *, where: str, from_query: bool,
) -> None:
    """Check one member, raising the first thing wrong with it."""
    label = f"[{where}.{field.name}]"
    if field.one_of:
        if value not in field.one_of:
            raise ConfigSchemaError(_union_failure(where, field.name, field.one_of))
        return
    if field.kind == "number":
        number = _as_number(str(value), None) if from_query else _numeric(value)
        if number is None:
            raise ConfigSchemaError(
                f"{label}: expected value of type [number] but got "
                f"[{_SCHEMA_TYPE_NAMES.get(type(value), 'string')}]",
            )
        if field.minimum is not None and number < field.minimum:
            raise ConfigSchemaError(
                f"{label}: Value must be equal to or greater than [{int(field.minimum)}].",
            )
        if field.maximum is not None and number > field.maximum:
            raise ConfigSchemaError(
                f"{label}: Value must be equal to or lower than [{int(field.maximum)}].",
            )
        return
    if field.kind == "array":
        if not isinstance(value, list):
            raise ConfigSchemaError(
                f"{label}: could not parse array value from json input",
            )
        if field.min_items is not None and len(value) < field.min_items:
            raise ConfigSchemaError(
                f"{label}: array size is [{len(value)}], but cannot be smaller "
                f"than [{field.min_items}]",
            )
        return
    expected = {"string": str, "boolean": bool, "object": dict}[field.kind]
    if not isinstance(value, expected) or (field.kind != "boolean" and isinstance(value, bool)):
        raise ConfigSchemaError(
            f"{label}: expected value of type [{field.kind}] but got "
            f"[{_SCHEMA_TYPE_NAMES.get(type(value), 'string')}]",
        )


def _numeric(value: object) -> float | None:
    """A JSON number, or ``None`` for anything else."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


# ---------------------------------------------------------------------------
# Exception items
# ---------------------------------------------------------------------------

#: What an exception *item* can be. The list's own vocabulary does not apply.
EXCEPTION_ITEM_TYPES: frozenset[str] = frozenset({"simple"})

#: The members an item body may carry. Kibana refuses any other by name.
_ITEM_BODY_KEYS: frozenset[str] = frozenset({
    "list_id", "item_id", "id", "name", "description", "type", "entries",
    "namespace_type", "tags", "meta", "comments", "os_types", "expire_time",
    "_version",
})

#: Reported in this order when they are missing, which is the order the codec
#: declares them in.
_ITEM_REQUIRED_CREATE: tuple[str, ...] = (
    "description", "entries", "list_id", "name", "type",
)
_ITEM_REQUIRED_UPDATE: tuple[str, ...] = ("description", "entries", "name", "type")

_ENTRY_OPERATORS: frozenset[str] = frozenset({"included", "excluded"})

#: The union an entry is checked against, branch by branch. io-ts reports
#: every branch it tried, so one malformed entry produces a message per
#: member each branch could not satisfy — including the `list` and `entries`
#: members of the two branches this one was never going to be.
_ENTRY_BRANCHES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("match", ("field", "operator", "type", "value")),
    ("match_any", ("field", "operator", "type", "value")),
    ("list", ("field", "operator", "type", "list")),
    ("nested", ("field", "type", "entries")),
)


def _entry_member_ok(entry: Mapping[str, object], branch: str, member: str) -> bool:
    """Whether one member of an entry satisfies one branch of the union."""
    value = entry.get(member, _MISSING)
    if value is _MISSING:
        return False
    if member == "field":
        return isinstance(value, str)
    if member == "operator":
        return value in _ENTRY_OPERATORS
    if member == "type":
        return value == branch
    if member == "list":
        return isinstance(value, dict)
    if member == "entries":
        return isinstance(value, list)
    # `value` — a string for `match`, a list of them for `match_any`.
    return isinstance(value, list) if branch == "match_any" else isinstance(value, str)


_MISSING = object()


def _entry_problems(entry: Mapping[str, object]) -> list[str]:
    """Every message one entry produces, in the order Kibana reports them.

    A union is satisfied by any one of its branches, so an entry that matches
    one produces nothing at all. Only when every branch failed does io-ts
    report them — each distinct failure once, however many branches ran into
    it.
    """
    problems: list[str] = []
    for branch, members in _ENTRY_BRANCHES:
        failures = [member for member in members
                    if not _entry_member_ok(entry, branch, member)]
        if not failures:
            return []
        for member in failures:
            supplied = entry.get(member, _MISSING)
            shown = "undefined" if supplied is _MISSING else _shown(supplied)
            message = f'Invalid value "{shown}" supplied to "entries,{member}"'
            if message not in problems:
                problems.append(message)
    return problems


def _shown(value: object) -> str:
    """How a supplied value appears inside an io-ts message."""
    return value if isinstance(value, str) else str(value)


def validate_exception_item_body(
    body: Mapping[str, object], *, update: bool = False,
) -> None:
    """Refuse an exception-item body the way Kibana refuses it.

    Nothing was refused here at all: an empty body created an item, and so
    did one naming a list that does not exist. An item with no `entries`
    matches nothing, and a client that had just been told it created one had
    no way to find that out.

    Raises:
        ExceptionListError: Carrying Kibana's own message.
    """
    problems: list[str] = []
    required = _ITEM_REQUIRED_UPDATE if update else _ITEM_REQUIRED_CREATE
    for field in required:
        if field not in body:
            problems.append(f'Invalid value "undefined" supplied to "{field}"')
    entries = body.get("entries")
    if entries is not None and not isinstance(entries, list):
        problems.append(f'Invalid value "{_shown(entries)}" supplied to "entries"')
    for field, allowed in (("type", EXCEPTION_ITEM_TYPES),
                           ("namespace_type", EXCEPTION_NAMESPACES)):
        value = body.get(field)
        if value is not None and value not in allowed:
            problems.append(_invalid(field, str(value)))
    if isinstance(entries, list):
        for entry in entries:
            problems.extend(
                _entry_problems(entry) if isinstance(entry, Mapping)
                else [f'Invalid value "{_shown(entry)}" supplied to "entries"'],
            )
    if problems:
        raise ExceptionListError(_BODY_PREFIX + ",".join(problems))

    unknown = [key for key in body if key not in _ITEM_BODY_KEYS]
    if unknown:
        raise ExceptionListError(f'{_BODY_PREFIX}invalid keys "{",".join(unknown)}"')
