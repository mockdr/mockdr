"""Read-side handlers for Microsoft Graph Security API."""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from application.mde_advanced_hunting.queries import run_query as run_hunt
from repository.graph.secure_score_repo import graph_secure_score_repo
from repository.graph.security_alert_repo import graph_security_alert_repo
from repository.graph.security_incident_repo import graph_security_incident_repo
from utils.dt import parse_utc
from utils.graph_odata import (
    apply_graph_filter,
    apply_odata_orderby,
    apply_odata_select,
)
from utils.graph_response import build_graph_list_response
from utils.odata_paging import page_link
from utils.serde import record_dict
from utils.vendor_enums import graph_enum_order

# ── Alerts v2 ─────────────────────────────────────────────────────────────────

def list_alerts_v2(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
    orderby: str | None = None,
    select: str | None = None,
    count: bool = False,
) -> dict:
    """Return security alerts v2 with OData query support.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).
        orderby:    OData ``$orderby`` expression.
        select:     OData ``$select`` expression.
        count:      ``$count=true``: report the filtered total.

    Returns:
        OData list response dict.
    """
    records = [record_dict(a) for a in graph_security_alert_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)
    # `$orderby` and `$select` were taken and dropped: a client that asked for
    # newest-first got insertion order, and one that asked for two fields got
    # the whole alert — believing both times that the query had been applied.
    records = apply_odata_orderby(records, orderby, graph_enum_order())

    total = len(records)
    page = apply_odata_select(records[skip : skip + top], select)
    next_link = page_link(
        skip + top, total,
        fallback="https://graph.microsoft.com/v1.0/security/alerts_v2",
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#security/alerts_v2",
        next_link=next_link,
        count=total if count else None,
    )


def get_alert_v2(alert_id: str) -> dict | None:
    """Return a single security alert v2 by ID.

    Args:
        alert_id: The alert's ``id``.

    Returns:
        Alert dict or ``None`` if not found.
    """
    alert = graph_security_alert_repo.get(alert_id)
    if alert is None:
        return None
    return record_dict(alert)


#: What a PATCH may set. Status is the update page's list -- `unknown` is a
#: value an alert can carry but not one the page lets a caller set. For
#: classification and determination the page and the v1.0 metadata disagree
#: on four determination names (`compromisedUser`/`compromisedAccount`,
#: `clean`/`notMalicious`, `insufficientData`/`notEnoughDataToValidate`,
#: `confirmedUserActivity`/`confirmedActivity`); both spellings are taken.
#: https://learn.microsoft.com/en-us/graph/api/security-alert-update?view=graph-rest-1.0
_ALERT_STATUS = frozenset({"new", "inProgress", "resolved", "unknownFutureValue"})
_ALERT_UPDATE_DETERMINATIONS = frozenset({
    "unknown", "apt", "malware", "securityPersonnel", "securityTesting", "unwantedSoftware",
    "other", "multiStagedAttack", "compromisedUser", "phishing", "maliciousUserActivity",
    "clean", "insufficientData", "confirmedUserActivity", "lineOfBusinessApplication",
    "unknownFutureValue",
})


class InvalidAlertUpdateError(ValueError):
    """A PATCH value outside the enum the update page documents."""


def _check_alert_update(body: dict) -> None:
    """Refuse a value the alerts_v2 update page does not list.

    The mock stored any string, so ``"status": "Resolved"`` -- Defender's
    PascalCase, which Graph's lowerCamel enum does not contain -- was saved
    and served back to every later read.

    Raises:
        InvalidAlertUpdateError: The field and the value refused.
    """
    enums = graph_enum_order()
    allowed = {
        "status": _ALERT_STATUS,
        "classification": frozenset(enums.get("classification") or ()),
        "determination": _ALERT_UPDATE_DETERMINATIONS | frozenset(enums.get("determination") or ()),
    }
    for field, members in allowed.items():
        if members and field in body and body[field] is not None and body[field] not in members:
            msg = f"Invalid value '{body[field]}' for property '{field}'."
            raise InvalidAlertUpdateError(msg)


def update_alert_v2(alert_id: str, body: dict) -> dict | None:
    """Update a security alert v2 (status, assignedTo, classification, determination).

    Args:
        alert_id: The alert's ``id``.
        body:     Dict of fields to update.

    Returns:
        Updated alert dict or ``None`` if not found.

    Raises:
        InvalidAlertUpdateError: A value the update page does not list.
    """
    _check_alert_update(body)
    alert = graph_security_alert_repo.get(alert_id)
    if alert is None:
        return None

    updatable_fields = {"status", "assignedTo", "classification", "determination"}
    for field_name in updatable_fields:
        if field_name in body:
            setattr(alert, field_name, body[field_name])

    graph_security_alert_repo.save(alert)
    return record_dict(alert)


# ── Incidents ─────────────────────────────────────────────────────────────────

def list_incidents(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
    orderby: str | None = None,
    select: str | None = None,
    expand: str | None = None,
    count: bool = False,
) -> dict:
    """Return security incidents with OData query support.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).
        orderby:    OData ``$orderby`` expression.
        select:     OData ``$select`` expression.
        expand:     OData ``$expand`` expression (supports ``alerts``).
        count:      ``$count=true``: report the filtered total.

    Returns:
        OData list response dict.
    """
    records = [record_dict(inc) for inc in graph_security_incident_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)

    # Expand alerts if requested
    for rec in records:
        if expand and "alerts" in expand:
            rec["alerts"] = _expand_alerts(rec.get("alert_ids", []))
        rec.pop("alert_ids", None)

    records = apply_odata_orderby(records, orderby, graph_enum_order())
    total = len(records)
    page = apply_odata_select(records[skip : skip + top], select)
    next_link = page_link(
        skip + top, total,
        fallback="https://graph.microsoft.com/v1.0/security/incidents",
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#security/incidents",
        next_link=next_link,
        count=total if count else None,
    )


def get_incident(
    incident_id: str,
    expand: str | None = None,
) -> dict | None:
    """Return a single security incident by ID.

    Args:
        incident_id: The incident's ``id``.
        expand:      OData ``$expand`` expression (supports ``alerts``).

    Returns:
        Incident dict or ``None`` if not found.
    """
    incident = graph_security_incident_repo.get(incident_id)
    if incident is None:
        return None

    result = record_dict(incident)
    if expand and "alerts" in expand:
        result["alerts"] = _expand_alerts(result.get("alert_ids", []))
    result.pop("alert_ids", None)

    return result


def _expand_alerts(alert_ids: list[str]) -> list[dict]:
    """Resolve alert IDs to full alert dicts for $expand=alerts."""
    alerts: list[dict] = []
    for aid in alert_ids:
        alert = graph_security_alert_repo.get(aid)
        if alert:
            alerts.append(record_dict(alert))
    return alerts


# ── Advanced Hunting ──────────────────────────────────────────────────────────

class InvalidTimespanError(ValueError):
    """A ``Timespan`` that is none of the ISO 8601 forms Graph documents."""


_DURATION = re.compile(
    r"^P(?:(?P<w>\d+)W)?(?:(?P<d>\d+)D)?"
    r"(?:T(?:(?P<h>\d+)H)?(?:(?P<m>\d+)M)?(?:(?P<s>\d+(?:\.\d+)?)S)?)?$",
)


def _duration(text: str) -> timedelta | None:
    """An ISO 8601 duration in weeks, days, hours, minutes and seconds."""
    match = _DURATION.match(text.strip().upper())
    if not match or text.strip().upper() in ("P", "PT"):
        return None
    parts = {k: float(v) for k, v in match.groupdict().items() if v}
    return timedelta(weeks=parts.get("w", 0), days=parts.get("d", 0), hours=parts.get("h", 0),
                     minutes=parts.get("m", 0), seconds=parts.get("s", 0))


def hunting_window(timespan: str | None, now: datetime | None = None) -> tuple[datetime, datetime]:
    """The ``(start, end)`` a runHuntingQuery ``Timespan`` selects.

    "The default value is 30 days, meaning if no startTime is specified, the
    query looks back 30 days from now", and the documented forms are
    Date/Date, Duration/endDate, Start/duration, a bare duration (back from
    now) and a single date (from then to now)
    (https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0).

    Raises:
        InvalidTimespanError: For anything else.
    """
    now = now or datetime.now(UTC)
    if timespan is None or not str(timespan).strip():
        return now - timedelta(days=30), now
    text = str(timespan).strip()
    if "/" in text:
        left, _, right = text.partition("/")
        start, end = parse_utc(left.strip()), parse_utc(right.strip())
        if start and end:
            return start, end
        if end and (back := _duration(left)) is not None:
            return end - back, end
        if start and (ahead := _duration(right)) is not None:
            return start, start + ahead
    elif (back := _duration(text)) is not None:
        return now - back, now
    elif (start := parse_utc(text.strip())) is not None:
        return start, now
    msg = f"Timespan '{text}' is not a valid ISO 8601 interval, duration or date."
    raise InvalidTimespanError(msg)


def _action_parameters(body: dict) -> dict:
    """An OData action body keyed by lower-cased parameter name.

    The reference page writes the parameters ``Query`` and ``Timespan``; the
    CSDL declares them ``query`` and ``timespan``, and the official SDKs,
    generated from it, send exactly that (msgraph-sdk-python's
    ``RunHuntingQueryPostRequestBody.serialize`` writes ``"query"`` and
    ``"timespan"``). Graph binds action parameters without regard to case, so
    both spellings run. Reading only ``Query`` answered every SDK hunt with
    ``400 A recognized query is expected``.
    """
    return {str(k).lower(): v for k, v in body.items()}


def run_hunting_query(body: dict) -> dict:
    """Execute a hunting query against the seeded hunting tables.

    Graph's advanced hunting is Defender's, and this mount had the
    implementation Defender's own route was given up: the query accepted and
    never evaluated, three synthetic rows returned whatever was asked, and
    device ids in them that this install does not have — so a hunter who
    followed a result to `managedDevices/{id}` got a 404 for a device the
    hunt had just reported. It runs the same evaluator over the same tables
    now.

    The rows are Defender's; the envelope is Graph's. Graph answers a
    ``microsoft.graph.security.huntingQueryResults`` — ``schema`` of
    ``{name, type}`` and ``results``, camelCase, with no ``Stats`` — and
    this route used to hand back Defender's ``Schema``/``Results`` verbatim,
    which a Graph SDK deserialises as an empty result.

    ``Timespan`` was read by nothing, so every hunt saw every seeded row. It
    now selects the window the docs describe, 30 days back from now when
    absent, applied to tables with a ``Timestamp`` column before the query
    runs -- so a time filter inside the query narrows further and "the
    shorter time span is applied", as documented. The seeders spread
    DeviceNetworkEvents up to 31 days back, so the default hides the couple of
    rows past 30 days on a fresh install (and more as an instance ages), the
    way Defender's retention would.

    Args:
        body: Request body containing ``Query`` (a KQL string) and optionally
              ``Timespan``.

    Returns:
        A ``huntingQueryResults`` with ``@odata.context``, ``schema`` and
        ``results``.

    Raises:
        KqlError: If the query cannot be parsed or names an unknown table.
        InvalidTimespanError: If ``Timespan`` is not a documented form.
    """
    params = _action_parameters(body)
    hunt = run_hunt(
        {"Query": params.get("query", "")},
        window=hunting_window(params.get("timespan")),
    )
    return {
        "@odata.context": (
            "https://graph.microsoft.com/v1.0/$metadata"
            "#microsoft.graph.security.huntingQueryResults"
        ),
        "schema": [{"name": c["Name"], "type": c["Type"]} for c in hunt["Schema"]],
        "results": hunt["Results"],
    }



# ── Secure Scores ─────────────────────────────────────────────────────────────

def list_secure_scores(
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return secure score snapshots with pagination.

    Args:
        top:  Page size (``$top``).
        skip: Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = [record_dict(s) for s in graph_secure_score_repo.list_all()]

    total = len(records)
    page = records[skip : skip + top]
    next_link = page_link(
        skip + top, total,
        fallback="https://graph.microsoft.com/v1.0/security/secureScores",
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#security/secureScores",
        next_link=next_link,
    )
