"""Kibana's alerting and actions APIs, and the identity behind them.

Every one of these was a 404 here and an answer on a running Kibana 8.15:
the alerting framework's health and rule catalogue, the connectors an
alerting rule can act through, the value lists an exception list points at,
and the three calls a client makes to find out *who* and *what* it is
talking to — ``/internal/security/me``, ``/api/licensing/info`` and the task
manager's health.

The rule-type catalogue is captured from a running instance rather than
written out here: a client reads deep into it — action groups, authorized
consumers, the alerts-as-data mapping — and a hand-written subset would be
missing whole subtrees. The nine ``siem.*`` types and the three stack ones a
security deployment shows are kept; the observability and APM types are not,
because mockdr does not model those products. The mapping block each rule
type carries repeats across them, so the fixture stores each distinct one
once and the loader puts it back.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query

from api.es_auth import require_es_auth
from config import APP_VERSION
from utils.kibana_query import refuses_unknown

router = APIRouter(tags=["Kibana Alerting"])

_FIXTURES = Path(__file__).resolve().parents[2] / "infrastructure" / "fixtures"


def _rule_types() -> list[dict]:
    """The rule-type catalogue, with each shared mapping block put back."""
    document = json.loads((_FIXTURES / "kibana_rule_types.json").read_text())
    blocks = document["alerts"]
    return [
        {**entry, "alerts": blocks[entry["alerts"][1:]]}
        if isinstance(entry.get("alerts"), str) else entry
        for entry in document["rule_types"]
    ]


_RULE_TYPES: list[dict] = _rule_types()

#: The connector types a Kibana 8.15 reports, verbatim. Which are *enabled*
#: depends on the licence, and a client reads that to decide what it may
#: create — so the licence fields are kept as a Basic deployment reports
#: them.
_CONNECTOR_TYPES: list[dict] = json.loads(
    (_FIXTURES / "kibana_connector_types.json").read_text(),
)

#: What a running Kibana reports about its task manager, and about its
#: licence. Both are read for what they *say* — is the framework healthy,
#: does this licence allow that feature — so they are captured rather than
#: typed out.
_TASK_HEALTH: dict = json.loads(
    (_FIXTURES / "kibana_task_manager_health.json").read_text(),
)
_LICENCE: dict = json.loads((_FIXTURES / "kibana_licence.json").read_text())

#: A health timestamp has to move, but not per request: Kibana reports when
#: it last checked, and a client that polls sees the same instant until the
#: next check.
_HEALTH_TIMESTAMP = "2026-08-25T10:00:00.000Z"


@router.get("/api/alerting/_health")
def alerting_health(_: dict = Depends(require_es_auth)) -> dict:
    """Whether the alerting framework can run rules at all."""
    check = {"status": "ok", "timestamp": _HEALTH_TIMESTAMP}
    return {
        "is_sufficiently_secure": True,
        "has_permanent_encryption_key": True,
        "alerting_framework_health": {
            "decryption_health": dict(check),
            "execution_health": dict(check),
            "read_health": dict(check),
        },
    }


@router.get("/api/alerting/rule_types")
def rule_types(_: dict = Depends(require_es_auth)) -> list[dict]:
    """The kinds of rule this deployment can run."""
    return _RULE_TYPES


@router.get(
    "/api/alerting/rules/_find",
    dependencies=[refuses_unknown(
        "page", "per_page", "search", "default_search_operator", "search_fields",
        "sort_field", "sort_order", "has_reference", "fields", "filter",
        "filter_consumers",
        numbers=("page", "per_page"),
    )],
)
def find_rules(
    # Taken as text: config-schema answers a non-number in its own words, and
    # an `int` here answers pydantic's to it instead.
    page: str = Query(default="1"),
    per_page: str = Query(default="10"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """The alerting rules this deployment holds.

    mockdr's detection rules are served by the detection engine's own API
    and are not backed by the alerting framework, so this lists none — the
    same answer a Kibana with no alerting rules gives.
    """
    return {"page": int(float(page or 0)), "per_page": int(float(per_page or 0)),
            "total": 0, "data": []}


@router.get("/api/actions/connectors")
def list_connectors(_: dict = Depends(require_es_auth)) -> list[dict]:
    """The connectors an alerting rule can act through."""
    return []


@router.get(
    "/api/actions/connector_types",
    dependencies=[refuses_unknown("feature_id")],
)
def connector_types(
    _feature_id: str | None = Query(default=None, alias="feature_id"),
    _: dict = Depends(require_es_auth),
) -> list[dict]:
    """The kinds of connector this deployment offers, and their licences."""
    return _CONNECTOR_TYPES


@router.get("/api/task_manager/_health")
def task_manager_health(_: dict = Depends(require_es_auth)) -> dict:
    """Whether background tasks are running, which alerting depends on.

    Captured from a running instance: the body is a page of measurements —
    drift percentiles, an estimated schedule density, a capacity estimate
    with a sentence explaining it — and a hand-written one had arrays where
    Kibana has percentile objects.
    """
    return {**_TASK_HEALTH, "timestamp": _HEALTH_TIMESTAMP,
            "last_update": _HEALTH_TIMESTAMP, "id": "mockdr-task-manager"}


@router.get("/internal/security/me")
def current_user(_: dict = Depends(require_es_auth)) -> dict:
    """Who Kibana thinks the caller is, which every client checks first."""
    return {
        "username": "elastic",
        "roles": ["superuser"],
        "full_name": None,
        "email": None,
        "metadata": {"_reserved": True},
        "enabled": True,
        "authentication_realm": {"name": "reserved", "type": "reserved"},
        "lookup_realm": {"name": "reserved", "type": "reserved"},
        "authentication_type": "realm",
        "authentication_provider": {"type": "http", "name": "__http__"},
        "elastic_cloud_user": False,
    }


@router.get("/api/licensing/info")
def licence_info(_: dict = Depends(require_es_auth)) -> dict:
    """The licence, and what it allows — read before a client offers a feature.

    A Basic licence, as a real one reports itself: which features are
    available decides what a client may ask for next, and an optimistic
    "everything is available" would have it offer what the deployment then
    refuses.
    """
    return {
        **_LICENCE,
        "license": {**_LICENCE["license"], "uid": _LICENCE_UID},
        "signature": f"mockdr-{APP_VERSION}",
    }


#: A licence's uid identifies the deployment; mockdr's is its own and stays
#: the same across restarts.
_LICENCE_UID = "00000000-0000-0000-0000-000000000000"


def _list_envelope(page: int, per_page: int, data: list[Any]) -> dict:
    """The envelope the value-list API pages with, cursor and all."""
    return {
        "data": data,
        "page": page,
        "per_page": per_page,
        "total": len(data),
        # Kibana's cursor is an opaque token; an empty page's is always this.
        "cursor": "WzBd",
    }


@router.get("/api/lists/_find")
def find_lists(
    # Taken as text: an empty value is the number zero on 8.15 — `?per_page=`
    # answers 200 with an empty page beside the real total — and an `int`
    # here answers pydantic's wording to it instead.
    page: str = Query(default="1"),
    per_page: str = Query(default="20"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """The value lists an exception can point at.

    mockdr holds none: a value list is a file a client uploads, and nothing
    in the mock creates one. The envelope is the one Kibana pages with, so a
    client reading `cursor` and `total` sees what it expects.
    """
    return _list_envelope(int(float(page or 0)), int(float(per_page or 0)), [])
