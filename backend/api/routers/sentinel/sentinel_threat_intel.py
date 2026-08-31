"""Sentinel Threat Intelligence router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from api.sentinel_auth import require_sentinel_auth
from application.sentinel.commands import threat_intel as ti_cmds
from application.sentinel.queries import threat_intel as ti_queries
from utils.sentinel.response import build_arm_error
from utils.vendor_errors import build_vendor_error

router = APIRouter(tags=["Sentinel Threat Intelligence"])

_WS = (
    "/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
    "/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
    "/providers/Microsoft.SecurityInsights"
)


# ── List indicators ──────────────────────────────────────────────────────


@router.get(_WS + "/threatIntelligence/main/indicators")
def list_indicators(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    request: Request,
    top: int = Query(default=None, alias="$top"),
    skip_token: str = Query(default=None, alias="$skipToken"),
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List threat intelligence indicators."""
    return ti_queries.list_indicators(
        top=min(top or 50, 1000),
        skip_token=skip_token or "",
        request_url=str(request.url),
    )


# ── Tagging one indicator ────────────────────────────────────────────────
#
# `ThreatIntelligenceIndicator_AppendTags` and `_ReplaceTags` act on the
# indicator named in the *path*, and take `{"threatIntelligenceTags": [...]}`.
# mockdr had invented a bulk pair on the collection — a path the vendor does
# not have, reading `indicatorNames` and `tags`, which no client generated
# from the ARM spec would ever send.  The two also differ in what they answer,
# which is not a thing anyone would guess: append gives 200 and no body,
# replace gives the indicator back (2024-03-01 SecurityInsights swagger,
# `ThreatIntelligence.json`).


async def _tags_from(request: Request) -> list[str]:
    """The tag list, in the member the vendor's schema names."""
    body = await request.json()
    if not isinstance(body, dict):
        # A JSON null or array reached `.get` on the wrong type and 500ed.
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error("sentinel", 400, "Request body must be a JSON object"),
        )
    tags = body.get("threatIntelligenceTags") or []
    return [str(tag) for tag in tags] if isinstance(tags, list) else []


@router.post(
    _WS + "/threatIntelligence/main/indicators/{name}/appendTags",
    status_code=200,
)
async def append_tags(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    name: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> Response:
    """Append tags to one indicator, and answer with nothing."""
    tags = await _tags_from(request)
    if ti_queries.get_indicator(name) is None:
        raise HTTPException(status_code=404, detail=build_vendor_error(
            "sentinel", 404, f"Threat intelligence indicator {name} was not found",
        ))
    ti_cmds.append_tags([name], tags)
    return Response(status_code=200)


@router.post(_WS + "/threatIntelligence/main/indicators/{name}/replaceTags")
async def replace_tags(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    name: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Replace one indicator's tags, and answer with the indicator."""
    tags = await _tags_from(request)
    if ti_queries.get_indicator(name) is None:
        raise HTTPException(status_code=404, detail=build_vendor_error(
            "sentinel", 404, f"Threat intelligence indicator {name} was not found",
        ))
    ti_cmds.replace_tags([name], tags)
    indicator = ti_queries.get_indicator(name)
    return indicator if indicator is not None else {}


# ── Single indicator CRUD ────────────────────────────────────────────────


@router.get(_WS + "/threatIntelligence/main/indicators/{name}")
def get_indicator(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    name: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Get a single threat intelligence indicator."""
    result = ti_queries.get_indicator(name)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("ResourceNotFound", f"Indicator '{name}' not found"),
        )
    return result


@router.put(_WS + "/threatIntelligence/main/indicators/{name}")
async def create_or_update_indicator(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    name: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Create or update a threat intelligence indicator."""
    body = await request.json()
    if not isinstance(body, dict):
        # A JSON null or array reached `.get` on the wrong type and 500ed.
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error("sentinel", 400, "Request body must be a JSON object"),
        )
    properties = body.get("properties", {})
    ti_cmds.create_or_update_indicator(name, properties)
    return ti_queries.get_indicator(name) or {}


@router.delete(_WS + "/threatIntelligence/main/indicators/{name}")
def delete_indicator(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    name: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Delete a threat intelligence indicator."""
    if not ti_cmds.delete_indicator(name):
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("ResourceNotFound", f"Indicator '{name}' not found"),
        )
    return {}


# ── Create with auto-name ────────────────────────────────────────────────


@router.post(_WS + "/threatIntelligence/main/createIndicator")
async def create_indicator(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Create a threat intelligence indicator with auto-generated name."""
    body = await request.json()
    if not isinstance(body, dict):
        # A JSON null or array reached `.get` on the wrong type and 500ed.
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error("sentinel", 400, "Request body must be a JSON object"),
        )
    properties = body.get("properties", {})
    indicator = ti_cmds.create_indicator(properties)
    result = ti_queries.get_indicator(indicator.name)
    return result or {}


def _whole(body: dict, member: str, default: int) -> int:
    """One of this body's numeric members, or a 400 saying which is wrong.

    `int(body.get(member) or default)` raised out of the handler for every
    value that is not a number — `"abc"`, a dict, and `Infinity`, which
    Python's JSON parser accepts and `int()` refuses with a third kind of
    exception. A client that sent the wrong type for a confidence bound got
    a 500: that tells it the server is broken and to retry, where a 400
    tells it the request is, which is the true and useful answer.
    """
    value = body.get(member)
    if value is None or value == "" or value == [] or value == {}:
        return default
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        # OverflowError too: Python's JSON parser accepts `Infinity` and
        # `1e400`, and `int()` of either raises a third kind of exception.
        raise HTTPException(
            status_code=400,
            detail=build_arm_error(
                "BadRequest",
                f"The value of parameter '{member}' is invalid.",
            ),
        ) from None


# ── Query / Metrics ──────────────────────────────────────────────────────


@router.post(_WS + "/threatIntelligence/main/queryIndicators")
async def query_indicators(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Query threat intelligence indicators."""
    body = await request.json()
    if not isinstance(body, dict):
        # A JSON null or array reached `.get` on the wrong type and 500ed.
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error("sentinel", 400, "Request body must be a JSON object"),
        )
    keywords = body.get("keywords") or []
    return ti_queries.query_indicators(
        # The spec spells keywords as a list; a client sending one string is
        # taken to mean that one keyword.
        keywords=(" ".join(str(k) for k in keywords)
                  if isinstance(keywords, list) else str(keywords)),
        pattern_types=body.get("patternTypes"),
        threat_types=body.get("threatTypes"),
        sources=body.get("sources"),
        ids=body.get("ids"),
        min_confidence=_whole(body, "minConfidence", 0),
        max_confidence=_whole(body, "maxConfidence", 100),
        include_disabled=bool(body.get("includeDisabled", True)),
        sort_by=body.get("sortBy"),
        page_size=_whole(body, "pageSize", 50),
    )


# `ThreatIntelligenceIndicatorMetrics_List` is a GET: it lists what the
# workspace holds and takes no body.  mockdr served it on POST alone, so a
# client generated from the ARM spec reached it not at all.
@router.get(_WS + "/threatIntelligence/main/metrics")
def get_metrics(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Get threat intelligence metrics."""
    return ti_queries.get_metrics()
