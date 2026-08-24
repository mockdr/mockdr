from fastapi import APIRouter, Depends, Query
from starlette.requests import Request

from api.auth import require_admin, require_write
from api.dto.common import FilterBody
from api.dto.requests import StarRuleCreateBody
from application.alerts import commands as alert_commands
from application.alerts import queries as alert_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from utils.documented_params import documented_openapi, documented_params
from utils.pagination import build_list_response

router = APIRouter(tags=["Alerts"])


# ── Queries ───────────────────────────────────────────────────────────────────


@router.get("/cloud-detection/alerts", openapi_extra=documented_openapi("/cloud-detection/alerts"))
def list_alerts(
    request: Request,
    ids: str = Query(None),
    # `tenant=true` asks for the whole tenant rather than the caller's own
    # scope. mockdr seeds one tenant, and the account scoping a non-admin
    # token carries still applies, so the answer is the same set — but the
    # parameter is declared rather than silently dropped.
    tenant: bool = Query(None),
    accountIds: str = Query(None),
    siteIds: str = Query(None),
    groupIds: str = Query(None),
    agentIds: str = Query(None),
    severities: str = Query(None),
    categories: str = Query(None),
    analystVerdicts: str = Query(None),
    incidentStatuses: str = Query(None),
    # The swagger's own names, beside the plural ones this mock has always
    # taken (see application/alerts/queries.py).
    severity: str = Query(None),
    analystVerdict: str = Query(None),
    incidentStatus: str = Query(None),
    osType: str = Query(None),
    ruleName__contains: str = Query(None),  # noqa: N803 - the vendor's own name
    query: str = Query(None),
    createdAt__gte: str = Query(None),
    createdAt__lte: str = Query(None),
    sortBy: str = Query(None),
    sortOrder: str = Query(None),
    skip: int = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of cloud-detection alerts."""
    params = {
        k: v for k, v in locals().items()
        if v is not None and k not in ("cursor", "limit", "request")
    }
    params.update(documented_params(request, "/cloud-detection/alerts"))
    return alert_queries.list_alerts(params, cursor, limit)


@router.post("/cloud-detection/alerts/analyst-verdict")
def set_analyst_verdict(body: FilterBody, current_user: dict = Depends(require_write)) -> dict:
    """Set the analyst verdict on the specified alerts."""
    ids = body.filter.get("ids", [])
    verdict = body.data.get("analystVerdict", "UNDEFINED")
    return alert_commands.set_analyst_verdict(verdict, ids, current_user.get("userId"))


@router.post("/cloud-detection/alerts/incident")
def set_incident_status(body: FilterBody, current_user: dict = Depends(require_write)) -> dict:
    """Set the incident status on the specified alerts."""
    ids = body.filter.get("ids", [])
    status = body.data.get("incidentStatus", "UNRESOLVED")
    return alert_commands.set_incident_status(status, ids, current_user.get("userId"))


# ── STAR Rules ───────────────────────────────────────────────────────────────


@router.get("/cloud-detection/rules", openapi_extra=documented_openapi("/cloud-detection/rules"))
def list_star_rules(
    request: Request,
    status: str = Query(None),
    severity: str = Query(None),
    queryType: str = Query(None),  # noqa: N803 - the vendor's own name
    sortBy: str = Query(None),
    sortOrder: str = Query(None),
    skip: int = Query(None),
) -> dict:
    """Return the STAR custom detection rules, filtered as the swagger declares."""
    params = {
        k: v for k, v in locals().items()
        if v is not None and k not in ("cursor", "limit", "request")
    }
    params.update(documented_params(request, "/cloud-detection/rules"))
    rules = alert_queries.filter_star_rules(params)
    # RuleViewSchema_many: the declared fields only, with a pagination block.
    return build_list_response(
        rules,
        None,
        len(rules),
        definition="v2_1.rules.schemas_RuleViewSchema_many_200",
        strict=True,
    )


@router.post("/cloud-detection/rules")
def create_star_rule(body: StarRuleCreateBody, current_user: dict = Depends(require_admin)) -> dict:
    """Create a new STAR custom detection rule."""
    return alert_commands.create_star_rule(body.model_dump(), current_user.get("userId"))
