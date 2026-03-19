from fastapi import APIRouter, Depends, HTTPException, Query

from api.auth import require_admin, require_write
from api.dto.common import FilterBody
from api.dto.requests import StarRuleCreateBody
from application.alerts import commands as alert_commands
from application.alerts import queries as alert_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE

router = APIRouter(tags=["Alerts"])


# ── Queries ───────────────────────────────────────────────────────────────────

@router.get("/cloud-detection/alerts")
def list_alerts(
    ids: str = Query(None),
    siteIds: str = Query(None),
    groupIds: str = Query(None),
    agentIds: str = Query(None),
    severities: str = Query(None),
    categories: str = Query(None),
    analystVerdicts: str = Query(None),
    incidentStatuses: str = Query(None),
    query: str = Query(None),
    createdAt__gte: str = Query(None),
    createdAt__lte: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of cloud-detection alerts."""
    params = {k: v for k, v in locals().items() if v is not None and k not in ("cursor", "limit")}
    return alert_queries.list_alerts(params, cursor, limit)


@router.get("/cloud-detection/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict:
    """Return a single alert by ID."""
    result = alert_queries.get_alert(alert_id)
    if not result:
        raise HTTPException(status_code=404)
    return result


# ── Commands ──────────────────────────────────────────────────────────────────

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

@router.get("/cloud-detection/rules")
def list_star_rules() -> dict:
    """Return all STAR custom detection rules."""
    return alert_commands.list_star_rules()


@router.post("/cloud-detection/rules")
def create_star_rule(body: StarRuleCreateBody, current_user: dict = Depends(require_admin)) -> dict:
    """Create a new STAR custom detection rule."""
    return alert_commands.create_star_rule(body.model_dump(), current_user.get("userId"))
