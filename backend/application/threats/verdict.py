"""Threat verdict and incident status commands."""

from application import bridge
from application.webhooks import commands as webhook_commands
from domain.webhook import THREAT_UPDATED
from repository.activity_repo import activity_repo
from repository.threat_repo import threat_repo
from utils.dt import utc_now
from utils.serde import record_dict


def set_analyst_verdict(verdict: str, ids: list[str], actor_user_id: str | None = None) -> dict:
    """Set the analyst verdict on a list of threats.

    Implements POST /threats/analyst-verdict.

    Args:
        verdict: Verdict string (e.g. ``"true_positive"``).
        ids: List of threat IDs to update.
        actor_user_id: ID of the acting user, if authenticated.

    Returns:
        Dict with ``data.affected`` indicating how many threats were updated.
    """
    affected = 0
    for threat_id in ids:
        threat = threat_repo.get(threat_id)
        if not threat:
            continue
        threat.threatInfo["analystVerdict"] = verdict
        threat.threatInfo["updatedAt"] = utc_now()
        threat_repo.save(threat)
        bridge.threat_changed(threat)
        site_id = threat.agentDetectionInfo.get("agentSiteId")
        activity_repo.create(
            activity_type=3784 if verdict == "true_positive" else 3016,
            description=f"Analyst verdict set to '{verdict}'",
            threat_id=threat_id,
            user_id=actor_user_id,
            site_id=site_id,
        )
        webhook_commands.fire_event(THREAT_UPDATED, record_dict(threat))
        affected += 1
    return {"data": {"affected": affected}}


def _mark_malicious(ids: list[str], actor_user_id: str | None = None) -> dict:
    """Set the engine's confidence and the analyst's verdict together.

    Only `dv-mark-as-threat` reaches this: a Deep Visibility marking says
    both, where `/threats/analyst-verdict` says only the second.
    """
    affected = 0
    for threat_id in ids:
        threat = threat_repo.get(threat_id)
        if not threat:
            continue
        threat.threatInfo["confidenceLevel"] = "malicious"
        threat.threatInfo["analystVerdict"] = "true_positive"
        threat.threatInfo["updatedAt"] = utc_now()
        threat_repo.save(threat)
        bridge.threat_changed(threat)
        site_id = threat.agentDetectionInfo.get("agentSiteId")
        activity_repo.create(
            3784, "Threat marked as malicious",
            threat_id=threat_id, user_id=actor_user_id, site_id=site_id,
        )
        webhook_commands.fire_event(THREAT_UPDATED, record_dict(threat))
        affected += 1
    return {"data": {"affected": affected}}


def set_incident_status(status: str, ids: list[str], actor_user_id: str | None = None) -> dict:
    """Set the incident status on a list of threats.

    Implements POST /threats/incident.

    Args:
        status: Status string (e.g. ``"resolved"``).
        ids: List of threat IDs to update.
        actor_user_id: ID of the acting user, if authenticated.

    Returns:
        Dict with ``data.affected`` indicating how many threats were updated.
    """
    affected = 0
    for threat_id in ids:
        threat = threat_repo.get(threat_id)
        if not threat:
            continue
        threat.threatInfo["incidentStatus"] = status
        threat.threatInfo["updatedAt"] = utc_now()
        threat_repo.save(threat)
        bridge.threat_changed(threat)
        site_id = threat.agentDetectionInfo.get("agentSiteId")
        activity_repo.create(
            activity_type=27,
            description=f"Incident status set to '{status}'",
            threat_id=threat_id,
            user_id=actor_user_id,
            site_id=site_id,
        )
        webhook_commands.fire_event(THREAT_UPDATED, record_dict(threat))
        affected += 1
    return {"data": {"affected": affected}}




