"""Threat mitigation, blocklist, engine, and file-fetch commands."""
import io
import zipfile

from fastapi import HTTPException

from repository.activity_repo import activity_repo
from repository.blocklist_repo import blocklist_repo
from repository.threat_repo import threat_repo
from utils.dt import utc_now
from utils.id_gen import new_id

_MITIGATION_MAP = {
    "kill":                 "killed",
    "quarantine":           "quarantined",
    "un-quarantine":        "active",
    "remediate":            "remediated",
    "rollback-remediation": "rollback",
}


def mitigate(action: str, ids: list[str], actor_user_id: str | None = None) -> dict:
    """Apply a mitigation action to a list of threats.

    Implements POST /threats/mitigate/{action}.

    Args:
        action: Mitigation action key (e.g. ``"kill"``, ``"quarantine"``).
        ids: List of threat IDs to mitigate.
        actor_user_id: ID of the acting user, if authenticated.

    Returns:
        Dict with ``data.affected`` indicating how many threats were updated.
    """
    new_status = _MITIGATION_MAP.get(action)
    if new_status is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown mitigation action: {action!r}. "
                   f"Valid actions: {sorted(_MITIGATION_MAP)}",
        )
    affected = 0
    for threat_id in ids:
        threat = threat_repo.get(threat_id)
        if not threat:
            continue
        threat.threatInfo["mitigationStatus"] = new_status
        threat.threatInfo["updatedAt"] = utc_now()
        threat_repo.save(threat)
        site_id = threat.agentDetectionInfo.get("agentSiteId")
        activity_repo.create(
            activity_type=26,
            description=f"Threat mitigated: {action}",
            threat_id=threat_id,
            user_id=actor_user_id,
            site_id=site_id,
        )
        affected += 1
    return {"data": {"affected": affected}}


def add_to_blacklist(ids: list[str], data: dict, actor_user_id: str | None = None) -> dict:
    """Add the SHA1 hash of each threat to the blocklist.

    Implements POST /threats/add-to-blacklist.

    Args:
        ids: List of threat IDs whose hashes to blocklist.
        data: Additional request data (unused but accepted for API compatibility).
        actor_user_id: ID of the acting user, if authenticated.

    Returns:
        Dict with ``data.affected`` indicating how many entries were added.
    """
    affected = 0
    for threat_id in ids:
        threat = threat_repo.get(threat_id)
        if not threat:
            continue
        bid = new_id()
        sha1 = threat.threatInfo.get("sha1", "")
        threat_name = threat.threatInfo.get("threatName", "")
        site_id = threat.agentDetectionInfo.get("agentSiteId")
        blocklist_repo.save_raw(bid, {
            "id": bid,
            "value": sha1,
            "type": "black_hash",
            "description": f"Added from threat: {threat_name}",
            "source": "threat",
            "siteId": site_id,
            "createdAt": utc_now(),
            "updatedAt": utc_now(),
        })
        activity_repo.create(
            4003, f"Hash {sha1} added to blocklist",
            threat_id=threat_id, user_id=actor_user_id, site_id=site_id,
        )
        affected += 1
    return {"data": {"affected": affected}}


def dv_add_to_blacklist(ids: list[str], data: dict, actor_user_id: str | None = None) -> dict:
    """Add the hash of each threat (from Deep Visibility context) to the blocklist.

    Implements POST /threats/dv-add-to-blacklist.
    Identical behaviour to add-to-blacklist but sourced from a DV query result.
    """
    return add_to_blacklist(ids, data, actor_user_id)


def fetch_file(ids: list[str], actor_user_id: str | None = None) -> dict:
    """Queue a file fetch from the agent and generate a fake sample zip.

    Implements POST /threats/fetch-file.
    Stores a zip archive on the threat object so the download endpoint can
    serve it immediately (simulating a completed agent upload).
    """
    affected = 0
    for threat_id in ids:
        threat = threat_repo.get(threat_id)
        if not threat:
            continue
        file_name = threat.threatInfo.get("fileName", "sample.exe")
        sha1 = threat.threatInfo.get("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        threat_name = threat.threatInfo.get("threatName", "Unknown")
        # Build a fake zip containing a text stub that mimics a quarantined file
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            content = (
                f"MOCK FETCHED FILE — SentinelOne Mock API\n"
                f"File: {file_name}\n"
                f"Threat: {threat_name}\n"
                f"SHA1: {sha1}\n"
                f"ThreatId: {threat_id}\n"
                f"FetchedAt: {utc_now()}\n"
                f"\n[This is a simulated file. No actual malware content.]\n"
            ).encode()
            zf.writestr(file_name, content)
        threat._fetched_file = buf.getvalue()
        site_id = threat.agentDetectionInfo.get("agentSiteId")
        threat_repo.save(threat)
        activity_repo.create(
            25, f"File fetch completed: {file_name}",
            threat_id=threat_id, user_id=actor_user_id, site_id=site_id,
        )
        affected += 1
    return {"data": {"affected": affected}}


def disable_engines(ids: list[str], actor_user_id: str | None = None) -> dict:
    """Disable detection engines on the agents hosting the specified threats.

    Implements POST /threats/engines/disable.
    Logs an activity per threat to record the engine disable request.
    """
    affected = 0
    for threat_id in ids:
        threat = threat_repo.get(threat_id)
        if not threat:
            continue
        computer = threat.agentDetectionInfo.get("agentComputerName", "unknown")
        site_id = threat.agentDetectionInfo.get("agentSiteId")
        activity_repo.create(
            120, f"Detection engines disabled on {computer}",
            threat_id=threat_id, user_id=actor_user_id, site_id=site_id,
        )
        affected += 1
    return {"data": {"affected": affected}}


def dv_mark_as_threat(ids: list[str], actor_user_id: str | None = None) -> dict:
    """Mark threats as confirmed malicious (from Deep Visibility context).

    Implements POST /threats/dv-mark-as-threat.
    Delegates to verdict.mark_as_threat.
    """
    from application.threats.verdict import mark_as_threat
    return mark_as_threat(ids, actor_user_id)
