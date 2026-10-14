"""Threat mitigation, blocklist, engine, and file-fetch commands."""
import io
import zipfile

from fastapi import HTTPException

from application import bridge
from repository.activity_repo import activity_repo
from repository.blocklist_repo import blocklist_repo
from repository.threat_repo import threat_repo
from utils.dt import utc_now
from utils.id_gen import new_id

#: Each mitigate action the 2.1 swagger enumerates for
#: ``POST /threats/mitigate/{action}`` — kill, remediate, rollback-remediation,
#: quarantine, un-quarantine, remove_macros, restore_macros — mapped to what it
#: leaves behind on the threat: the ``threatInfo.mitigationStatus`` and the
#: ``action`` of the entry it records in the threat's top-level
#: ``mitigationStatus`` list.
#:
#: The mock wrote "killed", "quarantined", "remediated", "rollback" and
#: "active" into ``threatInfo.mitigationStatus``, whose swagger enum is
#: ``not_mitigated``, ``mitigated``, ``marked_as_benign`` — so a client
#: filtering ``mitigationStatuses=mitigated`` never found a threat it had just
#: mitigated, and one that switches on the enum fell through every case. The
#: per-action detail belongs in the list, whose ``action`` enum is kill,
#: remediate, rollback, quarantine, unquarantine, network_quarantine,
#: remove_macros, restore_macros. Undoing a quarantine or restoring macros
#: leaves the threat unmitigated again. ``remove_macros`` and
#: ``restore_macros`` were refused with a 400 though the swagger lists them.
#: (The operation's prose also names "network-quarantine", but its enum does
#: not, so it is not accepted here.)
_MITIGATION_MAP: dict[str, tuple[str, str]] = {
    "kill":                 ("mitigated", "kill"),
    "quarantine":           ("mitigated", "quarantine"),
    "un-quarantine":        ("not_mitigated", "unquarantine"),
    "remediate":            ("mitigated", "remediate"),
    "rollback-remediation": ("mitigated", "rollback"),
    "remove_macros":        ("mitigated", "remove_macros"),
    "restore_macros":       ("not_mitigated", "restore_macros"),
}


def _status_description(status: str) -> str:
    """``mitigationStatusDescription`` the way the seeded threats spell it."""
    return status.replace("_", " ").title()


def record_mitigation(threat: object, action: str, now: str) -> None:
    """Apply a documented mitigate *action* to *threat* and record it.

    Sets ``threatInfo.mitigationStatus`` (and its description) from the
    swagger's enum and puts one entry for the action in the threat's
    ``mitigationStatus`` list, replacing an earlier entry for the same
    action. Shared with the playbook engine, whose policy auto-mitigation
    wrote the same past-tense strings.
    """
    status, list_action = _MITIGATION_MAP[action]
    info = threat.threatInfo  # type: ignore[attr-defined]
    info["mitigationStatus"] = status
    info["mitigationStatusDescription"] = _status_description(status)
    info["updatedAt"] = now
    entries = [
        e for e in (getattr(threat, "mitigationStatus", None) or [])
        if not (isinstance(e, dict) and e.get("action") == list_action)
    ]
    entries.append({
        "action": list_action,
        "status": "success",
        "actionsCounters": {
            "total": 1, "success": 1, "failed": 0, "pendingReboot": 0, "notFound": 0,
        },
        "agentSupportsReport": True,
        "groupNotFound": False,
        "lastUpdate": now,
        "latestReport": None,
        "mitigationStartedAt": now,
        "mitigationEndedAt": now,
        "reportId": None,
    })
    threat.mitigationStatus = entries  # type: ignore[attr-defined]


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
    if action not in _MITIGATION_MAP:
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
        record_mitigation(threat, action, utc_now())
        threat_repo.save(threat)
        bridge.threat_changed(threat)
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
        bridge.threat_changed(threat)
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

    Implements POST /threats/dv-mark-as-threat, which the 2.1 swagger does
    publish. It used to delegate to a `mark_as_threat` sitting behind
    `POST /threats/mark-as-threat`, a route the swagger does not publish at
    all; that route is gone and its body lives here, where its one remaining
    caller is. A Deep Visibility marking is the engine's as well as the
    analyst's, which is why it moves `confidenceLevel` and the plain
    `/threats/analyst-verdict` does not.
    """
    from application.threats.verdict import _mark_malicious

    return _mark_malicious(ids, actor_user_id)
