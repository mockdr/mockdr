"""Sentinel incident seeder — replays existing EDR data into Sentinel incidents + alerts + entities."""
from __future__ import annotations

import random
import time
import uuid
from dataclasses import asdict

from domain.sentinel.alert import SentinelAlert
from domain.sentinel.bookmark import SentinelBookmark
from domain.sentinel.entity import SentinelEntity
from domain.sentinel.incident import SentinelIncident
from domain.sentinel.incident_comment import SentinelIncidentComment
from repository.sentinel.alert_repo import sentinel_alert_repo
from repository.sentinel.bookmark_repo import sentinel_bookmark_repo
from repository.sentinel.entity_repo import sentinel_entity_repo
from repository.sentinel.incident_comment_repo import sentinel_incident_comment_repo
from repository.sentinel.incident_repo import sentinel_incident_repo
from repository.store import store

# Fixed reference epoch for deterministic seed data
_SEED_EPOCH = 1700000000.0

_SENTINEL_SEVERITIES = ["High", "Medium", "Medium", "Low", "Informational"]
_SENTINEL_STATUSES = ["New", "New", "New", "Active", "Active", "Closed"]

_INC_NUM = 0


def _next_num() -> int:
    global _INC_NUM
    _INC_NUM += 1
    return _INC_NUM


def seed_sentinel_incidents() -> None:
    """Replay all existing EDR data into Sentinel incidents."""
    global _INC_NUM
    _INC_NUM = 0
    _seed_from_mde()
    _seed_from_s1()
    _seed_from_cs()
    _seed_from_es()
    _seed_from_xdr()
    _seed_bookmarks()
    _seed_comments()


def _seed_from_mde() -> None:
    """Generate Sentinel incidents from MDE alerts."""
    alerts = store.get_all("mde_alerts")
    for alert_data in alerts:
        d = asdict(alert_data) if hasattr(alert_data, "__dataclass_fields__") else alert_data.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event_time))

        # Create entity
        hostname = str(d.get("computerDnsName", d.get("machine_id", "")))
        entity_ids = []
        if hostname:
            eid = _save_entity("Host", {"hostName": hostname})
            entity_ids.append(eid)

        alert_id = f"mde-{d.get('id', uuid.uuid4().hex)}"
        alert = SentinelAlert(
            alert_id=alert_id,
            alert_display_name=str(d.get("title", d.get("alert_name", "MDE Alert"))),
            description=str(d.get("description", "")),
            severity=_map_severity(str(d.get("severity", "Medium"))),
            product_name="Microsoft Defender for Endpoint",
            vendor_name="Microsoft",
            time_generated=now,
            entity_ids=entity_ids,
        )

        inc_id = f"inc-mde-{uuid.uuid4().hex[:12]}"
        incident = SentinelIncident(
            incident_id=inc_id,
            title=alert.alert_display_name,
            description=alert.description,
            severity=alert.severity,
            status=random.choice(_SENTINEL_STATUSES),
            incident_number=_next_num(),
            created_time_utc=now,
            last_modified_time_utc=now,
            first_activity_time_utc=now,
            last_activity_time_utc=now,
            provider_name="Microsoft 365 Defender",
            provider_incident_id=alert_id,
            alert_ids=[alert_id],
            entity_ids=entity_ids,
            alert_product_names=["Microsoft Defender for Endpoint"],
            tactics=["Execution"],
            etag=uuid.uuid4().hex[:8],
        )
        alert.incident_id = inc_id
        sentinel_alert_repo.save(alert)
        sentinel_incident_repo.save(incident)


def _seed_from_s1() -> None:
    """Generate Sentinel incidents from S1 threats."""
    threats = store.get_all("threats")
    for threat in threats:
        d = asdict(threat) if hasattr(threat, "__dataclass_fields__") else threat.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event_time))

        entity_ids = []
        comp = str(d.get("computerName", d.get("agentComputerName", "")))
        if comp:
            entity_ids.append(_save_entity("Host", {"hostName": comp}))

        alert_id = f"s1-{d.get('id', uuid.uuid4().hex)}"
        threat_name = str(d.get("threatName", d.get("classification", "Threat")))
        alert = SentinelAlert(
            alert_id=alert_id,
            alert_display_name=f"SentinelOne: {threat_name}",
            severity=random.choice(["High", "Medium"]),
            product_name="SentinelOne",
            vendor_name="SentinelOne",
            time_generated=now,
            entity_ids=entity_ids,
        )

        inc_id = f"inc-s1-{uuid.uuid4().hex[:12]}"
        incident = SentinelIncident(
            incident_id=inc_id,
            title=alert.alert_display_name,
            description=getattr(alert, "description", alert.alert_display_name),
            severity=alert.severity,
            status=random.choice(_SENTINEL_STATUSES),
            incident_number=_next_num(),
            created_time_utc=now, last_modified_time_utc=now,
            first_activity_time_utc=now, last_activity_time_utc=now,
            provider_name="Azure Sentinel",
            provider_incident_id=alert_id,
            alert_ids=[alert_id], entity_ids=entity_ids,
            alert_product_names=["SentinelOne"],
            related_analytic_rule_ids=["rule-s1-threats"],
            etag=uuid.uuid4().hex[:8],
        )
        alert.incident_id = inc_id
        sentinel_alert_repo.save(alert)
        sentinel_incident_repo.save(incident)


def _seed_from_cs() -> None:
    """Generate Sentinel incidents from CS detections."""
    detections = store.get_all("cs_detections")
    for det in detections:
        d = asdict(det) if hasattr(det, "__dataclass_fields__") else det.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event_time))

        entity_ids = []
        hn = str(d.get("hostname", d.get("device", {}).get("hostname", "")))
        if hn:
            entity_ids.append(_save_entity("Host", {"hostName": hn}))

        alert_id = f"cs-{d.get('detection_id', uuid.uuid4().hex)}"
        alert = SentinelAlert(
            alert_id=alert_id,
            alert_display_name=f"CrowdStrike: {d.get('detect_name', 'Detection')}",
            severity=random.choice(["High", "Medium"]),
            product_name="CrowdStrike Falcon",
            vendor_name="CrowdStrike",
            time_generated=now,
            entity_ids=entity_ids,
        )

        inc_id = f"inc-cs-{uuid.uuid4().hex[:12]}"
        incident = SentinelIncident(
            incident_id=inc_id,
            title=alert.alert_display_name,
            description=getattr(alert, "description", alert.alert_display_name),
            severity=alert.severity,
            status=random.choice(_SENTINEL_STATUSES),
            incident_number=_next_num(),
            created_time_utc=now, last_modified_time_utc=now,
            first_activity_time_utc=now, last_activity_time_utc=now,
            provider_name="Azure Sentinel",
            provider_incident_id=alert_id,
            alert_ids=[alert_id], entity_ids=entity_ids,
            alert_product_names=["CrowdStrike Falcon"],
            related_analytic_rule_ids=["rule-cs-detections"],
            etag=uuid.uuid4().hex[:8],
        )
        alert.incident_id = inc_id
        sentinel_alert_repo.save(alert)
        sentinel_incident_repo.save(incident)


def _seed_from_es() -> None:
    """Generate Sentinel incidents from Elastic alerts."""
    alerts = store.get_all("es_alerts")
    for al in alerts:
        d = asdict(al) if hasattr(al, "__dataclass_fields__") else al.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event_time))

        alert_id = f"es-{d.get('id', uuid.uuid4().hex)}"
        alert = SentinelAlert(
            alert_id=alert_id,
            alert_display_name=f"Elastic: {d.get('rule_name', 'Alert')}",
            severity="Medium",
            product_name="Elastic Security",
            vendor_name="Elastic",
            time_generated=now,
        )

        inc_id = f"inc-es-{uuid.uuid4().hex[:12]}"
        incident = SentinelIncident(
            incident_id=inc_id,
            title=alert.alert_display_name,
            description=getattr(alert, "description", alert.alert_display_name),
            severity="Medium",
            status=random.choice(_SENTINEL_STATUSES),
            incident_number=_next_num(),
            created_time_utc=now, last_modified_time_utc=now,
            first_activity_time_utc=now, last_activity_time_utc=now,
            provider_name="Azure Sentinel",
            provider_incident_id=alert_id,
            alert_ids=[alert_id],
            alert_product_names=["Elastic Security"],
            related_analytic_rule_ids=["rule-elastic-alerts"],
            etag=uuid.uuid4().hex[:8],
        )
        alert.incident_id = inc_id
        sentinel_alert_repo.save(alert)
        sentinel_incident_repo.save(incident)


def _seed_from_xdr() -> None:
    """Generate Sentinel incidents from XDR incidents."""
    incidents = store.get_all("xdr_incidents")
    for inc_data in incidents:
        d = asdict(inc_data) if hasattr(inc_data, "__dataclass_fields__") else inc_data.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event_time))

        alert_id = f"xdr-{d.get('incident_id', uuid.uuid4().hex)}"
        alert = SentinelAlert(
            alert_id=alert_id,
            alert_display_name=f"Cortex XDR: {d.get('description', 'Incident')}",
            severity=_map_severity(str(d.get("severity", "medium"))),
            product_name="Palo Alto Cortex XDR",
            vendor_name="Palo Alto Networks",
            time_generated=now,
        )

        inc_id = f"inc-xdr-{uuid.uuid4().hex[:12]}"
        incident = SentinelIncident(
            incident_id=inc_id,
            title=alert.alert_display_name,
            description=getattr(alert, "description", alert.alert_display_name),
            severity=alert.severity,
            status=random.choice(_SENTINEL_STATUSES),
            incident_number=_next_num(),
            created_time_utc=now, last_modified_time_utc=now,
            first_activity_time_utc=now, last_activity_time_utc=now,
            provider_name="Azure Sentinel",
            provider_incident_id=alert_id,
            alert_ids=[alert_id],
            alert_product_names=["Palo Alto Cortex XDR"],
            related_analytic_rule_ids=["rule-xdr-incidents"],
            etag=uuid.uuid4().hex[:8],
        )
        alert.incident_id = inc_id
        sentinel_alert_repo.save(alert)
        sentinel_incident_repo.save(incident)


def _seed_bookmarks() -> None:
    """Create sample investigation bookmarks linked to first few incidents."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    all_inc = sentinel_incident_repo.list_all()[:3]
    for _i, inc in enumerate(all_inc):
        bm = SentinelBookmark(
            bookmark_id=f"bm-{uuid.uuid4().hex[:8]}",
            display_name=f"Investigation note for {inc.title[:40]}",
            notes=f"Initial triage completed. Severity confirmed as {inc.severity}.",
            query=f"SecurityIncident | where IncidentNumber == {inc.incident_number}",
            incident_id=inc.incident_id,
            created=now, updated=now,
            etag=uuid.uuid4().hex[:8],
        )
        sentinel_bookmark_repo.save(bm)
        inc.bookmark_ids.append(bm.bookmark_id)
        sentinel_incident_repo.save(inc)


def _seed_comments() -> None:
    """Add comments to first few incidents."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    all_inc = sentinel_incident_repo.list_all()[:5]
    comments_text = [
        "Initial triage: alert appears legitimate. Escalating to Tier 2.",
        "Contacted asset owner for confirmation.",
        "Running automated enrichment playbook.",
    ]
    for inc in all_inc:
        msg = random.choice(comments_text)
        comment = SentinelIncidentComment(
            comment_id=f"cmt-{uuid.uuid4().hex[:8]}",
            incident_id=inc.incident_id,
            message=msg,
            created_time_utc=now,
            etag=uuid.uuid4().hex[:8],
        )
        sentinel_incident_comment_repo.save(comment)


def _save_entity(kind: str, properties: dict) -> str:
    """Create and persist a Sentinel entity."""
    eid = f"ent-{uuid.uuid4().hex[:12]}"
    entity = SentinelEntity(entity_id=eid, kind=kind, properties=properties)
    sentinel_entity_repo.save(entity)
    return eid


def _map_severity(sev: str) -> str:
    s = sev.lower()
    return {"critical": "High", "high": "High", "medium": "Medium",
            "low": "Low", "informational": "Informational"}.get(s, "Medium")
