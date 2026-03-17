"""EDR-to-Sentinel event bridge.

Subscribes to domain events from all 5 EDR vendors and creates
Sentinel alerts + incidents with entity extraction. MDE alerts
use the M365 Defender provider (native integration); all others
use Azure Sentinel with scheduled analytics rules.
"""
from __future__ import annotations

import uuid

from application.sentinel.commands.incidents import next_incident_number
from domain.event_bus import DomainEvent, event_bus
from domain.sentinel.alert import SentinelAlert
from domain.sentinel.entity import SentinelEntity
from domain.sentinel.incident import SentinelIncident
from repository.sentinel.alert_repo import sentinel_alert_repo
from repository.sentinel.entity_repo import sentinel_entity_repo
from repository.sentinel.incident_repo import sentinel_incident_repo
from utils.dt import utc_now

_MITRE_TACTIC_MAP: dict[str, str] = {
    "TA0001": "InitialAccess", "TA0002": "Execution",
    "TA0003": "Persistence", "TA0004": "PrivilegeEscalation",
    "TA0005": "DefenseEvasion", "TA0006": "CredentialAccess",
    "TA0007": "Discovery", "TA0008": "LateralMovement",
    "TA0009": "Collection", "TA0010": "Exfiltration",
    "TA0011": "CommandAndControl", "TA0040": "Impact",
}


def register_sentinel_bridge() -> None:
    """Register event bus subscribers for EDR-to-Sentinel bridging."""
    event_bus.subscribe("mde_alert_created", _handle_mde_alert)
    event_bus.subscribe("threat_created", _handle_s1_threat)
    event_bus.subscribe("cs_detection_created", _handle_cs_detection)
    event_bus.subscribe("es_alert_created", _handle_es_alert)
    event_bus.subscribe("xdr_incident_created", _handle_xdr_incident)
    event_bus.subscribe("xdr_alert_created", _handle_xdr_alert)
    event_bus.subscribe("mde_machine_updated", _handle_mde_machine)


# ── MDE → Sentinel (M365 Defender native integration) ─────────────────────

def _handle_mde_alert(event: DomainEvent) -> None:
    """Bridge MDE alert to Sentinel alert + incident (M365 Defender provider)."""
    payload = event.payload
    alert_id = str(payload.get("alertId", payload.get("id", uuid.uuid4().hex)))
    now = utc_now()

    # Extract entities from MDE alert
    entity_ids = _extract_entities_from_payload(payload, "mde")

    # Create Sentinel alert
    alert = SentinelAlert(
        alert_id=alert_id,
        alert_display_name=str(payload.get("title", payload.get("alert_name", "MDE Alert"))),
        description=str(payload.get("description", "")),
        severity=_map_mde_severity(str(payload.get("severity", "Medium"))),
        product_name="Microsoft Defender for Endpoint",
        vendor_name="Microsoft",
        tactics=_extract_tactics(payload),
        techniques=_extract_techniques(payload),
        time_generated=now,
        entity_ids=entity_ids,
    )

    # Find or create incident
    incident = _find_or_create_incident(
        alert=alert,
        provider_name="Microsoft 365 Defender",
        alert_product_names=["Microsoft Defender for Endpoint"],
        entity_ids=entity_ids,
    )
    alert.incident_id = incident.incident_id
    sentinel_alert_repo.save(alert)


def _handle_mde_machine(event: DomainEvent) -> None:
    """Bridge MDE machine update — create/update Host entity."""
    payload = event.payload
    hostname = str(payload.get("computerDnsName", payload.get("machineName", "")))
    if hostname:
        _create_entity("Host", {
            "hostName": hostname,
            "osMajorVersion": str(payload.get("osPlatform", "")),
            "osFamily": str(payload.get("osPlatform", "")),
        })


# ── SentinelOne → Sentinel ─────────────────────────────────────────────────

def _handle_s1_threat(event: DomainEvent) -> None:
    """Bridge S1 threat to Sentinel alert + incident."""
    payload = event.payload
    threat_info = payload.get("threatInfo", {})
    alert_id = f"s1-{payload.get('id', uuid.uuid4().hex)}"
    now = utc_now()

    entity_ids = _extract_entities_from_payload(payload, "s1")

    alert = SentinelAlert(
        alert_id=alert_id,
        alert_display_name=f"SentinelOne: {threat_info.get('threatName', 'Threat Detected')}",
        description=str(threat_info.get('classification', '')),
        severity=_map_s1_severity(str(threat_info.get("confidenceLevel", "suspicious"))),
        product_name="SentinelOne",
        vendor_name="SentinelOne",
        time_generated=now,
        entity_ids=entity_ids,
    )

    incident = _find_or_create_incident(
        alert=alert,
        provider_name="Azure Sentinel",
        alert_product_names=["SentinelOne"],
        entity_ids=entity_ids,
    )
    alert.incident_id = incident.incident_id
    sentinel_alert_repo.save(alert)


# ── CrowdStrike → Sentinel ─────────────────────────────────────────────────

def _handle_cs_detection(event: DomainEvent) -> None:
    """Bridge CS detection to Sentinel alert + incident."""
    payload = event.payload
    alert_id = f"cs-{payload.get('detection_id', uuid.uuid4().hex)}"
    now = utc_now()

    entity_ids = _extract_entities_from_payload(payload, "cs")

    alert = SentinelAlert(
        alert_id=alert_id,
        alert_display_name=f"CrowdStrike: {payload.get('detect_name', 'Detection')}",
        description=str(payload.get("detect_description", "")),
        severity=_map_cs_severity(payload.get("max_severity", 3)),
        product_name="CrowdStrike Falcon",
        vendor_name="CrowdStrike",
        time_generated=now,
        entity_ids=entity_ids,
    )

    incident = _find_or_create_incident(
        alert=alert,
        provider_name="Azure Sentinel",
        alert_product_names=["CrowdStrike Falcon"],
        entity_ids=entity_ids,
    )
    alert.incident_id = incident.incident_id
    sentinel_alert_repo.save(alert)


# ── Elastic Security → Sentinel ────────────────────────────────────────────

def _handle_es_alert(event: DomainEvent) -> None:
    """Bridge Elastic alert to Sentinel alert + incident."""
    payload = event.payload
    alert_id = f"es-{payload.get('id', uuid.uuid4().hex)}"
    now = utc_now()

    entity_ids = _extract_entities_from_payload(payload, "es")

    alert = SentinelAlert(
        alert_id=alert_id,
        alert_display_name="Elastic: {}".format(
            payload.get("rule_name", payload.get("signal", {}).get(
                "rule", {},
            ).get("name", "Alert")),
        ),
        description=str(payload.get("description", "")),
        severity=_map_generic_severity(str(payload.get("severity", "medium"))),
        product_name="Elastic Security",
        vendor_name="Elastic",
        time_generated=now,
        entity_ids=entity_ids,
    )

    incident = _find_or_create_incident(
        alert=alert,
        provider_name="Azure Sentinel",
        alert_product_names=["Elastic Security"],
        entity_ids=entity_ids,
    )
    alert.incident_id = incident.incident_id
    sentinel_alert_repo.save(alert)


# ── Cortex XDR → Sentinel ──────────────────────────────────────────────────

def _handle_xdr_incident(event: DomainEvent) -> None:
    """Bridge XDR incident to Sentinel alert + incident."""
    payload = event.payload
    alert_id = f"xdr-inc-{payload.get('incident_id', uuid.uuid4().hex)}"
    now = utc_now()

    entity_ids = _extract_entities_from_payload(payload, "xdr")

    alert = SentinelAlert(
        alert_id=alert_id,
        alert_display_name=f"Cortex XDR: {payload.get('description', 'Incident')}",
        description=str(payload.get("description", "")),
        severity=_map_generic_severity(str(payload.get("severity", "medium"))),
        product_name="Palo Alto Cortex XDR",
        vendor_name="Palo Alto Networks",
        time_generated=now,
        entity_ids=entity_ids,
    )

    incident = _find_or_create_incident(
        alert=alert,
        provider_name="Azure Sentinel",
        alert_product_names=["Palo Alto Cortex XDR"],
        entity_ids=entity_ids,
    )
    alert.incident_id = incident.incident_id
    sentinel_alert_repo.save(alert)


def _handle_xdr_alert(event: DomainEvent) -> None:
    """Bridge XDR alert — attach to existing incident if possible."""
    payload = event.payload
    alert_id = f"xdr-{payload.get('alert_id', uuid.uuid4().hex)}"
    now = utc_now()

    alert = SentinelAlert(
        alert_id=alert_id,
        alert_display_name=str(payload.get("name", "XDR Alert")),
        description=str(payload.get("description", "")),
        severity=_map_generic_severity(str(payload.get("severity", "medium"))),
        product_name="Palo Alto Cortex XDR",
        vendor_name="Palo Alto Networks",
        time_generated=now,
    )
    sentinel_alert_repo.save(alert)


# ── Helpers ────────────────────────────────────────────────────────────────

def _find_or_create_incident(
    alert: SentinelAlert,
    provider_name: str,
    alert_product_names: list[str],
    entity_ids: list[str] | None = None,
) -> SentinelIncident:
    """Find an existing open incident for this product or create a new one."""
    now = utc_now()
    incident_id = f"inc-{uuid.uuid4().hex[:16]}"
    number = next_incident_number()

    incident = SentinelIncident(
        incident_id=incident_id,
        title=alert.alert_display_name,
        description=alert.description,
        severity=alert.severity,
        status="New",
        incident_number=number,
        created_time_utc=now,
        last_modified_time_utc=now,
        first_activity_time_utc=now,
        last_activity_time_utc=now,
        provider_name=provider_name,
        provider_incident_id=alert.alert_id,
        alert_ids=[alert.alert_id],
        entity_ids=entity_ids or [],
        alert_product_names=alert_product_names,
        tactics=alert.tactics,
        techniques=alert.techniques,
        etag=uuid.uuid4().hex[:8],
    )
    sentinel_incident_repo.save(incident)
    return incident


def _extract_entities_from_payload(payload: dict, vendor: str) -> list[str]:
    """Extract entities from an EDR event payload."""
    entities: list[str] = []

    # Host entity
    hostname = ""
    if vendor == "mde":
        hostname = str(payload.get("computerDnsName", payload.get("machineName", "")))
    elif vendor == "s1":
        agent_info = payload.get("agentDetectionInfo", payload.get("agentRealtimeInfo", {}))
        hostname = str(agent_info.get("agentComputerName", agent_info.get("computerName", "")))
    elif vendor == "cs":
        hostname = str(payload.get("hostname", payload.get("device", {}).get("hostname", "")))
    elif vendor == "es":
        hostname = str(payload.get("host_name", ""))
    elif vendor == "xdr":
        hosts = payload.get("hosts", [])
        hostname = hosts[0] if hosts else str(payload.get("host_name", ""))

    if hostname:
        eid = _create_entity("Host", {"hostName": hostname})
        entities.append(eid)

    # Account entity
    username = ""
    if vendor == "mde":
        user_info = payload.get("relatedUser", {})
        username = str(user_info.get("userName", "")) if isinstance(user_info, dict) else ""
    elif vendor == "s1":
        threat_info = payload.get("threatInfo", {})
        username = str(threat_info.get("processUser", ""))
    elif vendor == "cs":
        username = str(payload.get("user_name", ""))
    elif vendor == "xdr":
        users = payload.get("users", [])
        username = users[0] if users else str(payload.get("user_name", ""))

    if username:
        eid = _create_entity("Account", {"accountName": username})
        entities.append(eid)

    # IP entity
    ip_addr = ""
    if vendor == "mde":
        ip_addr = str(payload.get("machineIp", ""))
    elif vendor == "cs":
        ip_addr = str(payload.get("local_ip", ""))

    if ip_addr:
        eid = _create_entity("Ip", {"address": ip_addr})
        entities.append(eid)

    return entities


def _create_entity(kind: str, properties: dict) -> str:
    """Create and persist a Sentinel entity, return its ID."""
    entity_id = f"ent-{uuid.uuid4().hex[:12]}"
    entity = SentinelEntity(
        entity_id=entity_id,
        kind=kind,
        properties=properties,
    )
    sentinel_entity_repo.save(entity)
    return entity_id


def _extract_tactics(payload: dict) -> list[str]:
    """Extract MITRE tactics from a payload."""
    tactics = []
    mitre = payload.get("mitreTechniques", payload.get("threatInfo", {}).get("mitreTechniques", []))
    if isinstance(mitre, list):
        for tech in mitre:
            tactic_id = str(tech).split(".")[0] if "." in str(tech) else ""
            tactic = _MITRE_TACTIC_MAP.get(tactic_id, "")
            if tactic and tactic not in tactics:
                tactics.append(tactic)
    return tactics or ["Execution"]


def _extract_techniques(payload: dict) -> list[str]:
    """Extract MITRE techniques from a payload."""
    mitre = payload.get("mitreTechniques", [])
    if isinstance(mitre, list):
        return [str(t) for t in mitre[:5]]
    return []


def _map_mde_severity(severity: str) -> str:
    """Map MDE severity to Sentinel severity."""
    return {"informational": "Informational", "low": "Low", "medium": "Medium",
            "high": "High", "critical": "High"}.get(severity.lower(), "Medium")


def _map_s1_severity(confidence: str) -> str:
    return {"malicious": "High", "suspicious": "Medium"}.get(confidence.lower(), "Medium")


def _map_cs_severity(severity: object) -> str:
    sev = int(severity) if isinstance(severity, (int, float)) else 3
    if sev >= 5:
        return "High"
    if sev >= 3:
        return "Medium"
    return "Low"


def _map_generic_severity(severity: str) -> str:
    return {"critical": "High", "high": "High", "medium": "Medium",
            "low": "Low", "informational": "Informational"}.get(severity.lower(), "Medium")
