"""EDR event seeder — replays existing EDR seed data through the Splunk event bridge.

Reads entities from all 5 EDR vendor repositories and creates Splunk events
with the correct sourcetypes and field schemas.
"""

from __future__ import annotations

import json
import random
from dataclasses import asdict

from application.splunk import edr_shapes as shapes
from domain.splunk.notable_event import NotableEvent
from domain.splunk.splunk_event import SplunkEvent
from repository.splunk.notable_event_repo import notable_event_repo
from repository.splunk.splunk_event_repo import splunk_event_repo
from repository.splunk.splunk_index_repo import splunk_index_repo
from repository.store import store
from utils.id_gen import new_hex, new_uuid

# Fixed reference epoch for deterministic seed data (2023-11-14T22:13:20Z)
_SEED_EPOCH = 1700000000.0


def seed_edr_events() -> None:
    """Replay all existing EDR data into the Splunk event store."""
    _seed_s1_events()
    _seed_cs_events()
    _seed_mde_events()
    _seed_es_events()
    _seed_xdr_events()
    _update_index_counts()


def _seed_s1_events() -> None:
    """Generate Splunk events from SentinelOne entities, as the SentinelOne App indexes them."""
    # Threats → sentinelone:channel:threats
    threats = store.get_all("threats")
    for threat in threats:
        d = asdict(threat) if hasattr(threat, "__dataclass_fields__") else threat.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        d = shapes.s1_threat(d)
        _save_event(shapes.S1_INDEX, shapes.S1_THREATS, shapes.S1_SOURCE, d, event_time)

        # Generate notable for malicious/suspicious threats
        threat_info = d.get("threatInfo", {})
        agent_info = d.get("agentDetectionInfo", {})
        confidence = str(
            threat_info.get("confidenceLevel", threat_info.get("classification", ""))
        ).lower()
        if confidence in ("malicious", "suspicious"):
            _save_notable(
                rule_name="SentinelOne - Threat Detected",
                rule_title="SentinelOne Threat Detected",
                severity="critical" if confidence == "malicious" else "high",
                dest=str(agent_info.get("computerName", agent_info.get("agentComputerName", ""))),
                user=str(threat_info.get("processUser", d.get("username", ""))),
                description=f"Threat: {threat_info.get('threatName', threat_info.get('classification', 'Unknown'))} "
                f"on {agent_info.get('computerName', agent_info.get('agentComputerName', 'Unknown'))}",
                drilldown_search=f"search index=sentinelone sourcetype=sentinelone:channel:threats "
                f'id="{d.get("id", "")}"',
                edr_vendor="sentinelone",
                edr_entity_id=str(d.get("id", "")),
                event_time=event_time,
            )

    # Agents → sentinelone:channel:agents
    agents = store.get_all("agents")
    for agent in agents:
        d = asdict(agent) if hasattr(agent, "__dataclass_fields__") else agent.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 3)
        _save_event(
            shapes.S1_INDEX, shapes.S1_AGENTS, shapes.S1_SOURCE, shapes.s1_agent(d), event_time
        )

    # Activities → sentinelone:channel:activities (sample)
    activities = store.get_all("activities")
    for activity in activities[:20]:
        d = (
            asdict(activity)
            if hasattr(activity, "__dataclass_fields__")
            else activity.__dict__.copy()
        )
        event_time = _SEED_EPOCH - random.uniform(0, 86400)
        _save_event(
            shapes.S1_INDEX,
            shapes.S1_ACTIVITIES,
            shapes.S1_SOURCE,
            shapes.s1_activity(d),
            event_time,
        )


def _seed_cs_events() -> None:
    """Generate Splunk events from CrowdStrike entities, as Event Streams emits them."""
    for det in store.get_all("cs_detections"):
        d = asdict(det) if hasattr(det, "__dataclass_fields__") else det.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        cs_event = shapes.cs_detection(d, event_time)
        _save_event(shapes.CS_INDEX, shapes.CS_SOURCETYPE, shapes.CS_SOURCE, cs_event, event_time)

        severity = cs_event["event"]["Severity"]
        if isinstance(severity, int) and severity >= 50:
            _save_notable(
                rule_name="CrowdStrike - Detection Alert",
                rule_title="CrowdStrike Detection Alert",
                severity=shapes.cs_notable_severity(severity),
                dest=cs_event["event"]["Hostname"],
                user=cs_event["event"]["UserName"],
                description=f"CS Detection: {cs_event['event']['Name'] or 'Unknown'}",
                drilldown_search=f'search index=crowdstrike sourcetype="{shapes.CS_SOURCETYPE}" '
                f'event.CompositeId="{cs_event["event"]["CompositeId"]}"',
                edr_vendor="crowdstrike",
                edr_entity_id=str(cs_event["event"]["CompositeId"]),
                event_time=event_time,
            )

    for inc in store.get_all("cs_incidents"):
        d = asdict(inc) if hasattr(inc, "__dataclass_fields__") else inc.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        _save_event(
            shapes.CS_INDEX,
            shapes.CS_SOURCETYPE,
            shapes.CS_SOURCE,
            shapes.cs_incident(d, event_time),
            event_time,
        )


def _seed_mde_events() -> None:
    """Generate Splunk events from MDE entities, as the Microsoft Security add-on indexes them."""
    alerts = store.get_all("mde_alerts")
    for alert in alerts:
        d = asdict(alert) if hasattr(alert, "__dataclass_fields__") else alert.__dict__.copy()
        d = shapes.mde_alert(d)
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        _save_event(shapes.MDE_INDEX, shapes.MDE_ALERTS, shapes.MDE_SOURCE, d, event_time)

        severity = str(d.get("severity", "")).lower()
        if severity in ("medium", "high", "critical"):
            _save_notable(
                rule_name="Microsoft Defender - Endpoint Alert",
                rule_title="Microsoft Defender Endpoint Alert",
                severity=severity,
                dest=str(d.get("computerDnsName", "")),
                user=str((d.get("relatedUser") or {}).get("userName", "")),
                description=f"MDE Alert: {d.get('title', 'Unknown')}",
                drilldown_search=f'search index=msdefender sourcetype="{shapes.MDE_ALERTS}" '
                f'id="{d.get("id", "")}"',
                edr_vendor="msdefender",
                edr_entity_id=str(d.get("id", "")),
                event_time=event_time,
            )

    machines = store.get_all("mde_machines")
    for machine in machines:
        d = asdict(machine) if hasattr(machine, "__dataclass_fields__") else machine.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 3)
        _save_event(
            shapes.MDE_INDEX,
            shapes.MDE_MACHINES,
            shapes.MDE_SOURCE,
            shapes.mde_machine(d),
            event_time,
        )


def _seed_es_events() -> None:
    """Generate Splunk events from Elastic Security entities."""
    alerts = store.get_all("es_alerts")
    for alert in alerts:
        d = asdict(alert) if hasattr(alert, "__dataclass_fields__") else alert.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        _save_event(
            "elastic_security", "elastic:security:alerts", "elastic:security", d, event_time
        )

        _save_notable(
            rule_name="Elastic Security - Detection Rule Alert",
            rule_title="Elastic Security Detection Rule Alert",
            severity=str(
                d.get("severity", d.get("signal", {}).get("rule", {}).get("severity", "medium"))
            ).lower(),
            dest=str(d.get("host_name", "")),
            user=str(d.get("user_name", "")),
            description=f"Elastic Alert: {d.get('rule_name', d.get('signal', {}).get('rule', {}).get('name', 'Unknown'))}",
            drilldown_search='search index=elastic_security sourcetype="elastic:security:alerts"',
            edr_vendor="elastic",
            edr_entity_id=str(d.get("id", "")),
            event_time=event_time,
        )

    endpoints = store.get_all("es_endpoints")
    for ep in endpoints:
        d = asdict(ep) if hasattr(ep, "__dataclass_fields__") else ep.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 3)
        _save_event(
            "elastic_security", "elastic:security:endpoints", "elastic:security", d, event_time
        )


def _seed_xdr_events() -> None:
    """Generate Splunk events from Cortex XDR entities, as the Palo Alto Networks add-on indexes them."""
    incidents = store.get_all("xdr_incidents")
    for inc in incidents:
        d = asdict(inc) if hasattr(inc, "__dataclass_fields__") else inc.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        d = shapes.xdr_incident(d)
        _save_event(shapes.XDR_INDEX, shapes.XDR_INCIDENTS, shapes.XDR_SOURCE, d, event_time)

        _save_notable(
            rule_name="Cortex XDR - Incident Created",
            rule_title="Cortex XDR Incident Created",
            severity=str(d.get("severity", "medium")).lower(),
            dest=", ".join(d.get("hosts", [])[:3]) if isinstance(d.get("hosts"), list) else "",
            user=", ".join(d.get("users", [])[:3]) if isinstance(d.get("users"), list) else "",
            description=f"XDR Incident: {d.get('description', 'Unknown')}",
            drilldown_search=f'search index=cortex_xdr sourcetype="{shapes.XDR_INCIDENTS}" '
            f'incident_id="{d.get("incident_id", "")}"',
            edr_vendor="cortex_xdr",
            edr_entity_id=str(d.get("incident_id", "")),
            event_time=event_time,
        )

    alerts = store.get_all("xdr_alerts")
    for alert in alerts:
        d = asdict(alert) if hasattr(alert, "__dataclass_fields__") else alert.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        _save_event(
            shapes.XDR_INDEX, shapes.XDR_ALERTS, shapes.XDR_SOURCE, shapes.xdr_alert(d), event_time
        )

    endpoints = store.get_all("xdr_endpoints")
    for ep in endpoints:
        d = asdict(ep) if hasattr(ep, "__dataclass_fields__") else ep.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 3)
        _save_event(
            shapes.XDR_INDEX,
            shapes.XDR_ENDPOINTS,
            shapes.XDR_SOURCE,
            shapes.xdr_endpoint(d),
            event_time,
        )


# ── Helpers ────────────────────────────────────────────────────────────────


def _save_event(index: str, sourcetype: str, source: str, payload: dict, event_time: float) -> None:
    """Create and persist a Splunk event."""
    # Flatten for field extraction
    fields: dict[str, object] = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            for k2, v2 in value.items():
                fields[f"{key}.{k2}"] = v2
        elif not isinstance(value, (list, dict)):
            fields[key] = value

    event = SplunkEvent(
        id=str(new_uuid()),
        index=index,
        sourcetype=sourcetype,
        source=source,
        host="mockdr",
        time=event_time,
        raw=json.dumps(payload, default=str),
        fields=fields,
    )
    splunk_event_repo.save(event)


def _save_notable(
    rule_name: str,
    rule_title: str,
    severity: str,
    dest: str,
    user: str,
    description: str,
    drilldown_search: str,
    edr_vendor: str,
    edr_entity_id: str,
    event_time: float,
) -> None:
    """Create and persist an ES notable event."""
    event_id = f"{new_hex()[:12]}@@notable@@{new_hex()[:12]}"
    time_str = str(event_time)
    notable = NotableEvent(
        event_id=event_id,
        rule_name=rule_name,
        rule_title=rule_title,
        rule_id=str(new_uuid()),
        search_name=rule_name,
        security_domain="endpoint",
        severity=severity,
        urgency=severity,
        src="",
        dest=dest,
        user=user,
        description=description,
        drilldown_search=drilldown_search,
        time=time_str,
        _time=time_str,
        info_min_time=str(event_time - 3600),
        info_max_time=time_str,
        edr_vendor=edr_vendor,
        edr_entity_id=edr_entity_id,
    )
    notable_event_repo.save(notable)


def _update_index_counts() -> None:
    """Update event counts on all indexes."""
    from repository.splunk.splunk_event_repo import splunk_event_repo

    for idx in splunk_index_repo.list_all():
        idx.total_event_count = splunk_event_repo.count_by_index(idx.name)
        splunk_index_repo.save(idx)
