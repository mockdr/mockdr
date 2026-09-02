"""EDR-to-Splunk event bridge.

Subscribes to domain events from all 5 EDR vendors and creates
corresponding Splunk events with the correct sourcetypes, indexes,
and field schemas that match the real Splunk add-ons.

Also generates ES notable events for high-severity items.
"""
from __future__ import annotations

import json
import time
import uuid

from application.splunk import edr_shapes as shapes
from domain.event_bus import (
    DomainEvent,
    event_bus,
)
from domain.splunk.notable_event import NotableEvent
from domain.splunk.splunk_event import SplunkEvent
from repository.splunk.notable_event_repo import notable_event_repo
from repository.splunk.splunk_event_repo import splunk_event_repo


def register_bridge() -> None:
    """Register event bus subscribers for EDR-to-Splunk bridging."""
    event_bus.subscribe("threat_created", _handle_s1_threat)
    event_bus.subscribe("cs_detection_created", _handle_cs_detection)
    event_bus.subscribe("cs_incident_created", _handle_cs_incident)
    event_bus.subscribe("mde_alert_created", _handle_mde_alert)
    event_bus.subscribe("mde_machine_updated", _handle_mde_machine)
    event_bus.subscribe("es_alert_created", _handle_es_alert)
    event_bus.subscribe("xdr_incident_created", _handle_xdr_incident)
    event_bus.subscribe("xdr_alert_created", _handle_xdr_alert)
    event_bus.subscribe("xdr_endpoint_updated", _handle_xdr_endpoint)
    event_bus.subscribe("agent_updated", _handle_s1_agent_updated)
    event_bus.subscribe("activity_created", _handle_s1_activity)


# ── SentinelOne ────────────────────────────────────────────────────────────

def _handle_s1_threat(event: DomainEvent) -> None:
    """Bridge S1 threat to Splunk event + notable."""
    payload = shapes.s1_threat(event.payload)
    _create_splunk_event(
        index=shapes.S1_INDEX,
        sourcetype=shapes.S1_THREATS,
        source=shapes.S1_SOURCE,
        payload=payload,
        event_time=event.timestamp,
    )
    # Generate notable for suspicious+ threats
    severity = str(payload.get("threatInfo", {}).get("confidenceLevel", "")).lower()
    if severity in ("suspicious", "malicious"):
        _create_notable(
            rule_name="SentinelOne - Threat Detected",
            rule_title="SentinelOne Threat Detected",
            security_domain="endpoint",
            severity=_map_s1_severity(severity),
            src=str(
                payload.get("agentRealtimeInfo", {}).get(
                    "agentNetworkInfo", {},
                ).get("agentIpV4", ""),
            ),
            dest=str(payload.get("agentRealtimeInfo", {}).get(
                "agentComputerName", "",
            )),
            user=str(payload.get("threatInfo", {}).get("processUser", "")),
            description=(
                f"Threat detected: "
                f"{payload.get('threatInfo', {}).get('threatName', 'Unknown')} "
                f"on {payload.get('agentRealtimeInfo', {}).get('agentComputerName', 'Unknown')}"
            ),
            drilldown_search=(
                f"search index=sentinelone "
                f"sourcetype=sentinelone:channel:threats "
                f'threatInfo.threatId="{payload.get("threatInfo", {}).get("threatId", "")}"'
            ),
            edr_vendor="sentinelone",
            edr_entity_id=str(payload.get("id", event.entity_id)),
            event_time=event.timestamp,
        )


def _handle_s1_agent_updated(event: DomainEvent) -> None:
    """Bridge S1 agent status change to Splunk event."""
    _create_splunk_event(
        index=shapes.S1_INDEX,
        sourcetype=shapes.S1_AGENTS,
        source=shapes.S1_SOURCE,
        payload=shapes.s1_agent(event.payload),
        event_time=event.timestamp,
    )


def _handle_s1_activity(event: DomainEvent) -> None:
    """Bridge S1 activity log entry to Splunk event."""
    _create_splunk_event(
        index=shapes.S1_INDEX,
        sourcetype=shapes.S1_ACTIVITIES,
        source=shapes.S1_SOURCE,
        payload=shapes.s1_activity(event.payload),
        event_time=event.timestamp,
    )


def _map_s1_severity(confidence: str) -> str:
    """Map S1 confidence to Splunk severity."""
    return {"malicious": "critical", "suspicious": "high"}.get(confidence, "medium")


# ── CrowdStrike ────────────────────────────────────────────────────────────

def _handle_cs_detection(event: DomainEvent) -> None:
    """Bridge a CS detection as the ``EppDetectionSummaryEvent`` Event Streams emits."""
    cs_event = shapes.cs_detection(event.payload, event.timestamp)
    _create_splunk_event(
        index=shapes.CS_INDEX,
        sourcetype=shapes.CS_SOURCETYPE,
        source=shapes.CS_SOURCE,
        payload=cs_event,
        event_time=event.timestamp,
    )
    fields = cs_event["event"]
    severity = fields["Severity"]
    if isinstance(severity, int) and severity >= 50:
        _create_notable(
            rule_name="CrowdStrike - Detection Alert",
            rule_title="CrowdStrike Detection Alert",
            security_domain="endpoint",
            severity=shapes.cs_notable_severity(severity),
            src="",
            dest=str(fields["Hostname"]),
            user=str(fields["UserName"]),
            description=(
                f"CS Detection: {fields['Name'] or 'Unknown'} on {fields['Hostname'] or 'Unknown'}"
            ),
            drilldown_search=(
                f'search index=crowdstrike sourcetype="{shapes.CS_SOURCETYPE}" '
                f'event.CompositeId="{fields["CompositeId"]}"'
            ),
            edr_vendor="crowdstrike",
            edr_entity_id=str(fields["CompositeId"] or event.entity_id),
            event_time=event.timestamp,
        )


def _handle_cs_incident(event: DomainEvent) -> None:
    """Bridge a CS incident as the ``IncidentSummaryEvent`` Event Streams emits."""
    _create_splunk_event(
        index=shapes.CS_INDEX,
        sourcetype=shapes.CS_SOURCETYPE,
        source=shapes.CS_SOURCE,
        payload=shapes.cs_incident(event.payload, event.timestamp),
        event_time=event.timestamp,
    )


# ── Microsoft Defender ─────────────────────────────────────────────────────

def _handle_mde_alert(event: DomainEvent) -> None:
    """Bridge MDE alert to Splunk event + notable."""
    payload = shapes.mde_alert(event.payload)
    _create_splunk_event(
        index=shapes.MDE_INDEX,
        sourcetype=shapes.MDE_ALERTS,
        source=shapes.MDE_SOURCE,
        payload=payload,
        event_time=event.timestamp,
    )
    severity = str(payload.get("severity", "")).lower()
    if severity in ("medium", "high", "critical"):
        _create_notable(
            rule_name="Microsoft Defender - Endpoint Alert",
            rule_title="Microsoft Defender Endpoint Alert",
            security_domain="endpoint",
            severity=severity,
            src="",
            dest=str(payload.get("computerDnsName", "")),
            user=str(payload.get("relatedUser", {}).get("userName", "")),
            description=f"MDE Alert: {payload.get('title', 'Unknown')} "
                        f"on {payload.get('computerDnsName', 'Unknown')}",
            drilldown_search=f'search index=msdefender sourcetype="{shapes.MDE_ALERTS}" '
                             f'id="{payload.get("id", "")}"',
            edr_vendor="msdefender",
            edr_entity_id=str(payload.get("id", event.entity_id)),
            event_time=event.timestamp,
        )


def _handle_mde_machine(event: DomainEvent) -> None:
    """Bridge MDE machine update to Splunk event."""
    _create_splunk_event(
        index=shapes.MDE_INDEX,
        sourcetype=shapes.MDE_MACHINES,
        source=shapes.MDE_SOURCE,
        payload=shapes.mde_machine(event.payload),
        event_time=event.timestamp,
    )


# ── Elastic Security ──────────────────────────────────────────────────────

def _handle_es_alert(event: DomainEvent) -> None:
    """Bridge Elastic alert to Splunk event + notable."""
    payload = event.payload
    _create_splunk_event(
        index="elastic_security",
        sourcetype="elastic:security:alerts",
        source="elastic:security",
        payload=payload,
        event_time=event.timestamp,
    )
    _create_notable(
        rule_name="Elastic Security - Detection Rule Alert",
        rule_title="Elastic Security Detection Rule Alert",
        security_domain="endpoint",
        severity=str(payload.get("kibana.alert.severity", "medium")).lower(),
        src="",
        dest=str(payload.get("host.name", "")),
        user=str(payload.get("user.name", "")),
        description=f"Elastic Alert: {payload.get('kibana.alert.rule.name', 'Unknown')}",
        drilldown_search=f'search index=elastic_security sourcetype="elastic:security:alerts" '
                         f'kibana.alert.uuid="{payload.get("kibana.alert.uuid", "")}"',
        edr_vendor="elastic",
        edr_entity_id=str(payload.get("kibana.alert.uuid", event.entity_id)),
        event_time=event.timestamp,
    )


# ── Cortex XDR ─────────────────────────────────────────────────────────────

def _handle_xdr_incident(event: DomainEvent) -> None:
    """Bridge XDR incident to Splunk event + notable."""
    payload = shapes.xdr_incident(event.payload)
    _create_splunk_event(
        index=shapes.XDR_INDEX,
        sourcetype=shapes.XDR_INCIDENTS,
        source=shapes.XDR_SOURCE,
        payload=payload,
        event_time=event.timestamp,
    )
    _create_notable(
        rule_name="Cortex XDR - Incident Created",
        rule_title="Cortex XDR Incident Created",
        security_domain="endpoint",
        severity=str(payload.get("severity", "medium")).lower(),
        src="",
        dest=", ".join(payload.get("hosts", [])[:3]),
        user=", ".join(payload.get("users", [])[:3]),
        description=f"XDR Incident: {payload.get('description', 'Unknown')}",
        drilldown_search=f'search index=cortex_xdr sourcetype="{shapes.XDR_INCIDENTS}" '
                         f'incident_id="{payload.get("incident_id", "")}"',
        edr_vendor="cortex_xdr",
        edr_entity_id=str(payload.get("incident_id", event.entity_id)),
        event_time=event.timestamp,
    )


def _handle_xdr_alert(event: DomainEvent) -> None:
    """Bridge XDR alert to Splunk event."""
    _create_splunk_event(
        index=shapes.XDR_INDEX,
        sourcetype=shapes.XDR_ALERTS,
        source=shapes.XDR_SOURCE,
        payload=shapes.xdr_alert(event.payload),
        event_time=event.timestamp,
    )


def _handle_xdr_endpoint(event: DomainEvent) -> None:
    """Bridge a Cortex XDR endpoint state change to Splunk."""
    _create_splunk_event(
        index=shapes.XDR_INDEX,
        sourcetype=shapes.XDR_ENDPOINTS,
        source=shapes.XDR_SOURCE,
        payload=shapes.xdr_endpoint(event.payload),
        event_time=event.timestamp,
    )


# ── Helpers ────────────────────────────────────────────────────────────────

def _create_splunk_event(
    index: str,
    sourcetype: str,
    source: str,
    payload: dict,
    event_time: float = 0.0,
) -> None:
    """Create and persist a Splunk event."""
    if not event_time:
        event_time = time.time()
    event = SplunkEvent(
        id=str(uuid.uuid4()),
        index=index,
        sourcetype=sourcetype,
        source=source,
        host="mockdr",
        time=event_time,
        raw=json.dumps(payload),
        fields=_flatten_dict(payload),
    )
    splunk_event_repo.save(event)


def _create_notable(
    rule_name: str,
    rule_title: str,
    security_domain: str,
    severity: str,
    src: str,
    dest: str,
    user: str,
    description: str,
    drilldown_search: str,
    edr_vendor: str,
    edr_entity_id: str,
    event_time: float = 0.0,
) -> None:
    """Create and persist an ES notable event."""
    if not event_time:
        event_time = time.time()
    event_id = f"{uuid.uuid4().hex[:12]}@@notable@@{uuid.uuid4().hex[:12]}"
    time_str = str(event_time)

    notable = NotableEvent(
        event_id=event_id,
        rule_name=rule_name,
        rule_title=rule_title,
        rule_id=str(uuid.uuid4()),
        search_name=rule_name,
        security_domain=security_domain,
        severity=severity,
        urgency=severity,
        status="1",
        status_label="New",
        owner="unassigned",
        src=src,
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


def _flatten_dict(d: dict, prefix: str = "") -> dict[str, object]:
    """Flatten a nested dict for field extraction (max depth 2)."""
    result: dict[str, object] = {}
    for key, value in d.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            result.update(_flatten_dict(value, full_key))
        elif isinstance(value, list):
            result[full_key] = value
        else:
            result[full_key] = value
    return result
