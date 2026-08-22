"""EDR event seeder — replays existing EDR seed data through the Splunk event bridge.

Reads entities from all 5 EDR vendor repositories and creates Splunk events
with the correct sourcetypes and field schemas.
"""

from __future__ import annotations

import json
import random
from dataclasses import asdict
from datetime import datetime

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
    """Generate Splunk events from SentinelOne entities."""
    # Threats → sentinelone:channel:threats
    threats = store.get_all("threats")
    for threat in threats:
        d = asdict(threat) if hasattr(threat, "__dataclass_fields__") else threat.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        _save_event("sentinelone", "sentinelone:channel:threats", "sentinelone:api", d, event_time)

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
        _save_event("sentinelone", "sentinelone:channel:agents", "sentinelone:api", d, event_time)

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
            "sentinelone", "sentinelone:channel:activities", "sentinelone:api", d, event_time
        )


def _seed_cs_events() -> None:
    """Generate Splunk events from CrowdStrike entities, as Event Streams emits them.

    The shapes are the ones recorded from the Falcon Event Streams API
    (``data/vendor-specs/cs_event_streams_reduced.json``): a detection is an
    ``EppDetectionSummaryEvent`` (the current type; ``DetectionSummaryEvent``
    is the legacy one), an incident an ``IncidentSummaryEvent`` with exactly
    nine fields. This used to dump the mock's whole incident model.
    """
    detections = store.get_all("cs_detections")
    for det in detections:
        d = asdict(det) if hasattr(det, "__dataclass_fields__") else det.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        behavior = (d.get("behaviors") or [{}])[0]
        device = d.get("device") or {}
        parent = behavior.get("parent_details") or {}
        disposition = behavior.get("pattern_disposition_details") or {}
        severity = d.get("max_severity", 50)
        composite_id = d.get("composite_id", "")
        cs_event = {
            "metadata": {
                "customerIDString": "3061c7ff3b634e22b38274d4b586558e",
                "offset": int(event_time * 1000),
                "eventType": "EppDetectionSummaryEvent",
                "eventCreationTime": int(event_time * 1000),
                "version": "1.0",
            },
            "event": {
                "AgentId": device.get("device_id", ""),
                "AggregateId": f"aggind:{device.get('device_id', '')}:{int(event_time)}",
                "CompositeId": composite_id,
                "Hostname": device.get("hostname", ""),
                "UserName": behavior.get("user_name", ""),
                "LogonDomain": device.get("machine_domain", ""),
                "LocalIP": device.get("local_ip", ""),
                "LocalIPv6": "",
                "MACAddress": device.get("mac_address", ""),
                "HostGroups": ",".join(device.get("groups") or []),
                "Name": behavior.get("scenario", "NGAV"),
                "Description": behavior.get("description", behavior.get("display_name", "")),
                "Objective": behavior.get("objective", "Falcon Detection Method"),
                "Tactic": behavior.get("tactic", ""),
                "Technique": behavior.get("technique", ""),
                "Severity": severity,
                "SeverityName": d.get("max_severity_displayname", "Medium"),
                "FileName": behavior.get("filename", ""),
                "FilePath": behavior.get("filepath", ""),
                "AssociatedFile": behavior.get("filepath", ""),
                "CommandLine": behavior.get("cmdline", ""),
                "SHA256String": behavior.get("sha256", ""),
                "MD5String": behavior.get("md5", ""),
                "SHA1String": behavior.get("sha1", "0" * 40),
                "IOCType": behavior.get("ioc_type", ""),
                "IOCValue": behavior.get("ioc_value", ""),
                "ParentCommandLine": parent.get("parent_cmdline", ""),
                "ParentImageFileName": parent.get("parent_cmdline", "")
                .split("\\")[-1]
                .split(" ")[0],
                "ParentProcessId": parent.get("parent_process_graph_id", ""),
                "ProcessId": behavior.get("control_graph_id", ""),
                "ProcessStartTime": int(event_time),
                "ProcessEndTime": int(event_time),
                "PatternDispositionDescription": behavior.get(
                    "pattern_disposition_description", ""
                ),
                "PatternDispositionFlags": {
                    "Indicator": bool(disposition.get("indicator", False)),
                    "Detect": bool(disposition.get("detect", False)),
                    "InddetMask": bool(disposition.get("inddet_mask", False)),
                    "SensorOnly": bool(disposition.get("sensor_only", False)),
                    "Rooting": bool(disposition.get("rooting", False)),
                    "KillProcess": bool(disposition.get("kill_process", False)),
                    "KillSubProcess": bool(disposition.get("kill_subprocess", False)),
                    "QuarantineMachine": bool(disposition.get("quarantine_machine", False)),
                    "QuarantineFile": bool(disposition.get("quarantine_file", False)),
                    "PolicyDisabled": bool(disposition.get("policy_disabled", False)),
                    "KillParent": bool(disposition.get("kill_parent", False)),
                    "OperationBlocked": bool(disposition.get("operation_blocked", False)),
                    "ProcessBlocked": bool(disposition.get("process_blocked", False)),
                },
                "PatternDispositionValue": behavior.get("pattern_disposition", 0),
                "PatternId": behavior.get("pattern_id", 0),
                "Type": "ldt",
                "DataDomains": "Endpoint",
                "SourceProducts": "Falcon Insight",
                "SourceVendors": "CrowdStrike",
                "FalconHostLink": f"https://falcon.crowdstrike.com/activity-v2/detections/{composite_id}",
            },
        }
        _save_event(
            "crowdstrike",
            "CrowdStrike:Event:Streams:JSON",
            "CrowdStrike:Event:Streams",
            cs_event,
            event_time,
        )

        if isinstance(severity, int) and severity >= 50:
            _save_notable(
                rule_name="CrowdStrike - Detection Alert",
                rule_title="CrowdStrike Detection Alert",
                severity="critical" if severity >= 90 else "high" if severity >= 70 else "medium",
                dest=device.get("hostname", ""),
                user=behavior.get("user_name", ""),
                description=f"CS Detection: {behavior.get('scenario', 'Unknown')}",
                drilldown_search='search index=crowdstrike sourcetype="CrowdStrike:Event:Streams:JSON"',
                edr_vendor="crowdstrike",
                edr_entity_id=str(composite_id),
                event_time=event_time,
            )

    incidents = store.get_all("cs_incidents")
    for inc in incidents:
        d = asdict(inc) if hasattr(inc, "__dataclass_fields__") else inc.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        host_ids = d.get("host_ids") or []
        cs_event = {
            "metadata": {
                "customerIDString": "3061c7ff3b634e22b38274d4b586558e",
                "offset": int(event_time * 1000),
                "eventType": "IncidentSummaryEvent",
                "eventCreationTime": int(event_time * 1000),
                "version": "1.0",
            },
            "event": {
                "IncidentID": d.get("incident_id", ""),
                "HostID": host_ids[0] if host_ids else "",
                "IncidentStartTime": _epoch(d.get("start")) or int(event_time),
                "IncidentEndTime": _epoch(d.get("end")) or int(event_time),
                "FineScore": d.get("fine_score", 0),
                "State": d.get("state", "open"),
                "IncidentType": 1,
                "LateralMovement": 1 if d.get("lm_host_ids") else 0,
                "FalconHostLink": f"https://falcon.crowdstrike.com/crowdscore/incidents/details/{d.get('incident_id', '')}",
            },
        }
        _save_event(
            "crowdstrike",
            "CrowdStrike:Event:Streams:JSON",
            "CrowdStrike:Event:Streams",
            cs_event,
            event_time,
        )


def _epoch(value: object) -> int:
    """An ISO-8601 timestamp (or epoch) as whole epoch seconds; 0 when absent."""
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value:
        try:
            return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
        except ValueError:
            return 0
    return 0


def _seed_mde_events() -> None:
    """Generate Splunk events from MDE entities."""
    alerts = store.get_all("mde_alerts")
    for alert in alerts:
        d = asdict(alert) if hasattr(alert, "__dataclass_fields__") else alert.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        _save_event(
            "msdefender", "ms:defender:endpoint:alerts", "ms:defender:endpoint", d, event_time
        )

        severity = str(d.get("severity", "")).lower()
        if severity in ("medium", "high", "critical"):
            _save_notable(
                rule_name="Microsoft Defender - Endpoint Alert",
                rule_title="Microsoft Defender Endpoint Alert",
                severity=severity,
                dest=str(d.get("computerDnsName", d.get("machine_id", ""))),
                user=str(d.get("user_name", "")),
                description=f"MDE Alert: {d.get('title', d.get('alert_name', 'Unknown'))}",
                drilldown_search='search index=msdefender sourcetype="ms:defender:endpoint:alerts"',
                edr_vendor="msdefender",
                edr_entity_id=str(d.get("alertId", d.get("id", ""))),
                event_time=event_time,
            )

    machines = store.get_all("mde_machines")
    for machine in machines:
        d = asdict(machine) if hasattr(machine, "__dataclass_fields__") else machine.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 3)
        _save_event(
            "msdefender", "ms:defender:endpoint:machines", "ms:defender:endpoint", d, event_time
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
    """Generate Splunk events from Cortex XDR entities."""
    incidents = store.get_all("xdr_incidents")
    for inc in incidents:
        d = asdict(inc) if hasattr(inc, "__dataclass_fields__") else inc.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        _save_event("cortex_xdr", "pan:xdr:incidents", "pan:xdr", d, event_time)

        _save_notable(
            rule_name="Cortex XDR - Incident Created",
            rule_title="Cortex XDR Incident Created",
            severity=str(d.get("severity", "medium")).lower(),
            dest=", ".join(d.get("hosts", [])[:3]) if isinstance(d.get("hosts"), list) else "",
            user=", ".join(d.get("users", [])[:3]) if isinstance(d.get("users"), list) else "",
            description=f"XDR Incident: {d.get('description', 'Unknown')}",
            drilldown_search='search index=cortex_xdr sourcetype="pan:xdr:incidents"',
            edr_vendor="cortex_xdr",
            edr_entity_id=str(d.get("incident_id", "")),
            event_time=event_time,
        )

    alerts = store.get_all("xdr_alerts")
    for alert in alerts:
        d = asdict(alert) if hasattr(alert, "__dataclass_fields__") else alert.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 7)
        _save_event("cortex_xdr", "pan:xdr:alerts", "pan:xdr", d, event_time)

    endpoints = store.get_all("xdr_endpoints")
    for ep in endpoints:
        d = asdict(ep) if hasattr(ep, "__dataclass_fields__") else ep.__dict__.copy()
        event_time = _SEED_EPOCH - random.uniform(0, 86400 * 3)
        _save_event("cortex_xdr", "pan:xdr:endpoints", "pan:xdr", d, event_time)


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
