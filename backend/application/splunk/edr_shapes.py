"""EDR records as the vendors' Splunk add-ons index them.

Each add-on polls the product's list API and writes every returned object
as one event, so a bridge event must be the API serialization of the
record — the shape the mock's list route answers — under the add-on's
sourcetype:

- SentinelOne App for Splunk (Splunkbase 5433): ``sentinelone:channel:threats``,
  ``sentinelone:channel:agents``, ``sentinelone:channel:activities`` from
  ``/threats``, ``/agents``, ``/activities``.
- Splunk Add-on for Microsoft Security (Splunkbase 6207):
  ``ms:defender:atp:alerts`` from ``/api/alerts`` (evidence expanded, as
  recorded in ``splunk/attack_data`` ``defender_atp_alerts.log``) and
  ``ms:defender:machines`` from ``/api/machines``.
- Splunk Add-on for Palo Alto Networks (Splunkbase 7523): ``pan:xdr:incident``
  from ``incidents/get_incidents``, ``pan:xdr:alert`` and ``pan:xdr:endpoint``.
  The add-on fetches alerts with ``get_alerts_multi_events``; an event is
  that route's alert object (Elastic's transcription of the reply,
  ``data/vendor-specs/xdr_alerts_multi_events_reduced.json``). Endpoints
  carry the ``endpoints/get_endpoint`` object.
"""

from __future__ import annotations

from datetime import datetime

from application.mde_alerts.queries import resource as mde_alert_resource
from application.mde_machines.queries import resource as mde_machine_resource
from application.threats.queries import public_threat
from application.xdr_alerts.queries import multi_events_alert
from utils.internal_fields import AGENT_INTERNAL_FIELDS
from utils.s1_fixtures import complete_item
from utils.strip import strip_fields
from utils.xdr_fixtures import complete_xdr_item
from utils.xdr_response import serialise_endpoint

S1_INDEX = "sentinelone"
S1_SOURCE = "sentinelone:api"
S1_THREATS = "sentinelone:channel:threats"
S1_AGENTS = "sentinelone:channel:agents"
S1_ACTIVITIES = "sentinelone:channel:activities"

MDE_INDEX = "msdefender"
MDE_SOURCE = "ms:defender"
MDE_ALERTS = "ms:defender:atp:alerts"
MDE_MACHINES = "ms:defender:machines"

XDR_INDEX = "cortex_xdr"
XDR_SOURCE = "pan:xdr"
XDR_INCIDENTS = "pan:xdr:incident"
XDR_ALERTS = "pan:xdr:alert"
XDR_ENDPOINTS = "pan:xdr:endpoint"

_ACTIVITY_STRINGS = frozenset({"agentId", "agentUpdatedVersion", "threatId", "hash"})


def s1_threat(record: dict) -> dict:
    """A threat as ``GET /threats`` lists it."""
    return complete_item(public_threat(record), "threats.schemas_ThreatSchema_many_200")


def s1_agent(record: dict) -> dict:
    """An agent as ``GET /agents`` lists it."""
    return complete_item(
        strip_fields(record, AGENT_INTERNAL_FIELDS), "agents.schemas_AgentViewSchema_many_200"
    )


def s1_activity(record: dict) -> dict:
    """An activity as ``GET /activities`` lists it."""
    item = {k: ("" if v is None and k in _ACTIVITY_STRINGS else v) for k, v in record.items()}
    if "activityType" in item:
        item["activityType"] = int(item["activityType"])
    return complete_item(item, "_ActivityViewSchema_many_200")


def mde_alert(record: dict) -> dict:
    """An alert as ``GET /api/alerts?$expand=evidence`` lists it."""
    return mde_alert_resource(dict(record))


def mde_machine(record: dict) -> dict:
    """A machine as ``GET /api/machines`` lists it."""
    return mde_machine_resource(dict(record))


def xdr_incident(record: dict) -> dict:
    """An incident as ``incidents/get_incidents`` lists it."""
    return complete_xdr_item(record, "incidents_get_incidents", "incidents")


def xdr_alert(record: dict) -> dict:
    """An alert as ``alerts/get_alerts_multi_events`` lists it."""
    return complete_xdr_item(
        multi_events_alert(record), "alerts_get_alerts_multi_events", "alerts"
    )


def xdr_endpoint(record: dict) -> dict:
    """An endpoint as ``endpoints/get_endpoint`` lists it."""
    return complete_xdr_item(
        serialise_endpoint(record), "endpoints_get_endpoint", "endpoints",
    )


# ── CrowdStrike: the Falcon Event Streams shapes ───────────────────────────
# Recorded in ``data/vendor-specs/cs_event_streams_reduced.json``: a detection
# is an ``EppDetectionSummaryEvent`` (``DetectionSummaryEvent`` is the legacy
# type), an incident an ``IncidentSummaryEvent`` with exactly nine fields.

CS_INDEX = "crowdstrike"
CS_SOURCE = "CrowdStrike:Event:Streams"
CS_SOURCETYPE = "CrowdStrike:Event:Streams:JSON"
_CS_CID = "3061c7ff3b634e22b38274d4b586558e"


def cs_detection(d: dict, event_time: float) -> dict:
    """A detection record as an ``EppDetectionSummaryEvent``."""
    behavior = (d.get("behaviors") or [{}])[0]
    device = d.get("device") or {}
    parent = behavior.get("parent_details") or {}
    disposition = behavior.get("pattern_disposition_details") or {}
    severity = d.get("max_severity", 50)
    composite_id = d.get("composite_id", "")
    return {
        "metadata": {
            "customerIDString": _CS_CID,
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


def cs_incident(d: dict, event_time: float) -> dict:
    """An incident record as an ``IncidentSummaryEvent``."""
    host_ids = d.get("host_ids") or []
    return {
        "metadata": {
            "customerIDString": _CS_CID,
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
            "FalconHostLink": (
                "https://falcon.crowdstrike.com/crowdscore/incidents/details/"
                f"{d.get('incident_id', '')}"
            ),
        },
    }


def cs_notable_severity(severity: int) -> str:
    """The ES urgency for a 10–100 Falcon severity."""
    return "critical" if severity >= 90 else "high" if severity >= 70 else "medium"


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
