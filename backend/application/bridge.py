"""Publish what a write changed, so the SIEM mounts see it (ADR-009).

The bridge subscribes to ten event types and, until this existed, four of
them had a publisher: an agent disconnected through the SentinelOne API, a
threat mitigated, a CrowdStrike alert triaged, a Defender alert closed and an
Elastic signal acknowledged all returned 200 while the Splunk mount went on
answering the state the install was seeded with. ADR-009 promises the
opposite — "after an EDR command returns, the corresponding Splunk event
already exists" — and a client that verifies an action through the SIEM,
which is what a SOAR playbook does, was reading a stale document.

Seeding does not come through here: the seeders write the SIEM's backlog
themselves, and publishing from the repositories would double every record.
"""

from __future__ import annotations

import time

from domain.event_bus import (
    AgentUpdated,
    CsDetectionCreated,
    EsAlertCreated,
    MdeAlertCreated,
    ThreatCreated,
    XdrAlertCreated,
    XdrIncidentCreated,
    event_bus,
)
from utils.serde import record_dict


def _payload(record: object) -> dict:
    """A record as the bridge's formatters read it."""
    return record if isinstance(record, dict) else record_dict(record)


def agent_changed(agent: object) -> None:
    """A SentinelOne agent's state changed."""
    event_bus.publish(AgentUpdated(
        entity_id=str(getattr(agent, "id", "")),
        payload=_payload(agent),
        timestamp=time.time(),
    ))


def threat_changed(threat: object) -> None:
    """A SentinelOne threat was created or moved on."""
    event_bus.publish(ThreatCreated(
        entity_id=str(getattr(threat, "id", "")),
        payload=_payload(threat),
        timestamp=time.time(),
    ))


def cs_detection_changed(detection: object) -> None:
    """A CrowdStrike detection was created or triaged."""
    event_bus.publish(CsDetectionCreated(
        entity_id=str(getattr(detection, "id", "")),
        payload=_payload(detection),
        timestamp=time.time(),
    ))


def mde_alert_changed(alert: object) -> None:
    """A Defender alert was created or updated."""
    event_bus.publish(MdeAlertCreated(
        entity_id=str(getattr(alert, "id", "")),
        payload=_payload(alert),
        timestamp=time.time(),
    ))


def es_alert_changed(alert: object) -> None:
    """An Elastic Security signal was created or triaged."""
    event_bus.publish(EsAlertCreated(
        entity_id=str(getattr(alert, "id", "")),
        payload=_payload(alert),
        timestamp=time.time(),
    ))


def xdr_incident_changed(incident: object) -> None:
    """A Cortex XDR incident was created or updated."""
    event_bus.publish(XdrIncidentCreated(
        entity_id=str(getattr(incident, "id", "")),
        payload=_payload(incident),
        timestamp=time.time(),
    ))


def xdr_alert_changed(alert: object) -> None:
    """A Cortex XDR alert was created or updated."""
    event_bus.publish(XdrAlertCreated(
        entity_id=str(getattr(alert, "id", "")),
        payload=_payload(alert),
        timestamp=time.time(),
    ))
