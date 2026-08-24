"""Write-only application commands for dev tooling: reset, export, import, scenarios."""
from __future__ import annotations

import base64
import binascii
import logging
import random
import time
from collections.abc import Callable
from typing import Any

from domain.account import Account
from domain.activity import Activity
from domain.agent import Agent
from domain.alert import Alert
from domain.cs_case import CsCase
from domain.cs_detection import CsDetection
from domain.cs_host import CsHost
from domain.cs_host_group import CsHostGroup
from domain.cs_incident import CsIncident
from domain.cs_ioc import CsIoc
from domain.cs_oauth_client import CsOAuthClient
from domain.cs_quarantined_file import CsQuarantinedFile
from domain.cs_user import CsUser
from domain.device_control_rule import DeviceControlRule
from domain.dv_query import DVQuery
from domain.es_action_response import EsActionResponse
from domain.es_alert import EsAlert
from domain.es_case import EsCase
from domain.es_case_comment import EsCaseComment
from domain.es_endpoint import EsEndpoint
from domain.es_exception_item import EsExceptionItem
from domain.es_exception_list import EsExceptionList
from domain.es_rule import EsRule
from domain.event_bus import AgentUpdated, ThreatCreated, event_bus
from domain.exclusion import Exclusion
from domain.firewall_rule import FirewallRule
from domain.graph.administrative_unit import GraphAdministrativeUnit
from domain.graph.app_protection_policy import GraphAppProtectionPolicy
from domain.graph.application import GraphApplication
from domain.graph.attack_simulation import GraphAttackSimulation
from domain.graph.audit_log import GraphAuditLog
from domain.graph.autopilot_device import GraphAutopilotDevice
from domain.graph.autopilot_profile import GraphAutopilotProfile
from domain.graph.channel import GraphChannel
from domain.graph.channel_message import GraphChannelMessage
from domain.graph.compliance_policy import GraphCompliancePolicy
from domain.graph.conditional_access_policy import GraphConditionalAccessPolicy
from domain.graph.detected_app import GraphDetectedApp
from domain.graph.device_category import GraphDeviceCategory
from domain.graph.device_configuration import GraphDeviceConfiguration
from domain.graph.directory_role import GraphDirectoryRole
from domain.graph.drive import GraphDrive
from domain.graph.drive_item import GraphDriveItem
from domain.graph.enrollment_restriction import GraphEnrollmentRestriction
from domain.graph.group import GraphGroup
from domain.graph.mail_folder import GraphMailFolder
from domain.graph.mail_message import GraphMailMessage
from domain.graph.mail_rule import GraphMailRule
from domain.graph.managed_device import GraphManagedDevice
from domain.graph.mobile_app import GraphMobileApp
from domain.graph.named_location import GraphNamedLocation
from domain.graph.oauth_client import GraphOAuthClient
from domain.graph.organization import GraphOrganization
from domain.graph.risk_detection import GraphRiskDetection
from domain.graph.risky_user import GraphRiskyUser
from domain.graph.secure_score import GraphSecureScore
from domain.graph.security_alert import GraphSecurityAlert
from domain.graph.security_incident import GraphSecurityIncident
from domain.graph.service_health import GraphServiceHealth
from domain.graph.service_principal import GraphServicePrincipal
from domain.graph.sharepoint_site import GraphSharePointSite
from domain.graph.sign_in_log import GraphSignInLog
from domain.graph.subscribed_sku import GraphSubscribedSku
from domain.graph.team import GraphTeam
from domain.graph.threat_assessment import GraphThreatAssessment
from domain.graph.ti_indicator import GraphTiIndicator
from domain.graph.update_ring import GraphUpdateRing
from domain.graph.user import GraphUser
from domain.graph.user_registration_detail import GraphUserRegistrationDetail
from domain.group import Group
from domain.ioc import IOC
from domain.mde_alert import MdeAlert
from domain.mde_indicator import MdeIndicator
from domain.mde_investigation import MdeInvestigation
from domain.mde_machine import MdeMachine
from domain.mde_machine_action import MdeMachineAction
from domain.mde_oauth_client import MdeOAuthClient
from domain.mde_software import MdeSoftware
from domain.mde_vulnerability import MdeVulnerability
from domain.policy import Policy
from domain.sentinel.alert import SentinelAlert
from domain.sentinel.alert_rule import SentinelAlertRule
from domain.sentinel.bookmark import SentinelBookmark
from domain.sentinel.data_connector import SentinelDataConnector
from domain.sentinel.entity import SentinelEntity
from domain.sentinel.incident import SentinelIncident
from domain.sentinel.incident_comment import SentinelIncidentComment
from domain.sentinel.threat_indicator import SentinelThreatIndicator
from domain.sentinel.watchlist import SentinelWatchlist
from domain.site import Site
from domain.splunk.hec_token import HecToken
from domain.splunk.kv_collection import KVCollection
from domain.splunk.notable_event import NotableEvent
from domain.splunk.saved_search import SavedSearch
from domain.splunk.search_job import SearchJob
from domain.splunk.splunk_event import SplunkEvent
from domain.splunk.splunk_index import SplunkIndex
from domain.splunk.splunk_user import SplunkUser
from domain.tag import Tag
from domain.threat import Threat
from domain.user import User
from domain.webhook import WebhookSubscription
from domain.xdr_action import XdrAction
from domain.xdr_alert import XdrAlert
from domain.xdr_api_key import XdrApiKey
from domain.xdr_audit_log import XdrAuditLog
from domain.xdr_distribution import XdrDistribution
from domain.xdr_endpoint import XdrEndpoint
from domain.xdr_hash_exception import XdrHashException
from domain.xdr_incident import XdrIncident
from domain.xdr_ioc import XdrIoc
from domain.xdr_script import XdrScript
from domain.xdr_xql_query import XdrXqlQuery
from repository.activity_repo import activity_repo
from repository.agent_repo import agent_repo
from repository.store import store
from repository.threat_repo import threat_repo
from utils.serde import record_dict

logger = logging.getLogger(__name__)

# Collections whose values are domain dataclasses — reconstructed via ClassName(**data)
_TYPED_COLLECTIONS: dict[str, type] = {
    "accounts": Account,
    # An in-flight search job used to disappear on restart, so a client
    # polling its sid got a 404 for a job the server had accepted.
    "splunk_search_jobs": SearchJob,
    "sites": Site,
    "groups": Group,
    "agents": Agent,
    "threats": Threat,
    "alerts": Alert,
    "activities": Activity,
    "exclusions": Exclusion,
    "policies": Policy,
    "firewall_rules": FirewallRule,
    "iocs": IOC,
    "users": User,
    "device_control_rules": DeviceControlRule,
    "dv_queries": DVQuery,
    "webhook_subscriptions": WebhookSubscription,
    "tags": Tag,
    # CrowdStrike
    "cs_hosts": CsHost,
    "cs_detections": CsDetection,
    "cs_incidents": CsIncident,
    "cs_iocs": CsIoc,
    "cs_host_groups": CsHostGroup,
    "cs_oauth_clients": CsOAuthClient,
    "cs_users": CsUser,
    "cs_quarantined_files": CsQuarantinedFile,
    "cs_cases": CsCase,
    # Elastic Security
    "es_endpoints": EsEndpoint,
    "es_rules": EsRule,
    "es_alerts": EsAlert,
    "es_cases": EsCase,
    "es_case_comments": EsCaseComment,
    "es_exception_lists": EsExceptionList,
    "es_exception_items": EsExceptionItem,
    "es_action_responses": EsActionResponse,
    # Microsoft Defender
    "mde_oauth_clients": MdeOAuthClient,
    "mde_machines": MdeMachine,
    "mde_alerts": MdeAlert,
    "mde_indicators": MdeIndicator,
    "mde_machine_actions": MdeMachineAction,
    "mde_investigations": MdeInvestigation,
    "mde_software": MdeSoftware,
    "mde_vulnerabilities": MdeVulnerability,
    # Cortex XDR
    "xdr_incidents": XdrIncident,
    "xdr_alerts": XdrAlert,
    "xdr_endpoints": XdrEndpoint,
    "xdr_scripts": XdrScript,
    "xdr_iocs": XdrIoc,
    "xdr_actions": XdrAction,
    "xdr_audit_logs": XdrAuditLog,
    "xdr_distributions": XdrDistribution,
    "xdr_api_keys": XdrApiKey,
    "xdr_xql_queries": XdrXqlQuery,
    # Microsoft Graph
    "graph_administrative_units": GraphAdministrativeUnit,
    "graph_app_protection_policies": GraphAppProtectionPolicy,
    "graph_applications": GraphApplication,
    "graph_attack_simulations": GraphAttackSimulation,
    "graph_audit_logs": GraphAuditLog,
    "graph_autopilot_devices": GraphAutopilotDevice,
    "graph_autopilot_profiles": GraphAutopilotProfile,
    "graph_channel_messages": GraphChannelMessage,
    "graph_channels": GraphChannel,
    "graph_compliance_policies": GraphCompliancePolicy,
    "graph_conditional_access_policies": GraphConditionalAccessPolicy,
    "graph_detected_apps": GraphDetectedApp,
    "graph_device_categories": GraphDeviceCategory,
    "graph_device_configurations": GraphDeviceConfiguration,
    "graph_directory_roles": GraphDirectoryRole,
    "graph_drive_items": GraphDriveItem,
    "graph_drives": GraphDrive,
    "graph_enrollment_restrictions": GraphEnrollmentRestriction,
    "graph_groups": GraphGroup,
    "graph_mail_folders": GraphMailFolder,
    "graph_mail_messages": GraphMailMessage,
    "graph_mail_rules": GraphMailRule,
    "graph_managed_devices": GraphManagedDevice,
    "graph_mobile_apps": GraphMobileApp,
    "graph_named_locations": GraphNamedLocation,
    "graph_oauth_clients": GraphOAuthClient,
    "graph_organization": GraphOrganization,
    "graph_risk_detections": GraphRiskDetection,
    "graph_risky_users": GraphRiskyUser,
    "graph_secure_scores": GraphSecureScore,
    "graph_security_alerts": GraphSecurityAlert,
    "graph_security_incidents": GraphSecurityIncident,
    "graph_service_health": GraphServiceHealth,
    "graph_service_principals": GraphServicePrincipal,
    "graph_sharepoint_sites": GraphSharePointSite,
    "graph_sign_in_logs": GraphSignInLog,
    "graph_subscribed_skus": GraphSubscribedSku,
    "graph_teams": GraphTeam,
    "graph_threat_assessments": GraphThreatAssessment,
    "graph_ti_indicators": GraphTiIndicator,
    "graph_update_rings": GraphUpdateRing,
    "graph_user_registration_details": GraphUserRegistrationDetail,
    "graph_users": GraphUser,
    # Microsoft Sentinel
    "sentinel_alert_rules": SentinelAlertRule,
    "sentinel_alerts": SentinelAlert,
    "sentinel_bookmarks": SentinelBookmark,
    "sentinel_data_connectors": SentinelDataConnector,
    "sentinel_entities": SentinelEntity,
    "sentinel_incident_comments": SentinelIncidentComment,
    "sentinel_incidents": SentinelIncident,
    "sentinel_threat_indicators": SentinelThreatIndicator,
    "sentinel_watchlists": SentinelWatchlist,
    # Splunk
    "splunk_events": SplunkEvent,
    "splunk_hec_tokens": HecToken,
    "splunk_indexes": SplunkIndex,
    "splunk_kv_collections": KVCollection,
    "splunk_notables": NotableEvent,
    "splunk_saved_searches": SavedSearch,
    "splunk_users": SplunkUser,
    "xdr_hash_exceptions": XdrHashException,
}

# Collections whose values carry no identifier of their own — membership lists
# and lookup tables keyed by something other than a record field. These are
# snapshotted as ``{key: value}`` maps and restored verbatim.
_MAPPING_COLLECTIONS = {
    "edr_id_map",
    # Seeded per user and keyed by user id; it was never registered, so a
    # restart lost every user's registered authentication methods.
    "graph_user_auth_methods",
    "graph_detected_app_devices",
    "graph_directory_role_members",
    "graph_group_members",
    "sentinel_oauth_clients",
}

# Collections whose values are already raw dicts (no domain class to reconstruct)
_RAW_COLLECTIONS = {
    "installed_apps",
    "blocklist",
    "api_tokens",
    "star_rules",
    "remote_script_runs",
    # CrowdStrike
    "cs_oauth_tokens",
    # Elastic Security
    "es_api_keys",
    # Microsoft Defender
    "mde_oauth_tokens",
    # None of these were registered, so an issued token, an open Splunk
    # session or a fired alert vanished on restart while the rest of the
    # store survived — leaving a client holding credentials the server had
    # never heard of.
    "graph_oauth_tokens",
    "sentinel_oauth_tokens",
    "splunk_sessions",
    "splunk_fired_alerts",
    "graph_safe_links_policies",
    "graph_safe_attachments_policies",
}

# Collections whose values are raw bytes. `json.dump(default=str)` rendered
# these as a Python repr ("b'PK\\x03\\x04…'") that import then skipped, so a
# collected file was gone after a restart while the activity referencing it
# remained.
_BINARY_COLLECTIONS = {
    "agent_uploads",
}


def reset() -> dict:
    """Re-seed all in-memory repositories with the deterministic initial data set.

    Returns:
        Dict with ``data.status`` confirming the reset.
    """
    from infrastructure.seed import generate_all
    generate_all()
    return {"data": {"status": "reset complete"}}


def export_state() -> dict:
    """Serialize the entire store to a JSON-safe dict.

    Returns:
        Dict mapping each collection name to a list of its records, plus
        ``_activity_order`` to preserve newest-first activity ordering and
        ``_proxy_config`` to preserve proxy vendor settings.
    """
    snapshot: dict[str, Any] = {}
    for collection, _cls in _TYPED_COLLECTIONS.items():
        records = store.get_all(collection)
        snapshot[collection] = [record_dict(r) for r in records]
    for collection in _RAW_COLLECTIONS:
        # Exported as a key->value map: several of these are keyed by a token
        # or session id rather than an "id" field, which a bare list loses.
        snapshot[collection] = dict(store.get_all_with_keys(collection))
    for collection in _BINARY_COLLECTIONS:
        snapshot[collection] = {
            key: base64.b64encode(value).decode()
            for key, value in store.get_all_with_keys(collection).items()
            if isinstance(value, bytes)
        }
    for collection in _MAPPING_COLLECTIONS:
        snapshot[collection] = dict(store.get_all_with_keys(collection))
    snapshot["_activity_order"] = store.get_activity_order()
    # The writer's version: a snapshot from another release is loaded, but
    # the log says which release wrote it when records are skipped.
    from config import APP_VERSION

    snapshot["_version"] = APP_VERSION

    # Persist proxy config (vendor connections survive restarts).
    from application.proxy import queries as proxy_queries
    cfg = proxy_queries.get_config_raw()
    snapshot["_proxy_config"] = record_dict(cfg)

    return snapshot


#: Collections whose store key is not the object's ``id``. The repositories own
#: these rules; import_state carried a partial copy that had drifted, so the six
#: composite-keyed Graph collections came back under a bare id and every lookup
#: by ``{user}:{message}`` missed. Keeping them in one table means a new
#: composite key cannot be added to a repo without appearing here.
_COMPOSITE_KEYS: dict[str, Callable[[Any], str]] = {
    "policies": lambda o: f"{o.scopeType}:{o.scopeId}",
    "alerts": lambda o: str(o.alertInfo["alertId"]),
    "iocs": lambda o: str(o.uuid),
    "graph_mail_messages": lambda o: f"{o._user_id}:{o.id}",
    "graph_mail_folders": lambda o: f"{o._user_id}:{o.id}",
    "graph_mail_rules": lambda o: f"{o._user_id}:{o.id}",
    "graph_channels": lambda o: f"{o._team_id}:{o.id}",
    "graph_channel_messages": lambda o: f"{o._team_id}:{o._channel_id}:{o.id}",
    "graph_drive_items": lambda o: f"{o._drive_id}:{o.id}",
}


def _store_key(collection: str, obj: Any) -> str:
    """Return the key *collection* stores *obj* under."""
    builder = _COMPOSITE_KEYS.get(collection)
    return builder(obj) if builder else str(obj.id)


def _import_raw(collection: str, entries: object) -> int:
    """Restore a raw-dict collection, accepting both snapshot shapes.

    Newer snapshots carry a key->value map, which preserves keys that are not
    an ``id`` field. Older ones carry a bare list; those keys are rebuilt the
    way they used to be so an existing snapshot still loads.
    """
    if isinstance(entries, dict):
        for key, value in entries.items():
            store.save(collection, key, value)
        return len(entries)

    if not isinstance(entries, list):
        return 0

    restored = 0
    for record in entries:
        if not isinstance(record, dict):
            continue
        record_id = (
            record.get("token", "") if collection == "api_tokens"
            else record.get("id", "")
        )
        if not record_id:
            continue
        store.save(collection, record_id, record)
        restored += 1
    return restored


def import_state(snapshot: dict) -> dict:
    """Clear the store and reload from the provided snapshot.

    Typed collections are reconstructed using their domain class constructor.
    Raw-dict collections are stored as-is.

    Args:
        snapshot: Dict mapping collection names to lists of record dicts.

    Returns:
        Dict with ``data.imported`` containing the total number of records loaded.
    """
    store.clear_all()
    total = 0
    skipped = 0

    for collection, cls in _TYPED_COLLECTIONS.items():
        records = snapshot.get(collection, [])
        for record in records:
            try:
                obj = cls(**record)
                store.save(collection, _store_key(collection, obj), obj)
                total += 1
            except (TypeError, KeyError) as exc:
                logger.warning(
                    "Skipped record in '%s' during import: %s",
                    collection, exc,
                )
                skipped += 1

    for collection in _RAW_COLLECTIONS:
        total += _import_raw(collection, snapshot.get(collection))

    for collection in _BINARY_COLLECTIONS:
        entries = snapshot.get(collection) or {}
        if not isinstance(entries, dict):
            continue
        for key, encoded in entries.items():
            try:
                store.save(collection, key, base64.b64decode(str(encoded)))
                total += 1
            except (ValueError, binascii.Error):
                logger.warning("Skipped unreadable binary entry in '%s'", collection)

    for collection in _MAPPING_COLLECTIONS:
        records = snapshot.get(collection, {})
        if not isinstance(records, dict):
            continue
        for key, value in records.items():
            store.save(collection, key, value)
            total += 1

    # Restore activity ordering so GET /activities returns newest-first correctly
    activity_order = snapshot.get("_activity_order", [])
    if activity_order:
        store.set_activity_order(activity_order)
    elif snapshot.get("activities"):
        # Fallback: snapshot from before _activity_order was added — rebuild by
        # sorting activities by createdAt descending
        acts = sorted(
            snapshot["activities"],
            key=lambda a: a.get("createdAt", ""),
            reverse=True,
        )
        store.set_activity_order([a["id"] for a in acts])

    # Restore proxy config if present.
    proxy_snapshot = snapshot.get("_proxy_config")
    if proxy_snapshot and isinstance(proxy_snapshot, dict):
        try:
            from application.proxy import commands as proxy_commands
            mode = proxy_snapshot.get("mode", "off")
            vendors = []
            for _k, vc in proxy_snapshot.get("vendors", {}).items():
                if isinstance(vc, dict):
                    vendors.append(vc)
            proxy_commands.set_config(mode=mode, vendors=vendors if vendors else None)
        except Exception:
            logger.warning("Failed to restore proxy config from snapshot", exc_info=True)

    return {"data": {"imported": total, "skipped": skipped}}


def _save_agent(agent: Agent) -> None:
    """Persist an agent and bridge the change to the SIEMs (ADR-009)."""
    agent_repo.save(agent)
    event_bus.publish(AgentUpdated(
        entity_id=agent.id, payload=record_dict(agent), timestamp=time.time(),
    ))


def _save_threat(threat: Threat) -> None:
    """Persist a threat and bridge it to the SIEMs (ADR-009)."""
    threat_repo.save(threat)
    event_bus.publish(ThreatCreated(
        entity_id=threat.id, payload=record_dict(threat), timestamp=time.time(),
    ))


def trigger_scenario(scenario: str) -> dict:
    """Apply a named bulk mutation to the in-memory store.

    Args:
        scenario: One of ``mass_infection``, ``agent_offline``, ``quiet_day``,
                  ``apt_campaign``.

    Returns:
        Dict with ``data`` containing the scenario name and affected count, or
        an error key if the scenario name is unknown.
    """
    if scenario == "mass_infection":
        agents = agent_repo.list_all()
        targets = random.sample(agents, min(20, len(agents)))
        for agent in targets:
            agent.isInfected = True
            agent.infected = True
            agent.activeThreats = random.randint(1, 5)
            _save_agent(agent)
        activity_repo.create(
            activity_type=5100,
            description=f"Scenario '{scenario}' triggered: {len(targets)} agents infected",
        )
        return {"data": {"affected": len(targets), "scenario": scenario}}

    if scenario == "agent_offline":
        agents = agent_repo.list_all()
        targets = random.sample(agents, max(1, len(agents) // 3))
        for agent in targets:
            agent.networkStatus = "disconnected"
            agent.isActive = False
            _save_agent(agent)
        activity_repo.create(
            activity_type=5100,
            description=f"Scenario '{scenario}' triggered: {len(targets)} agents disconnected",
        )
        return {"data": {"affected": len(targets), "scenario": scenario}}

    if scenario == "quiet_day":
        for threat in threat_repo.list_all():
            threat.threatInfo["incidentStatus"] = "resolved"
            threat.threatInfo["resolved"] = True
            threat.threatInfo["analystVerdict"] = "false_positive"
            _save_threat(threat)
        for agent in agent_repo.list_all():
            agent.isInfected = False
            agent.infected = False
            agent.activeThreats = 0
            agent.networkStatus = "connected"
            agent.isActive = True
            _save_agent(agent)
        activity_repo.create(
            activity_type=5100,
            description=f"Scenario '{scenario}' triggered: "
            "all threats resolved, all agents healthy",
        )
        status = "all threats resolved, all agents healthy"
        return {"data": {"scenario": scenario, "status": status}}

    if scenario == "apt_campaign":
        agents = agent_repo.list_all()
        targets = random.sample(agents, min(10, len(agents)))
        for agent in targets:
            agent.isInfected = True
            agent.infected = True
            agent.activeThreats = random.randint(3, 8)
            agent.networkStatus = "disconnected"
            _save_agent(agent)
        activity_repo.create(
            activity_type=5100,
            description=f"Scenario '{scenario}' triggered: {len(targets)} agents compromised",
        )
        return {"data": {"affected": len(targets), "scenario": scenario}}

    # ── Microsoft Graph scenarios ──────────────────────────────────────────────

    if scenario == "compliance_drift":
        devices = store.get_all("graph_managed_devices")
        target_count = max(1, int(len(devices) * 0.30))
        targets = random.sample(devices, min(target_count, len(devices)))
        for device in targets:
            device.complianceState = "noncompliant"  # type: ignore[attr-defined]
            store.save("graph_managed_devices", device.id, device)
        return {"data": {"affected": len(targets), "scenario": scenario}}

    if scenario == "mfa_gap":
        details = store.get_all("graph_user_registration_details")
        target_count = max(1, int(len(details) * 0.40))
        targets = random.sample(details, min(target_count, len(details)))
        for detail in targets:
            detail.isMfaRegistered = False  # type: ignore[attr-defined]
            detail.isMfaCapable = False  # type: ignore[attr-defined]
            detail.methodsRegistered = []  # type: ignore[attr-defined]
            detail.defaultMfaMethod = ""  # type: ignore[attr-defined]
            store.save("graph_user_registration_details", detail.id, detail)
        return {"data": {"affected": len(targets), "scenario": scenario}}

    if scenario == "risky_signin_wave":
        from domain.graph.sign_in_log import GraphSignInLog
        from infrastructure.seeders.graph.graph_shared import graph_uuid
        from utils.dt import utc_now

        users = store.get_all("graph_users")
        created = 0
        for _ in range(20):
            entry_id = graph_uuid()
            user = random.choice(users) if users else None
            log = GraphSignInLog(
                id=entry_id,
                createdDateTime=utc_now(),
                userDisplayName=getattr(user, "displayName", "Unknown") if user else "Unknown",
                userPrincipalName=(
                    getattr(user, "userPrincipalName", "unknown@acmecorp.onmicrosoft.com")
                    if user else "unknown@acmecorp.onmicrosoft.com"
                ),
                userId=getattr(user, "id", "") if user else "",
                appDisplayName="Microsoft 365 Portal",
                ipAddress=f"198.51.100.{random.randint(1, 254)}",
                clientAppUsed="Browser",
                status={"errorCode": 0, "failureReason": ""},
                riskLevelDuringSignIn="high",
                riskLevelAggregated="high",
                riskState="atRisk",
                isInteractive=True,
            )
            store.save("graph_sign_in_logs", entry_id, log)
            created += 1
        return {"data": {"affected": created, "scenario": scenario}}

    if scenario == "license_exhaustion":
        skus = store.get_all("graph_subscribed_skus")
        for sku in skus:
            enabled = (
                sku.prepaidUnits.get("enabled", 0)
                if isinstance(sku.prepaidUnits, dict) else 0
            )
            sku.consumedUnits = enabled
            store.save("graph_subscribed_skus", sku.id, sku)
        return {"data": {"affected": len(skus), "scenario": scenario}}

    return {"data": {"error": f"Unknown scenario: {scenario}"}}
