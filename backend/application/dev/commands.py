"""Write-only application commands for dev tooling: reset, export, import, scenarios."""
from __future__ import annotations

import logging
import random
from dataclasses import asdict
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
from domain.exclusion import Exclusion
from domain.firewall_rule import FirewallRule
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
from domain.site import Site
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
from domain.xdr_incident import XdrIncident
from domain.xdr_ioc import XdrIoc
from domain.xdr_script import XdrScript
from domain.xdr_xql_query import XdrXqlQuery
from repository.activity_repo import activity_repo
from repository.agent_repo import agent_repo
from repository.store import store
from repository.threat_repo import threat_repo

logger = logging.getLogger(__name__)

# Collections whose values are domain dataclasses — reconstructed via ClassName(**data)
_TYPED_COLLECTIONS: dict[str, type] = {
    "accounts": Account,
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
}

# Collections whose values are already raw dicts (no domain class to reconstruct)
_RAW_COLLECTIONS = {
    "installed_apps",
    "blocklist",
    "api_tokens",
    "star_rules",
    "remote_script_runs",
    "agent_uploads",
    # CrowdStrike
    "cs_oauth_tokens",
    # Elastic Security
    "es_api_keys",
    # Microsoft Defender
    "mde_oauth_tokens",
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
        ``_activity_order`` to preserve newest-first activity ordering.
    """
    snapshot: dict[str, Any] = {}
    for collection, _cls in _TYPED_COLLECTIONS.items():
        records = store.get_all(collection)
        snapshot[collection] = [asdict(r) for r in records]
    for collection in _RAW_COLLECTIONS:
        snapshot[collection] = list(store.get_all(collection))
    snapshot["_activity_order"] = store.get_activity_order()
    return snapshot


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
                # Collections with non-standard primary keys:
                #   policies  → "site:{scopeId}" or "group:{scopeId}"
                #   alerts    → alertInfo["alertId"]  (no top-level id field)
                #   iocs      → uuid  (not id)
                if collection == "policies":
                    key = f"{obj.scopeType}:{obj.scopeId}"
                elif collection == "alerts":
                    key = obj.alertInfo["alertId"]
                elif collection == "iocs":
                    key = obj.uuid
                else:
                    key = obj.id
                store.save(collection, key, obj)
                total += 1
            except (TypeError, KeyError) as exc:
                logger.warning(
                    "Skipped record in '%s' during import: %s",
                    collection, exc,
                )
                skipped += 1

    for collection in _RAW_COLLECTIONS:
        records = snapshot.get(collection, [])
        for record in records:
            if not isinstance(record, dict):
                continue
            # api_tokens are keyed by the token string; other raw dicts by "id"
            if collection == "api_tokens":
                record_id = record.get("token", "")
            else:
                record_id = record.get("id", "")
            if not record_id:
                continue
            store.save(collection, record_id, record)
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

    return {"data": {"imported": total, "skipped": skipped}}


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
            agent_repo.save(agent)
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
            agent_repo.save(agent)
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
            threat_repo.save(threat)
        for agent in agent_repo.list_all():
            agent.isInfected = False
            agent.infected = False
            agent.activeThreats = 0
            agent.networkStatus = "connected"
            agent.isActive = True
            agent_repo.save(agent)
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
            agent_repo.save(agent)
        activity_repo.create(
            activity_type=5100,
            description=f"Scenario '{scenario}' triggered: {len(targets)} agents compromised",
        )
        return {"data": {"affected": len(targets), "scenario": scenario}}

    return {"data": {"error": f"Unknown scenario: {scenario}"}}
