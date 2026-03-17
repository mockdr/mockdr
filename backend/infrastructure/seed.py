"""Seed orchestrator — populates all repositories with realistic fake data.

Called once at startup (``main.py``) and again on ``POST /_dev/reset``.
Each domain is handled by a dedicated seeder in ``infrastructure/seeders/``;
this module is responsible only for ordering, wiring, and deterministic RNG
initialisation.
"""
import random

from faker import Faker

from application.playbook._registry import reset_registry
from infrastructure.seeders.account import seed_account
from infrastructure.seeders.activities import seed_activities
from infrastructure.seeders.agents import seed_agents
from infrastructure.seeders.alerts import seed_alerts
from infrastructure.seeders.blocklist import seed_blocklist
from infrastructure.seeders.cs_cases import seed_cs_cases
from infrastructure.seeders.cs_detections import seed_cs_detections
from infrastructure.seeders.cs_host_groups import seed_cs_host_groups
from infrastructure.seeders.cs_hosts import seed_cs_hosts
from infrastructure.seeders.cs_incidents import seed_cs_incidents
from infrastructure.seeders.cs_iocs import seed_cs_iocs
from infrastructure.seeders.cs_oauth import seed_cs_oauth_clients
from infrastructure.seeders.cs_quarantine import seed_cs_quarantine
from infrastructure.seeders.cs_users import seed_cs_users
from infrastructure.seeders.device_control import seed_device_control_rules
from infrastructure.seeders.es_alerts import seed_es_alerts
from infrastructure.seeders.es_auth import seed_es_api_keys
from infrastructure.seeders.es_cases import seed_es_cases
from infrastructure.seeders.es_endpoints import seed_es_endpoints
from infrastructure.seeders.es_exception_lists import seed_es_exception_lists
from infrastructure.seeders.es_rules import seed_es_rules
from infrastructure.seeders.exclusions import seed_exclusions
from infrastructure.seeders.firewall import seed_firewall_rules
from infrastructure.seeders.groups import seed_groups
from infrastructure.seeders.installed_apps import seed_installed_apps
from infrastructure.seeders.ioc import seed_iocs
from infrastructure.seeders.mde_alerts import seed_mde_alerts
from infrastructure.seeders.mde_indicators import seed_mde_indicators
from infrastructure.seeders.mde_investigations import seed_mde_investigations
from infrastructure.seeders.mde_machine_actions import seed_mde_machine_actions
from infrastructure.seeders.mde_machines import seed_mde_machines
from infrastructure.seeders.mde_oauth import seed_mde_oauth_clients
from infrastructure.seeders.mde_software import seed_mde_software
from infrastructure.seeders.mde_vulnerabilities import seed_mde_vulnerabilities
from infrastructure.seeders.sentinel.incident_seeder import seed_sentinel_incidents
from infrastructure.seeders.sentinel.sentinel_seeder import seed_sentinel_infrastructure
from infrastructure.seeders.sites import seed_sites
from infrastructure.seeders.splunk.edr_event_seeder import seed_edr_events
from infrastructure.seeders.splunk.splunk_seeder import seed_splunk_infrastructure
from infrastructure.seeders.tags import seed_tags
from infrastructure.seeders.threats import seed_threats
from infrastructure.seeders.users import seed_users
from infrastructure.seeders.xdr_actions import seed_xdr_actions
from infrastructure.seeders.xdr_alerts import seed_xdr_alerts
from infrastructure.seeders.xdr_audit_logs import seed_xdr_audit_logs
from infrastructure.seeders.xdr_auth import seed_xdr_api_keys
from infrastructure.seeders.xdr_distributions import seed_xdr_distributions
from infrastructure.seeders.xdr_endpoints import seed_xdr_endpoints
from infrastructure.seeders.xdr_hash_exceptions import seed_xdr_hash_exceptions
from infrastructure.seeders.xdr_incidents import seed_xdr_incidents
from infrastructure.seeders.xdr_iocs import seed_xdr_iocs
from infrastructure.seeders.xdr_scripts import seed_xdr_scripts
from repository.store import store


def generate_all() -> None:
    """Re-seed all in-memory repositories with deterministic fake data.

    Resets the store and playbook registry, then runs every domain seeder
    in dependency order.  The RNG is re-seeded at entry so repeated calls
    always produce the same data set.
    """
    random.seed(42)
    fake = Faker()
    Faker.seed(42)

    store.clear_all()
    reset_registry()

    account_id, account_name = seed_account(fake)
    user_ids = seed_users(fake, account_id, account_name)
    site_ids = seed_sites(fake, account_id, account_name)
    group_ids_by_site = seed_groups(fake, account_id, account_name, site_ids)
    admin_user_id = user_ids[0] if user_ids else ""
    seed_tags(fake, account_id, account_name, site_ids, group_ids_by_site, admin_user_id)
    agent_ids = seed_agents(fake, account_id, account_name, group_ids_by_site)

    seed_threats(fake, agent_ids)
    seed_alerts(fake, agent_ids)
    seed_exclusions(fake, site_ids, user_ids)
    seed_blocklist(fake, site_ids, user_ids)
    seed_firewall_rules(fake, site_ids, user_ids)
    seed_device_control_rules(fake, site_ids, user_ids)
    seed_iocs(fake)
    seed_installed_apps(fake, agent_ids)
    seed_activities(
        fake, account_id, account_name,
        agent_ids, site_ids, group_ids_by_site, user_ids,
    )

    # ── CrowdStrike Falcon seeders ──────────────────────────────────────────
    seed_cs_oauth_clients()
    cs_host_ids = seed_cs_hosts(fake)
    cs_detection_ids = seed_cs_detections(fake, cs_host_ids)
    seed_cs_incidents(fake, cs_host_ids, cs_detection_ids)
    seed_cs_iocs(fake)
    seed_cs_host_groups(fake, cs_host_ids)
    seed_cs_users(fake)
    seed_cs_quarantine(fake, cs_host_ids)
    seed_cs_cases(fake, cs_detection_ids)

    # ── Microsoft Defender for Endpoint seeders ──────────────────────────────
    seed_mde_oauth_clients()
    mde_machine_ids = seed_mde_machines(fake)
    mde_alert_ids = seed_mde_alerts(fake, mde_machine_ids)
    seed_mde_indicators(fake)
    seed_mde_machine_actions(fake, mde_machine_ids)
    seed_mde_investigations(fake, mde_machine_ids, mde_alert_ids)
    seed_mde_software(fake, mde_machine_ids)
    seed_mde_vulnerabilities(fake)

    # ── Elastic Security seeders ─────────────────────────────────────────────
    seed_es_api_keys()
    es_endpoint_ids = seed_es_endpoints(fake)
    es_rule_ids = seed_es_rules(fake)
    es_alert_ids = seed_es_alerts(fake, es_endpoint_ids, es_rule_ids)
    seed_es_cases(fake, es_alert_ids)
    seed_es_exception_lists(fake, es_rule_ids)

    # ── Cortex XDR seeders ───────────────────────────────────────────────────
    seed_xdr_api_keys()
    xdr_endpoint_ids = seed_xdr_endpoints(fake)
    xdr_incident_ids = seed_xdr_incidents(fake, xdr_endpoint_ids)
    seed_xdr_alerts(fake, xdr_incident_ids, xdr_endpoint_ids)
    seed_xdr_scripts()
    seed_xdr_iocs(fake)
    seed_xdr_actions(xdr_endpoint_ids)
    seed_xdr_audit_logs(fake)
    seed_xdr_hash_exceptions()
    seed_xdr_distributions()

    # ── Splunk SIEM seeders ──────────────────────────────────────────────────
    seed_splunk_infrastructure()
    seed_edr_events()

    # ── Microsoft Sentinel seeders ───────────────────────────────────────────
    seed_sentinel_infrastructure()
    seed_sentinel_incidents()
