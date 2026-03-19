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
from infrastructure.seeders.graph.graph_administrative_units import seed_graph_administrative_units
from infrastructure.seeders.graph.graph_applications import seed_graph_applications
from infrastructure.seeders.graph.graph_conditional_access import seed_graph_conditional_access
from infrastructure.seeders.graph.graph_app_management import seed_graph_app_management
from infrastructure.seeders.graph.graph_audit_logs import seed_graph_audit_logs
from infrastructure.seeders.graph.graph_autopilot import seed_graph_autopilot
from infrastructure.seeders.graph.graph_compliance import seed_graph_compliance
from infrastructure.seeders.graph.graph_detected_apps import seed_graph_detected_apps
from infrastructure.seeders.graph.graph_groups import seed_graph_groups
from infrastructure.seeders.graph.graph_identity_protection import seed_graph_identity_protection
from infrastructure.seeders.graph.graph_directory_roles import seed_graph_directory_roles
from infrastructure.seeders.graph.graph_mail_rules import seed_graph_mail_rules
from infrastructure.seeders.graph.graph_managed_devices import seed_graph_managed_devices
from infrastructure.seeders.graph.graph_named_locations import seed_graph_named_locations
from infrastructure.seeders.graph.graph_sign_in_logs import seed_graph_sign_in_logs
from infrastructure.seeders.graph.graph_update_rings import seed_graph_update_rings
from infrastructure.seeders.graph.graph_subscribed_skus import seed_graph_subscribed_skus
from infrastructure.seeders.graph.graph_oauth import seed_graph_oauth_clients
from infrastructure.seeders.graph.graph_organization import seed_graph_organization
from infrastructure.seeders.graph.graph_service_principals import seed_graph_service_principals
from infrastructure.seeders.graph.graph_user_auth import seed_graph_user_auth
from infrastructure.seeders.graph.graph_defender_office import seed_graph_defender_office
from infrastructure.seeders.graph.graph_security import seed_graph_security
from infrastructure.seeders.graph.graph_service_health import seed_graph_service_health
from infrastructure.seeders.graph.graph_users import seed_graph_users
from infrastructure.seeders.graph.graph_mail import seed_graph_mail
from infrastructure.seeders.graph.graph_files import seed_graph_files
from infrastructure.seeders.graph.graph_teams import seed_graph_teams
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

    # ── Microsoft Graph API seeders ───────────────────────────────────────────
    seed_graph_oauth_clients()
    seed_graph_organization(fake)
    seed_graph_subscribed_skus(fake)
    graph_user_ids = seed_graph_users(fake)
    seed_graph_groups(fake, graph_user_ids)
    seed_graph_directory_roles(fake, graph_user_ids)
    seed_graph_user_auth(fake, graph_user_ids)
    seed_graph_mail_rules(fake, graph_user_ids)
    seed_graph_service_principals(fake)
    seed_graph_applications(fake)
    seed_graph_conditional_access(fake)
    seed_graph_named_locations(fake)
    seed_graph_administrative_units(fake, graph_user_ids)
    seed_graph_sign_in_logs(fake, graph_user_ids)
    seed_graph_audit_logs(fake, graph_user_ids)
    seed_graph_identity_protection(fake, graph_user_ids)
    seed_graph_managed_devices(fake)
    seed_graph_detected_apps(fake)
    seed_graph_compliance(fake)
    seed_graph_autopilot(fake)
    seed_graph_app_management(fake)
    seed_graph_update_rings(fake)
    seed_graph_security(fake)
    seed_graph_mail(fake, graph_user_ids)
    seed_graph_files(fake, graph_user_ids)
    seed_graph_teams(fake, graph_user_ids)
    seed_graph_defender_office(fake, graph_user_ids)
    seed_graph_service_health(fake)
