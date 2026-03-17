"""Master Sentinel seeder — OAuth clients, analytics rules, data connectors, watchlists, TI indicators."""
from __future__ import annotations

import time
import uuid

from domain.sentinel.alert_rule import SentinelAlertRule
from domain.sentinel.data_connector import SentinelDataConnector
from domain.sentinel.threat_indicator import SentinelThreatIndicator
from domain.sentinel.watchlist import SentinelWatchlist
from repository.sentinel.alert_rule_repo import sentinel_alert_rule_repo
from repository.sentinel.data_connector_repo import sentinel_data_connector_repo
from repository.sentinel.threat_indicator_repo import sentinel_threat_indicator_repo
from repository.sentinel.watchlist_repo import sentinel_watchlist_repo
from repository.store import store


def seed_sentinel_infrastructure() -> None:
    """Seed all Sentinel infrastructure."""
    _seed_oauth_clients()
    _seed_alert_rules()
    _seed_data_connectors()
    _seed_watchlists()
    _seed_threat_indicators()


def _seed_oauth_clients() -> None:
    """Pre-seed OAuth2 client credentials."""
    store.save("sentinel_oauth_clients", "sentinel-mock-client-id", {
        "client_id": "sentinel-mock-client-id",
        "client_secret": "sentinel-mock-client-secret",
    })


def _seed_alert_rules() -> None:
    """Create analytics rules for each EDR vendor."""
    rules = [
        SentinelAlertRule(
            rule_id="rule-s1-threats",
            display_name="SentinelOne Threat Correlation",
            description="Correlate SentinelOne threats into Sentinel incidents",
            kind="Scheduled",
            severity="High",
            query="SentinelOne_CL | where confidenceLevel_s == 'malicious'",
            tactics=["Execution", "Impact"],
            etag=uuid.uuid4().hex[:8],
        ),
        SentinelAlertRule(
            rule_id="rule-cs-detections",
            display_name="CrowdStrike Detection Alert",
            description="Correlate CrowdStrike Falcon detections into Sentinel incidents",
            kind="Scheduled",
            severity="High",
            query="CrowdStrike_CL | where Severity_d >= 3",
            tactics=["Execution", "LateralMovement"],
            etag=uuid.uuid4().hex[:8],
        ),
        SentinelAlertRule(
            rule_id="rule-mde-alerts",
            display_name="MDE Alert Ingestion",
            description="Auto-create incidents from Microsoft Defender for Endpoint alerts",
            kind="MicrosoftSecurityIncidentCreation",
            severity="Medium",
            product_filter="Microsoft Defender for Endpoint",
            etag=uuid.uuid4().hex[:8],
        ),
        SentinelAlertRule(
            rule_id="rule-elastic-alerts",
            display_name="Elastic Security Alert Correlation",
            description="Correlate Elastic Security alerts into Sentinel incidents",
            kind="Scheduled",
            severity="Medium",
            query="ElasticSecurity_CL | where severity_s in ('high', 'critical')",
            tactics=["Execution"],
            etag=uuid.uuid4().hex[:8],
        ),
        SentinelAlertRule(
            rule_id="rule-xdr-incidents",
            display_name="Cortex XDR Incident Correlation",
            description="Correlate Cortex XDR incidents into Sentinel incidents",
            kind="Scheduled",
            severity="High",
            query="CortexXDR_CL | where severity_s in ('high', 'critical')",
            tactics=["Execution", "CommandAndControl"],
            etag=uuid.uuid4().hex[:8],
        ),
    ]
    for rule in rules:
        sentinel_alert_rule_repo.save(rule)


def _seed_data_connectors() -> None:
    """Create data connector entries for each EDR vendor."""
    connectors = [
        ("dc-mde", "Microsoft Defender for Endpoint", "MicrosoftDefenderAdvancedThreatProtection"),
        ("dc-s1", "SentinelOne", "GenericUI"),
        ("dc-cs", "CrowdStrike Falcon", "GenericUI"),
        ("dc-elastic", "Elastic Security", "GenericUI"),
        ("dc-xdr", "Palo Alto Cortex XDR", "GenericUI"),
    ]
    for cid, name, kind in connectors:
        dc = SentinelDataConnector(
            connector_id=cid,
            name=name,
            kind=kind,
            data_types_state="Enabled",
            etag=uuid.uuid4().hex[:8],
        )
        sentinel_data_connector_repo.save(dc)


def _seed_watchlists() -> None:
    """Create sample watchlists with items."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    vip = SentinelWatchlist(
        watchlist_alias="VIP_Users",
        display_name="VIP Users",
        description="Executive and privileged accounts requiring enhanced monitoring",
        items_search_key="UserPrincipalName",
        created=now, updated=now, etag=uuid.uuid4().hex[:8],
        items=[
            {"_key": "vip-1", "UserPrincipalName": "ceo@acmecorp.com", "DisplayName": "Jane Smith", "Department": "Executive"},
            {"_key": "vip-2", "UserPrincipalName": "cfo@acmecorp.com", "DisplayName": "Bob Johnson", "Department": "Finance"},
            {"_key": "vip-3", "UserPrincipalName": "ciso@acmecorp.com", "DisplayName": "Alice Brown", "Department": "Security"},
            {"_key": "vip-4", "UserPrincipalName": "admin@acmecorp.com", "DisplayName": "Domain Admin", "Department": "IT"},
            {"_key": "vip-5", "UserPrincipalName": "svc-backup@acmecorp.com", "DisplayName": "Backup Service", "Department": "IT"},
        ],
    )
    sentinel_watchlist_repo.save(vip)

    assets = SentinelWatchlist(
        watchlist_alias="HighValueAssets",
        display_name="High Value Assets",
        description="Critical servers and infrastructure requiring enhanced protection",
        items_search_key="Hostname",
        created=now, updated=now, etag=uuid.uuid4().hex[:8],
        items=[
            {"_key": "hva-1", "Hostname": "DC01.acmecorp.com", "Role": "Domain Controller", "Criticality": "Critical"},
            {"_key": "hva-2", "Hostname": "SQL-PROD-01", "Role": "Production Database", "Criticality": "Critical"},
            {"_key": "hva-3", "Hostname": "EXCH-01", "Role": "Exchange Server", "Criticality": "High"},
            {"_key": "hva-4", "Hostname": "ADFS-01", "Role": "ADFS Server", "Criticality": "Critical"},
            {"_key": "hva-5", "Hostname": "VPN-GW-01", "Role": "VPN Gateway", "Criticality": "High"},
        ],
    )
    sentinel_watchlist_repo.save(assets)

    iocs = SentinelWatchlist(
        watchlist_alias="ThreatIOCs",
        display_name="Threat IOCs",
        description="Known-bad indicators from threat intelligence feeds",
        items_search_key="Indicator",
        created=now, updated=now, etag=uuid.uuid4().hex[:8],
        items=[
            {"_key": "ioc-1", "Indicator": "198.51.100.42", "Type": "IPv4", "ThreatType": "C2", "Confidence": "90"},
            {"_key": "ioc-2", "Indicator": "evil-domain.example.com", "Type": "Domain", "ThreatType": "Phishing", "Confidence": "85"},
            {"_key": "ioc-3", "Indicator": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", "Type": "SHA256", "ThreatType": "Malware", "Confidence": "95"},
        ],
    )
    sentinel_watchlist_repo.save(iocs)


def _seed_threat_indicators() -> None:
    """Create sample TI indicators."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    indicators = [
        SentinelThreatIndicator(
            name=f"indicator--{uuid.uuid4()}",
            display_name="Suspicious C2 IP",
            description="Known command and control IP address",
            pattern="[ipv4-addr:value = '198.51.100.42']",
            pattern_type="ipv4-addr",
            source="MockDR TI Feed",
            confidence=90,
            threat_types=["malicious-activity"],
            labels=["c2", "high-confidence"],
            valid_from=now,
            created=now, last_updated=now, etag=uuid.uuid4().hex[:8],
        ),
        SentinelThreatIndicator(
            name=f"indicator--{uuid.uuid4()}",
            display_name="Phishing Domain",
            description="Known phishing domain",
            pattern="[domain-name:value = 'evil-domain.example.com']",
            pattern_type="domain-name",
            source="MockDR TI Feed",
            confidence=85,
            threat_types=["phishing"],
            labels=["phishing"],
            valid_from=now,
            created=now, last_updated=now, etag=uuid.uuid4().hex[:8],
        ),
        SentinelThreatIndicator(
            name=f"indicator--{uuid.uuid4()}",
            display_name="Ransomware Hash",
            description="SHA-256 hash of known ransomware binary",
            pattern="[file:hashes.'SHA-256' = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2']",
            pattern_type="file",
            source="MockDR TI Feed",
            confidence=95,
            threat_types=["malicious-activity"],
            labels=["ransomware", "critical"],
            valid_from=now,
            created=now, last_updated=now, etag=uuid.uuid4().hex[:8],
        ),
    ]
    for ind in indicators:
        sentinel_threat_indicator_repo.save(ind)
