"""Master Splunk seeder — indexes, users, HEC tokens, saved searches, KV collections."""
from __future__ import annotations

from domain.splunk.hec_token import HecToken
from domain.splunk.kv_collection import KVCollection
from domain.splunk.saved_search import SavedSearch
from domain.splunk.splunk_index import SplunkIndex
from domain.splunk.splunk_user import SplunkUser
from repository.splunk.hec_token_repo import hec_token_repo
from repository.splunk.kv_collection_repo import kv_collection_repo
from repository.splunk.saved_search_repo import saved_search_repo
from repository.splunk.splunk_index_repo import splunk_index_repo
from repository.splunk.splunk_user_repo import splunk_user_repo

# Pre-defined index names
_INDEXES = [
    "main", "sentinelone", "crowdstrike", "msdefender",
    "elastic_security", "cortex_xdr", "notable",
    "_internal", "_audit",
]

# Pre-defined HEC tokens
_HEC_TOKENS = [
    HecToken(
        name="mockdr-edr-sentinelone",
        token="11111111-1111-1111-1111-111111111111",
        index="sentinelone",
        indexes="sentinelone",
        sourcetype="sentinelone:channel:threats",
        source="sentinelone:api",
    ),
    HecToken(
        name="mockdr-edr-crowdstrike",
        token="22222222-2222-2222-2222-222222222222",
        index="crowdstrike",
        indexes="crowdstrike",
        sourcetype="CrowdStrike:Event:Streams:JSON",
        source="CrowdStrike:Event:Streams",
    ),
    HecToken(
        name="mockdr-edr-general",
        token="33333333-3333-3333-3333-333333333333",
        index="main",
        indexes="main,msdefender,elastic_security,cortex_xdr",
        sourcetype="",
        source="",
    ),
]

# Pre-defined saved searches
_SAVED_SEARCHES = [
    SavedSearch(
        name="SentinelOne Threats - Last 24h",
        search='search index=sentinelone sourcetype=sentinelone:channel:threats',
        description="All SentinelOne threats from the last 24 hours",
        dispatch_earliest_time="-24h@h",
        dispatch_latest_time="now",
    ),
    SavedSearch(
        name="CrowdStrike High Severity Detections",
        search='search index=crowdstrike sourcetype="CrowdStrike:Event:Streams:JSON" '
               'event.Severity>=4',
        description="CrowdStrike detections with severity 4+",
        dispatch_earliest_time="-24h@h",
        dispatch_latest_time="now",
    ),
    SavedSearch(
        name="All EDR Notable Events",
        search='`notable`',
        description="All notable events from EDR sources",
        dispatch_earliest_time="-24h@h",
        dispatch_latest_time="now",
    ),
    SavedSearch(
        name="Microsoft Defender Alerts",
        search='search index=msdefender sourcetype="ms:defender:endpoint:alerts"',
        description="Microsoft Defender for Endpoint alerts",
        dispatch_earliest_time="-24h@h",
        dispatch_latest_time="now",
    ),
    SavedSearch(
        name="Cortex XDR Incidents",
        search='search index=cortex_xdr sourcetype="pan:xdr:incidents"',
        description="Cortex XDR incidents",
        dispatch_earliest_time="-7d@d",
        dispatch_latest_time="now",
    ),
]


def seed_splunk_infrastructure() -> None:
    """Seed all Splunk infrastructure: indexes, users, tokens, saved searches, KV collections."""
    _seed_indexes()
    _seed_users()
    _seed_hec_tokens()
    _seed_saved_searches()
    _seed_kv_collections()


def _seed_indexes() -> None:
    """Create pre-defined indexes."""
    for name in _INDEXES:
        idx = SplunkIndex(name=name)
        splunk_index_repo.save(idx)


def _seed_users() -> None:
    """Create pre-defined Splunk users."""
    users = [
        SplunkUser(
            username="admin",
            password="mockdr-admin",
            realname="MockDR Admin",
            email="admin@mockdr.local",
            roles=["admin"],
            default_app="search",
        ),
        SplunkUser(
            username="analyst",
            password="mockdr-analyst",
            realname="MockDR Analyst",
            email="analyst@mockdr.local",
            roles=["sc_admin"],
            default_app="SplunkEnterpriseSecuritySuite",
        ),
        SplunkUser(
            username="viewer",
            password="mockdr-viewer",
            realname="MockDR Viewer",
            email="viewer@mockdr.local",
            roles=["user"],
            default_app="search",
        ),
    ]
    for user in users:
        splunk_user_repo.save(user)


def _seed_hec_tokens() -> None:
    """Create pre-defined HEC tokens."""
    for token in _HEC_TOKENS:
        hec_token_repo.save(token)


def _seed_saved_searches() -> None:
    """Create pre-defined saved searches."""
    for ss in _SAVED_SEARCHES:
        saved_search_repo.save(ss)


def _seed_kv_collections() -> None:
    """Create pre-defined KV Store collections."""
    collections = [
        KVCollection(
            name="splunk_xsoar_users",
            app="search",
            owner="nobody",
            field_types={"xsoar_user": "string", "splunk_user": "string"},
        ),
        KVCollection(
            name="incident_review_lookup",
            app="SA-ThreatIntelligence",
            owner="nobody",
            field_types={
                "rule_id": "string",
                "status": "string",
                "owner": "string",
                "urgency": "string",
                "comment": "string",
            },
        ),
    ]
    for coll in collections:
        kv_collection_repo.save(coll)
