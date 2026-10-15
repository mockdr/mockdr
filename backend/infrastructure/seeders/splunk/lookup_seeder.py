"""Lookup definitions, the threat-intel collections and the asset/identity CSVs.

``lookup`` and ``inputlookup`` resolve a name through a lookup definition
(transforms.conf), so each KV Store collection the mock seeds gets one, the
way Enterprise Security ships a definition beside each of its collections.
Two CSV lookups model ES's asset and identity tables; they are derived from
the seeded SentinelOne fleet, so an asset's ``nt_host`` is an agent's
``computerName`` and its ``owner`` the user last logged in there — a search
that joins a detection to its asset finds the asset.

Nothing here draws from the seeded random stream: the seeders after this one
(Sentinel, Graph) would otherwise get different ids. Keys are derived from
the values they key.
"""
from __future__ import annotations

import hashlib

from domain.splunk.kv_collection import KVCollection
from domain.splunk.lookup import LookupDefinition, LookupFile
from repository.splunk.kv_collection_repo import kv_collection_repo
from repository.splunk.lookup_repo import lookup_definition_repo, lookup_file_repo
from repository.store import store
from utils.event_time import parse_epoch

#: Where ES keeps its threat-intel collections and their lookups.
_THREAT_INTEL_APP = "SA-ThreatIntelligence"
#: And its asset and identity lookups.
_IDENTITY_APP = "SA-IdentityManagement"

#: ES's ``ip_intel`` and ``file_intel`` collections, reduced to the fields a
#: correlation search reads.
_IP_INTEL_FIELDS = ["_key", "description", "ip", "threat_key", "time", "weight"]
_FILE_INTEL_FIELDS = [
    "_key", "description", "file_hash", "file_name", "threat_key", "time", "weight",
]

ASSET_FILE = "mockdr_assets.csv"
IDENTITY_FILE = "mockdr_identities.csv"
_ASSET_HEADER = [
    "ip", "mac", "nt_host", "dns", "owner", "priority", "bunit", "category", "is_expected",
]
_IDENTITY_HEADER = ["identity", "email", "nick", "bunit", "category", "priority", "watchlist"]

#: Documentation addresses (RFC 5737), so the intel can never name a host
#: someone owns.
_INTEL_IPS = (
    ("203.0.113.10", "Known command-and-control server"),
    ("203.0.113.20", "Tor exit node"),
    ("198.51.100.77", "Credential-phishing landing page"),
)


def seed_lookups() -> None:
    """Seed the intel collections, the CSV files and every lookup definition."""
    _seed_intel_collections()
    _seed_lookup_files()
    for definition in _definitions():
        lookup_definition_repo.save(definition)


def _key(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:24]


def _seed_intel_collections() -> None:
    ip_intel = KVCollection(
        name="ip_intel", app=_THREAT_INTEL_APP,
        field_types={f: "string" for f in _IP_INTEL_FIELDS if f != "_key"},
    )
    for ip, description in _INTEL_IPS:
        ip_intel.records.append({
            "_key": _key("ip_intel", ip), "description": description, "ip": ip,
            "threat_key": "mockdr_intel", "time": 1767225600, "weight": 3,
        })
    kv_collection_repo.save(ip_intel)

    file_intel = KVCollection(
        name="file_intel", app=_THREAT_INTEL_APP,
        field_types={f: "string" for f in _FILE_INTEL_FIELDS if f != "_key"},
    )
    seen: set[str] = set()
    for threat in store.get_all("threats"):
        info = getattr(threat, "threatInfo", None) or {}
        sha256 = str(info.get("sha256") or "")
        if str(info.get("confidenceLevel", "")).lower() != "malicious" or not sha256:
            continue
        if sha256 in seen:
            continue
        seen.add(sha256)
        file_intel.records.append({
            "_key": _key("file_intel", sha256),
            "description": f"SentinelOne verdict: {info.get('classification', 'Malware')}",
            "file_hash": sha256,
            "file_name": str(info.get("threatName") or ""),
            "threat_key": "mockdr_sentinelone",
            "time": int(parse_epoch(info.get("createdAt")) or 0),
            "weight": 3,
        })
    kv_collection_repo.save(file_intel)


def _seed_lookup_files() -> None:
    assets = LookupFile(name=ASSET_FILE, app=_IDENTITY_APP, header=list(_ASSET_HEADER))
    identities = LookupFile(
        name=IDENTITY_FILE, app=_IDENTITY_APP, header=list(_IDENTITY_HEADER),
    )
    known: set[str] = set()
    for agent in store.get_all("agents"):
        interfaces = getattr(agent, "networkInterfaces", None) or [{}]
        server = getattr(agent, "machineType", "") == "server"
        row = {
            "ip": agent.lastIpToMgmt,
            "mac": str(interfaces[0].get("physical", "")),
            "nt_host": agent.computerName,
            "dns": f"{agent.computerName.lower()}.{agent.domain}" if agent.domain else "",
            "owner": agent.lastLoggedInUserName,
            "priority": "high" if server else "medium",
            "bunit": agent.siteName,
            "category": agent.machineType,
            "is_expected": "true" if server else "",
        }
        assets.rows.append({k: v for k, v in row.items() if v})
        user = agent.lastLoggedInUserName
        if user and user not in known:
            known.add(user)
            identities.rows.append({k: v for k, v in {
                "identity": user,
                "email": f"{user}@{agent.domain}" if agent.domain else "",
                "bunit": agent.siteName,
                "category": "endpoint_user",
                "priority": "medium",
            }.items() if v})
    for console_user in store.get_all("users"):
        identity = console_user.email.split("@", 1)[0]
        if identity in known:
            continue
        known.add(identity)
        identities.rows.append({
            "identity": identity, "email": console_user.email,
            "nick": console_user.fullName, "category": "console_user",
            "priority": "high" if console_user.lowestRole == "Admin" else "medium",
            "watchlist": "true" if console_user.lowestRole == "Admin" else "false",
        })
    lookup_file_repo.save(assets)
    lookup_file_repo.save(identities)


def _definitions() -> list[LookupDefinition]:
    return [
        LookupDefinition(
            name="splunk_xsoar_users", app="search", collection="splunk_xsoar_users",
            fields_list=["_key", "xsoar_user", "splunk_user"],
        ),
        LookupDefinition(
            name="incident_review_lookup", app=_THREAT_INTEL_APP,
            collection="incident_review_lookup",
            fields_list=["_key", "rule_id", "status", "owner", "urgency", "comment"],
        ),
        LookupDefinition(
            name="ip_intel", app=_THREAT_INTEL_APP, collection="ip_intel",
            fields_list=list(_IP_INTEL_FIELDS),
        ),
        LookupDefinition(
            name="file_intel", app=_THREAT_INTEL_APP, collection="file_intel",
            fields_list=list(_FILE_INTEL_FIELDS),
        ),
        LookupDefinition(name="mockdr_assets", app=_IDENTITY_APP, filename=ASSET_FILE),
        LookupDefinition(
            name="mockdr_identities", app=_IDENTITY_APP, filename=IDENTITY_FILE,
        ),
    ]
