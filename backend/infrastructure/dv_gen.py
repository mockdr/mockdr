"""Runtime Deep Visibility event generator.

Extracted from ``seed.py`` so that ``application.deep_visibility.commands``
can import it without depending on the full seeder infrastructure.
"""
import random
import re

from faker import Faker

from infrastructure.process_gen import PROCESS_CATALOG
from infrastructure.seeders._shared import DV_EVENT_TYPES, rand_ago
from repository.agent_repo import agent_repo
from utils.id_gen import new_id

_fake = Faker()

# Event types biased toward threat activity (for infected agents)
_THREAT_EVENT_TYPES: list[str] = ["Process", "File", "Network", "DNS"]

# OS-specific slices of PROCESS_CATALOG
_WINDOWS_PROCS: list[tuple[str, str]] = [
    p for p in PROCESS_CATALOG if p[1].startswith("C:\\")
]
_POSIX_PROCS: list[tuple[str, str]] = [
    p for p in PROCESS_CATALOG if p[1].startswith("/")
]


def _parse_agent_ids(query_str: str) -> list[str]:
    """Extract agent IDs referenced in a Deep Visibility query string.

    SentinelOne agent IDs are 18–19 digit decimal numbers.  Handles both
    equality and ``In (...)`` forms, e.g. ``AgentId = "123..."`` or
    ``AgentId In ("123...", "456...")``.

    Args:
        query_str: Raw DV query string from the request body.

    Returns:
        List of matched agent ID strings, or an empty list if none found.
    """
    return re.findall(r'"(\d{15,})"', query_str)


def generate_dv_events(count: int = 50, query_body: dict | None = None) -> list[dict]:
    """Generate a list of Deep Visibility events grounded in real mock agent data.

    Selects real agents from the store and uses their actual identity fields
    (``computerName``, ``id``, ``osType``, ``lastIpToMgmt``) for every event.
    If the query string contains an ``AgentId`` filter the matching agents are
    used exclusively; if the filter matches nothing, all agents are used as
    fallback.

    Infected agents receive a higher proportion of threat-related event types
    (Process, File, Network, DNS) to make the event stream more realistic.

    Args:
        count: Number of events to generate.
        query_body: Raw request body from ``POST /dv/init-query``.  Used to
            extract optional ``AgentId`` filters from the ``query`` field.

    Returns:
        List of event dicts ready to be returned in an API response.
    """
    query_str = (query_body or {}).get("query", "")

    all_agents = agent_repo.list_all()
    if not all_agents:
        # Graceful degradation when store is empty (e.g. isolated unit tests)
        agents = []
    else:
        filter_ids = _parse_agent_ids(query_str)
        if filter_ids:
            matched = [a for a in all_agents if a.id in filter_ids]
            agents = matched if matched else all_agents
        else:
            agents = all_agents

    events: list[dict] = []
    for _ in range(count):
        if agents:
            agent = random.choice(agents)
            agent_name = agent.computerName
            agent_id   = agent.id
            agent_os   = agent.osType
            agent_ip   = agent.lastIpToMgmt
            catalog    = (
                _WINDOWS_PROCS if agent_os == "windows"
                else _POSIX_PROCS if agent_os in ("linux", "macos")
                else PROCESS_CATALOG
            ) or PROCESS_CATALOG
            event_type = (
                random.choice(_THREAT_EVENT_TYPES)
                if agent.infected
                else random.choice(DV_EVENT_TYPES)
            )
        else:
            agent_name = f"ENDPOINT-{_fake.lexify('??????').upper()}"
            agent_id   = new_id()
            agent_os   = random.choice(["windows", "macos", "linux"])
            agent_ip   = _fake.ipv4_private()
            catalog    = PROCESS_CATALOG
            event_type = random.choice(DV_EVENT_TYPES)

        proc_name, proc_path = random.choice(catalog)
        events.append({
            "id":               new_id(),
            "objectType":       "process",
            "eventType":        event_type,
            "createdAt":        rand_ago(1),
            "agentName":        agent_name,
            "agentId":          agent_id,
            "agentOs":          agent_os,
            "agentIp":          agent_ip,
            "agentDomain":      _fake.domain_name(),
            "agentGroupId":    new_id(),
            "agentInfected":   False,
            "agentIsActive":   True,
            "agentIsDecommissioned": False,
            "agentMachineType": "laptop",
            "agentNetworkStatus": "connected",
            "agentUuid":         _fake.uuid4(),
            "agentVersion":      "23.4.2.3",
            "siteName":         agent.siteName if agents else _fake.company(),
            "user":             _fake.user_name(),
            "processName":      proc_name,
            "processImagePath": proc_path,
            "processCmd":       f"{proc_name} --config {_fake.file_path()}",
            "processGroupId":   new_id(),
            "processStartTime": rand_ago(1),
            "processUserName":  _fake.user_name(),
            "pid":              str(random.randint(100, 65535)),
            "parentPid":        str(random.randint(1, 1000)),
            "srcIp":            agent_ip,
            "dstIp":            _fake.ipv4_public(),
            "dstPort":          random.randint(1, 65535),
            "srcPort":          random.randint(1024, 65535),
            "fileFullName":     _fake.file_path(),
            "fileSha256":       _fake.sha256(),
            "fileSha1":         _fake.sha1(),
            "fileMd5":          _fake.md5(),
            "registryPath":     f"HKLM\\SOFTWARE\\{_fake.word()}\\{_fake.word()}",
            "dnsRequest":       _fake.domain_name(),
            "dnsResponse":      _fake.ipv4_public(),
        })
    return events
