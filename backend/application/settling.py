"""Actions finish on the device's time, not when someone next reads them.

Five actions settle about a second after they are asked for: Falcon
containment, SentinelOne connect/disconnect, Cortex isolation, Defender
machine actions and Elastic response actions. Each settled when its own
API next read the record, and only then — so the state was right for a
client polling that API and wrong for everyone else. A SOAR playbook that
isolates through Cortex and confirms through Splunk read
``AGENT_PENDING_ISOLATION`` in the SIEM for as long as nobody happened to
list the endpoint; an agent disconnected through SentinelOne stayed
``disconnecting`` in the Splunk index for good.

``settle_due`` settles everything whose time has come, wherever it lives,
dated when it settled rather than when it was noticed. Splunk runs it before
every search, and the housekeeping sweep every minute, so a consumer that
only ever reads the SIEM — or reads nothing for a day — finds the same
state the vendor's own API reports.
"""
from __future__ import annotations


def settle_due() -> int:
    """Settle every pending action whose device has answered; how many settled."""
    from application.agents.network import settle_due as settle_agents
    from application.cs_hosts.queries import settle_due as settle_hosts
    from application.es_endpoints.commands import settle_due as settle_es_actions
    from application.mde_machine_actions.queries import settle_due as settle_mde_actions
    from application.xdr_endpoints.queries import settle_due as settle_endpoints

    return sum(settle() for settle in (
        settle_agents, settle_hosts, settle_endpoints, settle_mde_actions, settle_es_actions,
    ))
