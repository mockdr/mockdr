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

Each of the five keeps its own states and side effects (the SIEM bridge, a
completion stamp); what they share lives here — the one wait
(``SETTLE_SECONDS``), the test of whether it is over (``has_answered``), the
moment a settled record is dated (``answered_at``) and the sweep over a
repository (``settle_each``).

``settle_due`` settles everything whose time has come, wherever it lives,
dated when it settled rather than when it was noticed. Splunk runs it before
every search, and the housekeeping sweep every minute, so a consumer that
only ever reads the SIEM — or reads nothing for a day — finds the same
state the vendor's own API reports.
"""
from __future__ import annotations

from collections.abc import Callable, Container, Iterable
from typing import TypeVar

from utils.dt import plus_seconds

_T = TypeVar("_T")

#: How long a device takes to answer an action, in seconds: long enough that a
#: client polling twice sees the state move rather than finding it already
#: done, short enough that a playbook waiting for it is not slowed. One wait
#: for all five actions, so a change to it cannot reach four of them.
SETTLE_SECONDS = 1.0


def has_answered(waited: float | None) -> bool:
    """Whether a device asked *waited* seconds ago has answered by now.

    Args:
        waited: Seconds since the action was asked for; None when the moment
            it was asked for is unreadable, which never settles.
    """
    return waited is not None and waited > SETTLE_SECONDS


def answered_at(asked_at: str) -> str | None:
    """When a device asked at *asked_at* (ISO-8601) answered; None if unreadable.

    The settled record is dated then, not at the read that noticed: stamped
    at the read, an action left unread for a day reported a day's run time.
    """
    return plus_seconds(asked_at, SETTLE_SECONDS)


def settle_each(
    records: Iterable[_T], state: str, pending: Container[object] | None,
    settle: Callable[[_T], object],
) -> int:
    """Run *settle* over every record whose *state* is pending; how many moved.

    Args:
        records: The records to look at.
        state:   The attribute holding the record's state.
        pending: The states that settle into another, or None to hand every
                 record to *settle* (which then decides, and may tidy up).
        settle:  Settles one record if its time has come, returning it.
    """
    done = 0
    for record in records:
        before = getattr(record, state, None)
        if pending is not None and before not in pending:
            continue
        if getattr(settle(record), state, before) != before:
            done += 1
    return done


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
