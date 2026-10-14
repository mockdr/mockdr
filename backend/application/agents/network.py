"""An agent's network state moves when the agent acknowledges, not when asked.

``networkStatus`` is enumerated ``connected``, ``disconnected``,
``connecting``, ``disconnecting`` in the 2.1 swagger
(``agents.schemas_AgentViewSchema``): a connect or disconnect is sent to the
agent and the console shows it in transit until the agent answers. The mock
jumped straight to the final state, so the two transitional values never
occurred, and a client that polls until ``disconnected`` — or one that
treats ``disconnecting`` as "isolation requested, not yet in force" — was
never exercised.

The action now leaves the agent ``connecting`` / ``disconnecting``, and a
read a moment later finds it settled — the same shape, and the same one
second, as the Falcon mount's containment (``application/cs_hosts/queries``,
``_SETTLES_INTO``). The settled state is saved and handed to the SIEM
bridge like any other change of the agent.

Only a transition an action started settles. The fleet is seeded with
agents already ``disconnecting`` — an agent that never acknowledged, which a
console shows too — and settling those on the first read would erase the
state the seed exists to show.
"""
from __future__ import annotations

import time

from application import bridge
from repository.agent_repo import agent_repo
from repository.store import store
from utils.dt import utc_now

#: The state each action leaves the agent in until it acknowledges.
PENDING_FOR = {"connect": "connecting", "disconnect": "disconnecting"}

#: What a transitional state settles into once the agent has acknowledged.
_SETTLES_INTO = {"connecting": "connected", "disconnecting": "disconnected"}

#: How long the agent takes to acknowledge, so a client that polls twice sees
#: the state move rather than finding it already done.
_SETTLE_SECONDS = 1.0


#: Each in-flight transition by agent id: when it was asked for (epoch
#: seconds), and the ``updatedAt`` it stamped on the agent — a record that no
#: longer carries that stamp (reseeded, or changed since) is not the one that
#: asked. Kept in the store rather than in this module, so it is persisted
#: and exported with the agent it belongs to: held in process memory, a
#: restart with ``MOCKDR_PERSIST`` (or an export and import) in the second a
#: transition was in flight left that agent ``connecting`` for ever.
_REQUESTS = "agent_network_requests"


def begin(agent: object, action: str) -> None:
    """Put *agent* in transit for a connect or disconnect."""
    stamp = utc_now()
    agent.networkStatus = PENDING_FOR[action]  # type: ignore[attr-defined]
    agent.updatedAt = stamp  # type: ignore[attr-defined]
    store.save(_REQUESTS, str(getattr(agent, "id", "")),
               {"requested_at": time.time(), "stamp": stamp})


def settled(agent: object) -> object:
    """Move *agent* out of a transitional network state once the wait is over.

    The agent answers about a second after it was asked, whether or not
    anyone is looking: the change reaches the SIEM dated then, not at the
    read that happened to notice it.
    """
    agent_id = str(getattr(agent, "id", ""))
    pending = store.get(_REQUESTS, agent_id)
    if pending is None:
        return agent
    requested, stamp = float(pending["requested_at"]), pending["stamp"]
    target = _SETTLES_INTO.get(str(getattr(agent, "networkStatus", "")))
    if target is None or getattr(agent, "updatedAt", None) != stamp:
        store.delete(_REQUESTS, agent_id)
        return agent
    if time.time() - requested <= _SETTLE_SECONDS:
        return agent
    store.delete(_REQUESTS, agent_id)
    agent.networkStatus = target  # type: ignore[attr-defined]
    agent_repo.save(agent)  # type: ignore[arg-type]
    bridge.agent_changed(agent, at=requested + _SETTLE_SECONDS)
    return agent


def settle_all(agents: list) -> list:
    """Settle every agent in *agents* and return the list."""
    for agent in agents:
        settled(agent)
    return agents


def settle_due() -> int:
    """Settle every transition whose agent has answered; how many settled."""
    done = 0
    for agent_id in list(store.get_all_with_keys(_REQUESTS)):
        agent = agent_repo.get(agent_id)
        if agent is None:
            store.delete(_REQUESTS, agent_id)
            continue
        before = agent.networkStatus
        if getattr(settled(agent), "networkStatus", before) != before:
            done += 1
    return done
