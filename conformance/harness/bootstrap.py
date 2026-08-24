"""Making the two targets comparable before anything is compared.

A fresh Splunk has no HEC token; mockdr seeds a known one. An empty
Elasticsearch has no indices; mockdr seeds several. Sending the same request
to both without first reconciling that would produce findings about the
*fixtures*, not about the software — the harness would be loudest exactly
where it is least useful.

So each platform gets a bootstrap that returns a context of ids and
credentials per target. Probes reference those as `${placeholders}`, which is
what lets one probe description address two differently-provisioned servers.
"""
from __future__ import annotations

import httpx

from harness.clients import Clients
from harness.spec import PlatformSpec

#: mockdr's seeded HEC token. Fixed on purpose — reproducibility is a feature
#: of the mock, and a probe that had to discover it would be testing the
#: discovery endpoint rather than the one it names.
MOCK_HEC_TOKEN = "11111111-1111-1111-1111-111111111111"


class BootstrapError(Exception):
    """A target could not be prepared, so its probes cannot mean anything."""


#: The HEC input the README tells an operator to create. Preferred over
#: whatever else is on the box, because a stale token from an earlier run
#: or an unrelated input may carry different index permissions — and then
#: the probes would be measuring that input's configuration, not splunkd.
PREFERRED_HEC_INPUT = "conformance"


def bootstrap_splunk(
    spec: PlatformSpec, target: str, clients: Clients,
) -> dict[str, str]:
    """Ensure both targets have a usable HEC token, and report which.

    The real Splunk generates its own token, so it has to be read back rather
    than assumed: `http-event-collector create` ignores a requested value and
    mints one. mockdr's is seeded and known.
    """
    if target == "mock":
        return {"hec_token": MOCK_HEC_TOKEN}

    if "management" not in spec.endpoints:
        raise BootstrapError("splunk spec has no 'management' endpoint")

    response = clients.get("management", target).get(
        "/services/data/inputs/http",
        params={"output_mode": "json"},
        auth=spec.credentials[target].pair if target in spec.credentials else None,
    )
    if response.status_code != 200:
        raise BootstrapError(
            f"cannot list HEC tokens on the real Splunk: "
            f"HTTP {response.status_code} {response.text[:200]}",
        )
    # The parent [http] stanza has no token of its own; only the child
    # inputs do, so an entry without one is not a failure.
    inputs = {
        str(entry.get("name", "")).removeprefix("http://"): entry["content"]
        for entry in response.json().get("entry", [])
        if entry.get("content", {}).get("token")
    }
    name = PREFERRED_HEC_INPUT if PREFERRED_HEC_INPUT in inputs else next(iter(inputs), None)
    if name is not None:
        _restrict_indexes(clients, spec, target, name, inputs[name])
        return {"hec_token": str(inputs[name]["token"])}

    raise BootstrapError(
        "the real Splunk has no HEC token. Create one with:\n"
        "  splunk http-event-collector create conformance "
        "-uri https://localhost:8089 -auth admin:<password>",
    )


#: What the real token is allowed to write to. mockdr's seeded token is
#: restricted to one index, and a probe for "an index the token may not
#: write to" only means something if the real token is restricted too: an
#: unrestricted HEC accepts any index name, even one that does not exist,
#: with 200 (measured on 10.4.2). `main` because it exists on every install.
_PROBE_INDEX = "main"


def _restrict_indexes(
    clients: Clients, spec: PlatformSpec, target: str, name: str, content: dict,
) -> None:
    """Give the real HEC token an index allow-list, if it has none.

    The one write the bootstrap makes to a real instance. Idempotent: a token
    that is already restricted is left alone, whatever its list says.
    """
    if content.get("indexes"):
        return
    clients.get("management", target).post(
        f"/services/data/inputs/http/{name}",
        # splunkd refuses `indexes` without `index`: "The indexes should be
        # specified together with index."
        data={"index": _PROBE_INDEX, "indexes": _PROBE_INDEX, "output_mode": "json"},
        auth=(
            spec.credentials[target].pair if target in spec.credentials
            else httpx.USE_CLIENT_DEFAULT
        ),
    )


def bootstrap_elastic(
    spec: PlatformSpec, target: str, clients: Clients,
) -> dict[str, str]:
    """Report an index that exists on this target.

    Structural probes do not need one, but any probe that reads documents
    does, and which index exists differs: mockdr seeds its own names, a fresh
    Elasticsearch has only what Kibana created for itself.
    """
    if "search" not in spec.endpoints:
        raise BootstrapError("elastic spec has no 'search' endpoint")

    _await_allocated_shards(spec, target, clients)

    response = clients.get("search", target).get(
        "/_cat/indices", params={"format": "json"},
        auth=spec.credentials[target].pair if target in spec.credentials else None,
    )
    if response.status_code != 200:
        raise BootstrapError(
            f"cannot list indices on {target}: HTTP {response.status_code} "
            f"{response.text[:200]}",
        )
    try:
        rows = response.json()
    except ValueError as exc:
        # A target answering non-JSON here usually means the base URL is
        # wrong, and saying so beats a traceback from deep inside a parse.
        raise BootstrapError(
            f"{target} answered non-JSON at /_cat/indices "
            f"({response.headers.get('content-type', 'unknown')}) — "
            f"check the endpoint's base URL",
        ) from exc
    if not isinstance(rows, list):
        raise BootstrapError(f"{target}: expected an array from /_cat/indices")
    names = [
        str(row["index"]) for row in rows
        if isinstance(row, dict) and not str(row.get("index", "")).startswith(".")
    ]
    return {"index": names[0] if names else "_all"}


def _await_allocated_shards(spec: PlatformSpec, target: str, clients: Clients) -> None:
    """Block until the real cluster has every shard allocated.

    A cluster that is still allocating answers a search with a populated
    ``_shards.failures`` (``no_shard_available_action_exception``). The mock
    has no shards to fail, so the harness would report the difference as
    drift — a measurement of the moment, not of either product.
    """
    if target != "real":
        return
    response = clients.get("search", target).get(
        "/_cluster/health",
        params={
            "wait_for_status": "yellow",
            "wait_for_no_initializing_shards": "true",
            "wait_for_no_relocating_shards": "true",
            "timeout": "120s",
        },
        auth=spec.credentials[target].pair if target in spec.credentials else None,
    )
    if response.status_code != 200:
        raise BootstrapError(
            f"cluster health on {target}: HTTP {response.status_code} "
            f"{response.text[:200]}",
        )
    health = response.json()
    if health.get("timed_out") or health.get("unassigned_shards"):
        raise BootstrapError(
            f"{target} still has {health.get('unassigned_shards')} unassigned shard(s) "
            f"after 120s (status {health.get('status')}) — probing now would "
            f"measure the allocation, not the API",
        )


BOOTSTRAPS = {
    "splunk": bootstrap_splunk,
    "elastic": bootstrap_elastic,
}
