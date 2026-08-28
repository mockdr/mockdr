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
from harness.seed import (
    SeedError,
    await_indexed,
    seed_elastic,
    seed_kibana_case,
    seed_scroll,
    seed_search_job,
    seed_sourcetype,
    seed_splunk,
)
from harness.spec import PlatformSpec

#: mockdr's seeded HEC token. Fixed on purpose — reproducibility is a feature
#: of the mock, and a probe that had to discover it would be testing the
#: discovery endpoint rather than the one it names.
MOCK_HEC_TOKEN = "11111111-1111-1111-1111-111111111111"

#: mockdr's own tokens are restricted per index, and the one above may only
#: write to `sentinelone`. The seed events go to `main`, which is the index
#: the real instance's token is restricted to and the one every install has.
MOCK_SEED_HEC_TOKEN = "33333333-3333-3333-3333-333333333333"


class BootstrapError(Exception):
    """A target could not be prepared, so its probes cannot mean anything."""


#: The HEC input the README tells an operator to create. Preferred over
#: whatever else is on the box, because a stale token from an earlier run
#: or an unrelated input may carry different index permissions — and then
#: the probes would be measuring that input's configuration, not splunkd.
PREFERRED_HEC_INPUT = "conformance"


def bootstrap_splunk(
    spec: PlatformSpec, target: str, clients: Clients, *, seeded: bool = False,
) -> dict[str, str]:
    """Ensure both targets have a usable HEC token, and report which.

    The real Splunk generates its own token, so it has to be read back rather
    than assumed: `http-event-collector create` ignores a requested value and
    mints one. mockdr's is seeded and known.

    With ``seeded``, the same events go into both targets afterwards and the
    sourcetype they carry is reported as a placeholder, so the semantic
    probes can search for exactly them.
    """
    if target == "mock":
        return _with_seed(
            spec, target, clients, MOCK_HEC_TOKEN,
            seed_token=MOCK_SEED_HEC_TOKEN, seeded=seeded,
        )

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
        return _with_seed(
            spec, target, clients, str(inputs[name]["token"]), seeded=seeded,
        )

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


#: One sourcetype for the whole run, so both targets search the same events.
_RUN_SOURCETYPE = seed_sourcetype()


def _with_seed(
    spec: PlatformSpec, target: str, clients: Clients, token: str, *,
    seeded: bool, seed_token: str = "",
) -> dict[str, str]:
    """Report the HEC token, and put the seed events behind it when asked.

    ``seed_token`` separates the two jobs: the token the probes authenticate
    with is not always one that may write to the seed index.
    """
    context = {"hec_token": token}
    if not seeded:
        return context
    try:
        seed_splunk(target, clients, seed_token or token, _RUN_SOURCETYPE)
        await_indexed(spec, target, clients, _RUN_SOURCETYPE)
    except SeedError as exc:
        raise BootstrapError(str(exc)) from exc
    context["sourcetype"] = _RUN_SOURCETYPE
    auth = (
        spec.credentials[target].pair if target in spec.credentials
        else httpx.USE_CLIENT_DEFAULT
    )
    try:
        context.update(seed_search_job(target, clients, auth))
    except SeedError as exc:
        raise BootstrapError(str(exc)) from exc
    return context


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
    spec: PlatformSpec, target: str, clients: Clients, *, seeded: bool = False,
) -> dict[str, str]:
    """Report an index that exists on this target.

    With ``seeded``, an index of six known documents is created on both
    targets as well, and reported as ``seed_index`` — which is what lets a
    probe compare what a query *answers* rather than only how it is shaped.

    Structural probes do not need one, but any probe that reads documents
    does, and which index exists differs: mockdr seeds its own names, a fresh
    Elasticsearch has only what Kibana created for itself.
    """
    if "search" not in spec.endpoints:
        raise BootstrapError("elastic spec has no 'search' endpoint")

    _await_allocated_shards(spec, target, clients)
    _require_kibana_available(spec, target, clients)

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
    names = sorted(
        str(row["index"]) for row in rows
        if isinstance(row, dict) and not str(row.get("index", "")).startswith(".")
    )
    if names:
        return _with_elastic_seed(
            {"index": names[0]}, spec, target, clients, seeded=seeded,
        )
    # A fresh Elasticsearch has only Kibana's own system indices, and Kibana
    # keeps creating and rolling them over while the probes run: a request
    # against `_all` then measures that churn — an index whose stats are not
    # yet available, a shard that is not yet allocated — rather than either
    # product's API. One index of our own, created here, is stable.
    return _with_elastic_seed(
        {"index": _create_probe_index(spec, target, clients)},
        spec, target, clients, seeded=seeded,
    )


def _with_elastic_seed(
    context: dict[str, str], spec: PlatformSpec, target: str, clients: Clients, *,
    seeded: bool,
) -> dict[str, str]:
    """Add the seeded index to the context, when the run asked for one."""
    if not seeded:
        return context
    auth = (
        spec.credentials[target].pair if target in spec.credentials
        else httpx.USE_CLIENT_DEFAULT
    )
    try:
        context = {**context, "seed_index": seed_elastic(target, clients, auth)}
        context = {**context, **seed_scroll(target, clients, auth)}
        if "kibana" in spec.endpoints:
            context = {**context, **seed_kibana_case(target, clients, auth)}
    except SeedError as exc:
        raise BootstrapError(str(exc)) from exc
    return context


_ES_PROBE_INDEX = "conformance-probe"


def _create_probe_index(spec: PlatformSpec, target: str, clients: Clients) -> str:
    """Create a single-shard, replica-free index and wait for it to go green."""
    auth = (
        spec.credentials[target].pair if target in spec.credentials
        else httpx.USE_CLIENT_DEFAULT
    )
    client = clients.get("search", target)
    created = client.put(
        f"/{_ES_PROBE_INDEX}",
        json={"settings": {"number_of_shards": 1, "number_of_replicas": 0}},
        auth=auth,
    )
    if created.status_code not in (200, 400):  # 400: it already exists
        raise BootstrapError(
            f"cannot create {_ES_PROBE_INDEX} on {target}: HTTP {created.status_code} "
            f"{created.text[:200]}",
        )
    health = client.get(
        f"/_cluster/health/{_ES_PROBE_INDEX}",
        params={"wait_for_status": "green", "timeout": "60s"},
        auth=auth,
    )
    if health.status_code != 200 or health.json().get("timed_out"):
        raise BootstrapError(f"{_ES_PROBE_INDEX} on {target} never went green")
    return _ES_PROBE_INDEX


def _require_kibana_available(
    spec: PlatformSpec, target: str, clients: Clients,
) -> None:
    """Refuse to run if Kibana is up but not *available*.

    Kibana answers every request with a 503 while it is starting, and with a
    503 forever if it cannot authenticate against Elasticsearch. Either way
    the probes then compare the mock against a product that is not running,
    and report dozens of differences that read as mock defects — the exact
    inversion this harness exists to prevent. Saying so once, at the top, is
    worth more than fifty findings that are all the same fact.
    """
    if "kibana" not in spec.endpoints:
        return
    auth = (
        spec.credentials[target].pair if target in spec.credentials
        else httpx.USE_CLIENT_DEFAULT
    )
    try:
        response = clients.get("kibana", target).get("/api/status", auth=auth)
    except httpx.HTTPError as exc:
        raise BootstrapError(f"{target}: Kibana is unreachable — {exc}") from exc
    if response.status_code != 200:
        raise BootstrapError(
            f"{target}: Kibana answered {response.status_code} at /api/status; "
            f"it is not ready to be compared against",
        )
    try:
        level = response.json()["status"]["overall"]["level"]
    except (ValueError, KeyError, TypeError):
        level = "unreadable"
    if level != "available":
        raise BootstrapError(
            f"{target}: Kibana reports its status as {level!r}, not 'available'. "
            f"It cannot authenticate against Elasticsearch unless the "
            f"`kibana-credentials` service has run — see conformance/README.md.",
        )


def _await_allocated_shards(spec: PlatformSpec, target: str, clients: Clients) -> None:
    """Block until the real cluster has every shard allocated.

    A cluster that is still allocating answers a search with a populated
    ``_shards.failures`` (``no_shard_available_action_exception``). The mock
    has no shards to fail, so the harness would report the difference as
    drift — a measurement of the moment, not of either product.

    "Settled" is not "green": a single-node install leaves every replica
    unassigned for good and stays yellow, which is its healthy state. What
    must be over is *movement* — nothing initializing, nothing relocating.
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
    if health.get("timed_out") or health.get("initializing_shards") or health.get(
        "relocating_shards"
    ):
        raise BootstrapError(
            f"{target} is still moving shards after 120s "
            f"(status {health.get('status')}, "
            f"{health.get('initializing_shards')} initializing, "
            f"{health.get('relocating_shards')} relocating) — probing now would "
            f"measure the allocation, not the API",
        )


BOOTSTRAPS = {
    "splunk": bootstrap_splunk,
    "elastic": bootstrap_elastic,
}
