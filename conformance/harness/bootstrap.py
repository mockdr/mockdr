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

from harness.spec import Endpoint, PlatformSpec

#: mockdr's seeded HEC token. Fixed on purpose — reproducibility is a feature
#: of the mock, and a probe that had to discover it would be testing the
#: discovery endpoint rather than the one it names.
MOCK_HEC_TOKEN = "11111111-1111-1111-1111-111111111111"


class BootstrapError(Exception):
    """A target could not be prepared, so its probes cannot mean anything."""


def _client(endpoint: Endpoint, target: str) -> httpx.Client:
    base = endpoint.mock if target == "mock" else endpoint.real
    return httpx.Client(base_url=base, verify=endpoint.verify_tls, timeout=30.0)


def bootstrap_splunk(
    spec: PlatformSpec, target: str, admin: tuple[str, str],
) -> dict[str, str]:
    """Ensure both targets have a usable HEC token, and report which.

    The real Splunk generates its own token, so it has to be read back rather
    than assumed: `http-event-collector create` ignores a requested value and
    mints one. mockdr's is seeded and known.
    """
    if target == "mock":
        return {"hec_token": MOCK_HEC_TOKEN}

    management = spec.endpoints.get("management")
    if management is None:
        raise BootstrapError("splunk spec has no 'management' endpoint")

    with _client(management, target) as client:
        response = client.get(
            "/services/data/inputs/http",
            params={"output_mode": "json"},
            auth=admin,
        )
        if response.status_code != 200:
            raise BootstrapError(
                f"cannot list HEC tokens on the real Splunk: "
                f"HTTP {response.status_code} {response.text[:200]}",
            )
        for entry in response.json().get("entry", []):
            token = entry.get("content", {}).get("token")
            # The parent [http] stanza has no token of its own; only the
            # child inputs do, so an entry without one is not a failure.
            if token:
                return {"hec_token": str(token)}

    raise BootstrapError(
        "the real Splunk has no HEC token. Create one with:\n"
        "  splunk http-event-collector create conformance "
        "-uri https://localhost:8089 -auth admin:<password>",
    )


def bootstrap_elastic(
    spec: PlatformSpec, target: str, admin: tuple[str, str],
) -> dict[str, str]:
    """Report an index that exists on this target.

    Structural probes do not need one, but any probe that reads documents
    does, and which index exists differs: mockdr seeds its own names, a fresh
    Elasticsearch has only what Kibana created for itself.
    """
    endpoint = spec.endpoints.get("search")
    if endpoint is None:
        raise BootstrapError("elastic spec has no 'search' endpoint")

    with _client(endpoint, target) as client:
        response = client.get("/_cat/indices", params={"format": "json"}, auth=admin)
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


BOOTSTRAPS = {
    "splunk": bootstrap_splunk,
    "elastic": bootstrap_elastic,
}
