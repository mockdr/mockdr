"""Graph, Defender and Sentinel front one Entra authority, and answer as one.

Each mount's discovery document advertises ``client_secret_basic``, and
Entra accepts it: "The Basic auth pattern of instead providing credentials
in the Authorization header, per RFC 6749 is also supported"
(https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow).
Graph and Defender took it; Sentinel's directory read the form body only and
answered a Basic client ``AADSTS900144 ... 'client_id'``. It also refused an
application it had never heard of as a wrong secret (``401 invalid_client``)
where the other two answer ``400 unauthorized_client`` AADSTS700016, and the
other two answered a request naming no grant in FastAPI's words rather than
Entra's.
"""
from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

MOUNTS = {
    "graph": ("graph-mock-admin-client", "graph-mock-admin-secret",
              "https://graph.microsoft.com/.default"),
    "mde": ("mde-mock-admin-client", "mde-mock-admin-secret",
            "https://api.securitycenter.microsoft.com/.default"),
    "sentinel": ("sentinel-mock-client-id", "sentinel-mock-client-secret",
                 "https://management.azure.com/.default"),
}


def _basic(client_id: str, secret: str) -> dict[str, str]:
    raw = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {raw}"}


@pytest.mark.parametrize("mount", sorted(MOUNTS))
def test_the_discovery_document_advertises_basic(client: TestClient, mount: str) -> None:
    document = client.get(f"/{mount}/common/v2.0/.well-known/openid-configuration").json()
    assert "client_secret_basic" in document["token_endpoint_auth_methods_supported"]


@pytest.mark.parametrize("mount", sorted(MOUNTS))
def test_a_basic_client_gets_a_token(client: TestClient, mount: str) -> None:
    client_id, secret, scope = MOUNTS[mount]
    resp = client.post(f"/{mount}/oauth2/v2.0/token", headers=_basic(client_id, secret),
                       data={"grant_type": "client_credentials", "scope": scope})
    assert resp.status_code == 200, resp.text
    assert resp.json()["token_type"] == "Bearer"


def test_a_basic_sentinel_token_opens_arm(client: TestClient) -> None:
    client_id, secret, scope = MOUNTS["sentinel"]
    token = client.post("/sentinel/oauth2/v2.0/token", headers=_basic(client_id, secret),
                        data={"grant_type": "client_credentials", "scope": scope},
                        ).json()["access_token"]
    resp = client.get(
        "/sentinel/providers/Microsoft.SecurityInsights/operations",
        params={"api-version": "2024-03-01"}, headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200


@pytest.mark.parametrize("mount", sorted(MOUNTS))
def test_a_wrong_basic_secret_is_a_wrong_secret(client: TestClient, mount: str) -> None:
    client_id, _, scope = MOUNTS[mount]
    resp = client.post(f"/{mount}/oauth2/v2.0/token", headers=_basic(client_id, "nope"),
                       data={"grant_type": "client_credentials", "scope": scope})
    assert resp.status_code == 401
    assert resp.json()["error_codes"] == [7000215]


@pytest.mark.parametrize("mount", sorted(MOUNTS))
def test_an_unknown_application_is_unauthorized_client(client: TestClient, mount: str) -> None:
    _, _, scope = MOUNTS[mount]
    resp = client.post(f"/{mount}/oauth2/v2.0/token", data={
        "grant_type": "client_credentials", "client_id": "nobody", "client_secret": "x",
        "scope": scope,
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "unauthorized_client"
    assert resp.json()["error_codes"] == [700016]


@pytest.mark.parametrize("mount", sorted(MOUNTS))
def test_a_request_naming_no_grant_is_told_in_entras_words(
    client: TestClient, mount: str,
) -> None:
    client_id, secret, scope = MOUNTS[mount]
    resp = client.post(f"/{mount}/oauth2/v2.0/token", data={
        "client_id": client_id, "client_secret": secret, "scope": scope,
    })
    assert resp.status_code == 400
    assert resp.json()["error_description"] == (
        "AADSTS900144: The request body must contain the following parameter: 'grant_type'."
    )


def test_sentinel_still_issues_for_the_resource_the_scope_names(client: TestClient) -> None:
    """Sentinel's own part: no scope rule at the token endpoint, the API checks the audience."""
    client_id, secret, _ = MOUNTS["sentinel"]
    token = client.post("/sentinel/oauth2/v2.0/token", headers=_basic(client_id, secret), data={
        "grant_type": "client_credentials", "scope": "https://api.loganalytics.io/.default",
    }).json()["access_token"]
    resp = client.get(
        "/sentinel/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/mockdr-rg"
        "/providers/Microsoft.OperationalInsights/workspaces/mockdr-ws"
        "/providers/Microsoft.SecurityInsights/incidents",
        params={"api-version": "2024-03-01"}, headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "InvalidAuthenticationTokenAudience"
