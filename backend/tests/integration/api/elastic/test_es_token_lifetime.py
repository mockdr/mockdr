"""An Elasticsearch token's life, from mint to deletion, as `TokenService` lives it.

Elasticsearch 8.15 source (x-pack security `TokenService`, `ExpiredTokenRemover`):

* an access token lives 20 minutes (`xpack.security.authc.token.timeout`);
* one past that, or invalidated, is refused with `expiredTokenException()`:
  401, reason "token expired", challenge `Bearer realm="security",
  error="invalid_token", error_description="The access token expired"`;
* a refresh token is refused 24 hours after its document was created —
  `invalid_grant`, "token document has expired";
* `ExpiredTokenRemover` deletes documents older than 24 hours, after which
  the cluster does not know the token and refuses it like any other.

The mock answered an expired token with the generic "unable to
authenticate" and the Basic/ApiKey challenge, refreshed a week-old refresh
token, and kept every token until a cap of 5,000 evicted the oldest.
"""
from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from api.routers.es_auth import reap_tokens
from repository.store import store
from tests.clock import Clock

BASIC = {"Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode()}
EXPIRED = 'Bearer realm="security", error="invalid_token", error_description="The access token expired"'


def _pair(client: TestClient) -> dict:
    response = client.post("/elastic/_security/oauth2/token", headers=BASIC, json={
        "grant_type": "password", "username": "elastic", "password": "mock-elastic-password",
    })
    assert response.status_code == 200, response.text
    return dict(response.json())


def _health(client: TestClient, token: str) -> object:
    return client.get("/elastic/_cluster/health", headers={"Authorization": f"Bearer {token}"})


def test_an_expired_token_says_so(client: TestClient, clock: Clock) -> None:
    token = _pair(client)["access_token"]
    assert _health(client, token).status_code == 200  # type: ignore[attr-defined]
    clock.advance(1201)

    response = _health(client, token)
    assert response.status_code == 401  # type: ignore[attr-defined]
    assert response.headers["www-authenticate"] == EXPIRED  # type: ignore[attr-defined]
    error = response.json()["error"]  # type: ignore[attr-defined]
    assert error["reason"] == "token expired"
    assert error["header"] == {"WWW-Authenticate": [EXPIRED]}


def test_an_invalidated_token_is_refused_the_same_way(client: TestClient) -> None:
    token = _pair(client)["access_token"]
    client.request("DELETE", "/elastic/_security/oauth2/token", headers=BASIC,
                   json={"token": token})

    response = _health(client, token)
    assert response.status_code == 401  # type: ignore[attr-defined]
    assert response.json()["error"]["reason"] == "token expired"  # type: ignore[attr-defined]


def test_a_refresh_token_lives_a_day(client: TestClient, clock: Clock) -> None:
    young, old = _pair(client), _pair(client)
    clock.advance(days=1, seconds=-60)
    refreshed = client.post("/elastic/_security/oauth2/token", headers=BASIC, json={
        "grant_type": "refresh_token", "refresh_token": young["refresh_token"],
    })
    assert refreshed.status_code == 200, refreshed.text
    clock.advance(61)

    refused = client.post("/elastic/_security/oauth2/token", headers=BASIC, json={
        "grant_type": "refresh_token", "refresh_token": old["refresh_token"],
    })
    assert refused.status_code == 400
    assert refused.json() == {"error": "invalid_grant",
                              "error_description": "token document has expired"}


def test_documents_older_than_a_day_are_deleted(client: TestClient, clock: Clock) -> None:
    old = _pair(client)
    clock.advance(days=1, seconds=1)
    fresh = _pair(client)

    assert reap_tokens() == 2  # the old access token and its refresh token
    assert store.get("es_tokens", old["access_token"]) is None
    assert store.get("es_tokens", fresh["access_token"]) is not None
    # Deleted, the token is nobody's: the generic refusal again.
    gone = _health(client, old["access_token"])
    assert gone.json()["error"]["reason"].startswith("unable to authenticate")  # type: ignore[attr-defined]
