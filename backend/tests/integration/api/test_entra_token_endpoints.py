"""The Graph and Defender token endpoints behave like the Entra endpoint they stand in for.

Five things a real client meets at ``login.microsoftonline.com`` that the two
mounts got wrong:

* HTTP Basic client authentication. "The Basic auth pattern of instead
  providing credentials in the Authorization header, per RFC 6749 is also
  supported"
  (https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow).
  Both mounts required the secret as a form field and refused the request.
* The scope. It "should be the resource identifier (application ID URI) of
  the resource you want, suffixed with .default. All scopes included must be
  for a single resource" (same page); otherwise ``400 invalid_scope``
  AADSTS70011. Both mounts minted a token for ``scope=x``.
* An unknown application is ``400 unauthorized_client`` AADSTS700016
  ("Application with identifier ... was not found in the directory"), not the
  ``401 invalid_client`` AADSTS7000215 of a wrong secret.
* Discovery: MSAL and azure-identity read
  ``{authority}/v2.0/.well-known/openid-configuration`` before the token call
  (https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc),
  and the mock served none.
* Graph's 401 challenge names the authority's ``/authorize`` endpoint and
  Graph's app ID (https://learn.microsoft.com/en-us/entra/msal/dotnet/advanced/extract-authentication-parameters);
  the mock named the token endpoint, from which no authority can be derived.
"""
from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from infrastructure.seeders.graph.graph_shared import GRAPH_TENANT_ID
from infrastructure.seeders.mde_shared import MDE_TENANT_ID

GRAPH = ("/graph", "graph-mock-admin-client", "graph-mock-admin-secret",
         "https://graph.microsoft.com/.default", "/graph/v1.0/users")
MDE = ("/mde", "mde-mock-admin-client", "mde-mock-admin-secret",
       "https://api.securitycenter.microsoft.com/.default", "/mde/api/machines")
MOUNTS = [GRAPH, MDE]


def _basic(client_id: str, secret: str) -> dict[str, str]:
    raw = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {raw}"}


class TestClientSecretBasic:
    """The secret may come in the Authorization header instead of the body."""

    @pytest.mark.parametrize(("mount", "cid", "secret", "scope", "probe"), MOUNTS)
    def test_basic_credentials_get_a_working_token(
        self, client: TestClient, mount: str, cid: str, secret: str, scope: str, probe: str,
    ) -> None:
        response = client.post(f"{mount}/oauth2/v2.0/token", headers=_basic(cid, secret),
                               data={"grant_type": "client_credentials", "scope": scope})
        assert response.status_code == 200, response.text
        token = response.json()["access_token"]
        assert client.get(probe, headers={"Authorization": f"Bearer {token}"}).status_code == 200

    def test_a_wrong_basic_secret_is_still_refused(self, client: TestClient) -> None:
        response = client.post("/mde/oauth2/v2.0/token",
                               headers=_basic("mde-mock-admin-client", "nope"),
                               data={"grant_type": "client_credentials", "scope": MDE[3]})
        assert response.status_code == 401
        assert response.json()["error"] == "invalid_client"


class TestScopeIsValidated:
    """Only `{this API}/.default` gets a token."""

    @pytest.mark.parametrize("scope", [
        "x",
        "User.Read",
        "https://graph.microsoft.com/User.Read",
        "https://graph.microsoft.com/.default https://management.azure.com/.default",
        "https://api.securitycenter.microsoft.com/.default",
    ])
    def test_graph_refuses_a_scope_it_would_not_issue(
        self, client: TestClient, scope: str,
    ) -> None:
        response = client.post("/graph/oauth2/v2.0/token", data={
            "client_id": GRAPH[1], "client_secret": GRAPH[2],
            "grant_type": "client_credentials", "scope": scope,
        })
        assert response.status_code == 400
        body = response.json()
        assert body["error"] == "invalid_scope"
        assert body["error_codes"] == [70011]
        assert body["error_description"].startswith("AADSTS70011:")

    def test_defender_refuses_a_graph_scope(self, client: TestClient) -> None:
        response = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": MDE[1], "client_secret": MDE[2],
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        })
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_scope"

    @pytest.mark.parametrize("scope", [
        "https://api.security.microsoft.com/.default",
        "https://API.SecurityCenter.Microsoft.com//.default",
    ])
    def test_defender_accepts_its_other_identifiers(
        self, client: TestClient, scope: str,
    ) -> None:
        response = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": MDE[1], "client_secret": MDE[2],
            "grant_type": "client_credentials", "scope": scope,
        })
        assert response.status_code == 200, response.text


class TestUnknownClient:
    """An application Entra never heard of is AADSTS700016."""

    @pytest.mark.parametrize(("mount", "cid", "secret", "scope", "probe"), MOUNTS)
    def test_unknown_client_is_unauthorized_client(
        self, client: TestClient, mount: str, cid: str, secret: str, scope: str, probe: str,
    ) -> None:
        response = client.post(f"{mount}/oauth2/v2.0/token", data={
            "client_id": "no-such-app", "client_secret": secret,
            "grant_type": "client_credentials", "scope": scope,
        })
        assert response.status_code == 400
        body = response.json()
        assert body["error"] == "unauthorized_client"
        assert body["error_codes"] == [700016]
        assert "Application with identifier 'no-such-app' was not found" in body["error_description"]


class TestDiscovery:
    """The authority's discovery document leads to a token endpoint that works."""

    @pytest.mark.parametrize(("mount", "cid", "secret", "scope", "probe", "tenant"), [
        (*GRAPH, GRAPH_TENANT_ID), (*MDE, MDE_TENANT_ID),
    ])
    def test_token_endpoint_from_discovery_issues_a_token(
        self, client: TestClient, mount: str, cid: str, secret: str, scope: str, probe: str,
        tenant: str,
    ) -> None:
        doc = client.get(f"http://mock.example{mount}/{tenant}/v2.0/.well-known/openid-configuration")
        assert doc.status_code == 200
        body = doc.json()
        assert body["token_endpoint"] == f"http://mock.example{mount}/{tenant}/oauth2/v2.0/token"
        assert "client_secret_basic" in body["token_endpoint_auth_methods_supported"]
        assert body["issuer"] == f"http://mock.example{mount}/{tenant}/v2.0"
        keys = client.get(body["jwks_uri"]).json()["keys"]
        assert [(k["kty"], k["use"], k["issuer"]) for k in keys] == [
            ("RSA", "sig", body["issuer"])]

        # What MSAL does next: POST to the token_endpoint it just read.
        issued = client.post(body["token_endpoint"], headers=_basic(cid, secret),
                             data={"grant_type": "client_credentials", "scope": scope})
        assert issued.status_code == 200, issued.text
        token = issued.json()["access_token"]
        assert client.get(probe, headers={"Authorization": f"Bearer {token}"}).status_code == 200

    @pytest.mark.parametrize("mount", ["/graph", "/mde"])
    @pytest.mark.parametrize(
        "route", ["v2.0/.well-known/openid-configuration", "discovery/v2.0/keys"],
    )
    def test_a_tenant_the_mount_does_not_host_is_refused(
        self, client: TestClient, mount: str, route: str,
    ) -> None:
        """Entra answers discovery for an unknown tenant ``400 invalid_tenant``.

        Both routes served any tenant segment, and the key set's never read it.
        The hosted tenant, its verified domain and the multi-tenant aliases
        still resolve.
        """
        unknown = client.get(f"{mount}/00000000-0000-0000-0000-00000000dead/{route}")
        assert unknown.status_code == 400
        assert unknown.json()["error"] == "invalid_tenant"
        assert unknown.json()["error_codes"] == [90002]
        for tenant in (GRAPH_TENANT_ID, "acmecorp.onmicrosoft.com", "common"):
            assert client.get(f"{mount}/{tenant}/{route}").status_code == 200

    def test_the_common_document_keeps_the_issuer_template(self, client: TestClient) -> None:
        body = client.get("/graph/common/v2.0/.well-known/openid-configuration").json()
        assert body["issuer"].endswith("/graph/{tenantid}/v2.0")


class TestGraphChallengeNamesTheAuthority:
    """Graph's 401 points at `/authorize` and names Graph's application ID."""

    def test_challenge_matches_graphs_own(self, client: TestClient) -> None:
        challenge = client.get("/graph/v1.0/users").headers["www-authenticate"]
        assert challenge == (
            'Bearer realm="", '
            'authorization_uri="http://testserver/graph/common/oauth2/authorize", '
            'client_id="00000003-0000-0000-c000-000000000000"'
        )
