"""The Sentinel mount is an Entra authority azure-identity can use.

``azure.identity.ClientSecretCredential`` -- what azure-mgmt-securityinsight
and azure-monitor-query are built to take -- hands its ``authority`` to MSAL,
and MSAL's first request is ``GET {authority}/{tenant}/v2.0/.well-known/
openid-configuration`` (``msal/authority.py``, ``tenant_discovery``); only
then does it POST to the ``token_endpoint`` it read there. /graph and /mde
served the document; /sentinel answered 404, so the credential failed with
"Unable to get authority configuration" before any ARM call was made, and an
Azure SDK could not be pointed at this mount at all.

The exchange below is MSAL's: discovery, then the token endpoint it names,
then an ARM read with the token.
"""
from __future__ import annotations

from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

TENANT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
INCIDENTS = (
    "/sentinel/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/mockdr-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace"
    "/providers/Microsoft.SecurityInsights/incidents"
)


class TestDiscovery:
    """MSAL's discovery, token and first call, in order."""

    @pytest.mark.parametrize("tenant", [TENANT, "acmecorp.onmicrosoft.com"])
    def test_msal_flow_reaches_arm(self, client: TestClient, tenant: str) -> None:
        doc = client.get(f"https://mock.example/sentinel/{tenant}/v2.0/.well-known/openid-configuration")
        assert doc.status_code == 200, doc.text
        body = doc.json()
        assert body["token_endpoint"] == (
            f"https://mock.example/sentinel/{tenant}/oauth2/v2.0/token"
        )
        assert body["issuer"] == f"https://mock.example/sentinel/{tenant}/v2.0"
        keys = client.get(body["jwks_uri"]).json()["keys"]
        assert [(k["kty"], k["use"], k["issuer"]) for k in keys] == [
            ("RSA", "sig", body["issuer"])]

        issued = client.post(urlsplit(body["token_endpoint"]).path, data={
            "client_id": "sentinel-mock-client-id",
            "client_secret": "sentinel-mock-client-secret",
            "grant_type": "client_credentials",
            "scope": "https://management.azure.com/.default",
        })
        assert issued.status_code == 200, issued.text
        token = issued.json()["access_token"]
        listed = client.get(INCIDENTS, headers={"Authorization": f"Bearer {token}"})
        assert listed.status_code == 200, listed.text

    @pytest.mark.parametrize(
        "route", ["v2.0/.well-known/openid-configuration", "discovery/v2.0/keys"],
    )
    def test_a_tenant_this_directory_does_not_host_is_refused(
        self, client: TestClient, route: str,
    ) -> None:
        unknown = client.get(f"/sentinel/00000000-0000-0000-0000-00000000dead/{route}")
        assert unknown.status_code == 400
        assert unknown.json()["error"] == "invalid_tenant"
        assert unknown.json()["error_codes"] == [90002]
