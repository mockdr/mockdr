"""The Microsoft mounts issue JWT access tokens, as Entra does, and publish their key.

"Access tokens are JSON web tokens (JWT)"
(https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference).
Graph and Defender issued a uuid and Sentinel 64 hex digits, so a connector
that decodes its token -- for ``exp``, ``tid``, ``roles``, ``appid`` or
``oid`` -- failed on the first decode against the mock and worked against
Azure; and ``jwks_uri`` served no key, so nothing a test received could be
checked against it.

Every resource the mounts front (Graph, WindowsDefenderATP, Azure Resource
Manager, Log Analytics) accepts v1.0 tokens, and Entra issues the version
the resource asks for, from either endpoint
(https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens), so
the tokens are v1.0: issuer ``https://sts.windows.net/{tid}/``, ``appid``
and ``appidacr``, and ``x5t`` beside ``kid`` in the header.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any
from urllib.parse import urlsplit

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

import utils.entra_access_token as entra_access_token
from api.graph_auth import FEATURE_GATES
from utils.entra_access_token import mint_access_token, service_principal_object_id
from utils.entra_app_roles import graph_roles, mde_roles

TENANT = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
ADMIN = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}

#: (mount, client id, secret, scope, the aud the token carries, an API call it opens)
GRAPH = ("/graph", "graph-mock-admin-client", "graph-mock-admin-secret",
         "https://graph.microsoft.com/.default", "https://graph.microsoft.com",
         "/graph/v1.0/users")
MDE = ("/mde", "mde-mock-admin-client", "mde-mock-admin-secret",
       "https://api.securitycenter.microsoft.com/.default",
       "https://api.securitycenter.microsoft.com", "/mde/api/machines")
ARM = ("/sentinel", "sentinel-mock-client-id", "sentinel-mock-client-secret",
       "https://management.azure.com/.default", "https://management.azure.com/",
       "/sentinel/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/"
       "mockdr-rg/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace/"
       "providers/Microsoft.SecurityInsights/incidents?api-version=2024-03-01")
LOGS = ("/sentinel", "sentinel-mock-client-id", "sentinel-mock-client-secret",
        "https://api.loganalytics.io/.default", "https://api.loganalytics.io", None)
ALL = [GRAPH, MDE, ARM, LOGS]
IDS = ["graph", "mde", "arm", "log-analytics"]


def _unb64(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _decode(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Header and claims, without verifying -- what a connector does."""
    header, payload, _ = token.split(".")
    return json.loads(_unb64(header)), json.loads(_unb64(payload))


def _issue(client: TestClient, mount: str, cid: str, secret: str, scope: str) -> dict:
    response = client.post(f"{mount}/{TENANT}/oauth2/v2.0/token", data={
        "client_id": cid, "client_secret": secret,
        "grant_type": "client_credentials", "scope": scope,
    })
    assert response.status_code == 200, response.text
    return response.json()


def _served_keys(client: TestClient, mount: str) -> list[dict]:
    """The key set, found the way MSAL finds it: through the discovery document."""
    doc = client.get(f"{mount}/{TENANT}/v2.0/.well-known/openid-configuration").json()
    return client.get(urlsplit(doc["jwks_uri"]).path).json()["keys"]


def _verify(token: str, keys: list[dict]) -> None:
    """Check the RS256 signature with the served key the header's ``kid`` names."""
    header, _ = _decode(token)
    assert header["alg"] == "RS256"
    jwk = next(k for k in keys if k["kid"] == header["kid"])
    public = rsa.RSAPublicNumbers(
        int.from_bytes(_unb64(jwk["e"]), "big"), int.from_bytes(_unb64(jwk["n"]), "big"),
    ).public_key()
    signing_input, _, signature = token.rpartition(".")
    public.verify(_unb64(signature), signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())


class TestTokensAreV1Jwts:
    """Each mount's token decodes to the claims an app-only v1.0 token carries."""

    @pytest.mark.parametrize(("mount", "cid", "secret", "scope", "aud", "probe"), ALL, ids=IDS)
    def test_the_header_names_the_key(
        self, client: TestClient, mount: str, cid: str, secret: str, scope: str, aud: str,
        probe: str | None,
    ) -> None:
        """``typ`` JWT, ``alg`` RS256, and ``kid`` with v1.0's legacy ``x5t`` beside it."""
        header, _ = _decode(_issue(client, mount, cid, secret, scope)["access_token"])
        assert header == {"typ": "JWT", "alg": "RS256", "x5t": header["kid"],
                          "kid": header["kid"]}

    @pytest.mark.parametrize(("mount", "cid", "secret", "scope", "aud", "probe"), ALL, ids=IDS)
    def test_the_claims_are_an_app_only_tokens(
        self, client: TestClient, mount: str, cid: str, secret: str, scope: str, aud: str,
        probe: str | None,
    ) -> None:
        body = _issue(client, mount, cid, secret, scope)
        _, claims = _decode(body["access_token"])
        principal = service_principal_object_id(TENANT, cid)
        assert claims["aud"] == aud
        assert claims["iss"] == claims["idp"] == f"https://sts.windows.net/{TENANT}/"
        assert claims["tid"] == TENANT
        assert claims["appid"] == cid
        assert claims["appidacr"] == "1"
        assert claims["idtyp"] == "app"
        assert claims["oid"] == claims["sub"] == principal
        assert claims["ver"] == "1.0"
        assert len(claims["uti"]) == 22
        assert "azp" not in claims and "scp" not in claims

    @pytest.mark.parametrize(("mount", "cid", "secret", "scope", "aud", "probe"), ALL, ids=IDS)
    def test_exp_agrees_with_expires_in(
        self, client: TestClient, mount: str, cid: str, secret: str, scope: str, aud: str,
        probe: str | None,
    ) -> None:
        """A client scheduling its refresh from ``exp`` or ``expires_in`` gets one answer.

        ``iat`` and ``nbf`` are backdated five minutes, as Entra's are: the
        reference's v1.0 example token has ``exp - iat`` of 3900 seconds.
        """
        before = int(time.time())
        body = _issue(client, mount, cid, secret, scope)
        after = int(time.time())
        _, claims = _decode(body["access_token"])
        assert before + body["expires_in"] <= claims["exp"] <= after + body["expires_in"]
        assert claims["iat"] == claims["nbf"] == claims["exp"] - body["expires_in"] - 300

    def test_aud_is_the_resource_the_scope_named(self, client: TestClient) -> None:
        """v1.0: "it can be the client ID or the resource URI used in the request"."""
        body = _issue(client, "/mde", MDE[1], MDE[2],
                      "fc780465-2017-40d4-a0c5-307022471b92/.default")
        assert _decode(body["access_token"])[1]["aud"] == "fc780465-2017-40d4-a0c5-307022471b92"


class TestSignatureVerifiesAgainstTheServedKeys:
    """A token checks out against the key set ``jwks_uri`` serves."""

    @pytest.mark.parametrize(("mount", "cid", "secret", "scope", "aud", "probe"), ALL, ids=IDS)
    def test_signature_verifies(
        self, client: TestClient, mount: str, cid: str, secret: str, scope: str, aud: str,
        probe: str | None,
    ) -> None:
        token = _issue(client, mount, cid, secret, scope)["access_token"]
        _verify(token, _served_keys(client, mount))

    def test_a_changed_claim_no_longer_verifies(self, client: TestClient) -> None:
        token = _issue(client, *GRAPH[:4])["access_token"]
        header, payload, signature = token.split(".")
        claims = json.loads(_unb64(payload))
        claims["roles"] = ["Directory.ReadWrite.All"]
        forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        with pytest.raises(InvalidSignature):
            _verify(f"{header}.{forged}.{signature}", _served_keys(client, "/graph"))

    @pytest.mark.parametrize("mount", ["/graph", "/mde", "/sentinel"])
    def test_the_key_is_in_entras_keys_document_shape(
        self, client: TestClient, mount: str,
    ) -> None:
        """The members of ``login.microsoftonline.com/{tenant}/discovery/v2.0/keys``.

        ``kid`` and ``x5t`` are the SHA-1 thumbprint of the ``x5c``
        certificate, and the certificate holds the same public key as ``n``
        and ``e``.
        """
        doc = client.get(f"{mount}/{TENANT}/v2.0/.well-known/openid-configuration").json()
        (key,) = _served_keys(client, mount)
        assert set(key) == {"kty", "use", "kid", "x5t", "n", "e", "x5c",
                            "cloud_instance_name", "issuer"}
        assert (key["kty"], key["use"], key["e"]) == ("RSA", "sig", "AQAB")
        assert key["issuer"] == doc["issuer"]
        assert doc["id_token_signing_alg_values_supported"] == ["RS256"]
        der = base64.b64decode(key["x5c"][0])
        thumbprint = base64.urlsafe_b64encode(hashlib.sha1(der, usedforsecurity=False).digest()).rstrip(b"=").decode()
        assert key["kid"] == key["x5t"] == thumbprint
        public = x509.load_der_x509_certificate(der).public_key()
        assert isinstance(public, rsa.RSAPublicKey)
        assert public.public_numbers().n == int.from_bytes(_unb64(key["n"]), "big")

    def test_every_mount_serves_the_one_key(self, client: TestClient) -> None:
        kids = {_served_keys(client, m)[0]["kid"] for m in ("/graph", "/mde", "/sentinel")}
        assert len(kids) == 1


class TestRolesListTheClientsPermissions:
    """``roles`` carries the application permissions the seeded client holds."""

    def _roles(self, client: TestClient, mount: str, cid: str, scope: str) -> list[str]:
        secret = cid.removesuffix("-client") + "-secret"
        claims = _decode(_issue(client, mount, cid, secret, scope)["access_token"])[1]
        return list(claims.get("roles", []))

    def test_graph_admin(self, client: TestClient) -> None:
        roles = self._roles(client, "/graph", "graph-mock-admin-client", GRAPH[3])
        for permission in ("SecurityAlert.ReadWrite.All", "SecurityIncident.ReadWrite.All",
                           "ThreatHunting.Read.All", "User.ReadWrite.All",
                           "Directory.ReadWrite.All"):
            assert permission in roles

    def test_graph_security_contributor_reads_the_directory(self, client: TestClient) -> None:
        roles = self._roles(client, "/graph", "graph-mock-security-client", GRAPH[3])
        assert {"SecurityAlert.ReadWrite.All", "ThreatHunting.Read.All",
                "User.Read.All"} <= set(roles)
        assert "User.ReadWrite.All" not in roles

    def test_graph_plan1_reader_holds_no_security_permission(self, client: TestClient) -> None:
        roles = self._roles(client, "/graph", "graph-mock-p1-client", GRAPH[3])
        assert "User.Read.All" in roles
        assert not [r for r in roles if r.startswith(("Security", "ThreatHunting"))]
        assert not [r for r in roles if "ReadWrite" in r]

    @pytest.mark.parametrize(("role_client", "present", "absent"), [
        ("mde-mock-viewer-client", {"Alert.Read.All", "Machine.Read.All",
                                    "AdvancedQuery.Read.All"},
         {"Alert.ReadWrite.All", "Machine.Isolate", "Ti.ReadWrite.All"}),
        ("mde-mock-analyst-client", {"Alert.ReadWrite.All", "Machine.Isolate",
                                     "Ti.ReadWrite.All", "Machine.Read.All"},
         {"Machine.ReadWrite.All", "Machine.Offboard"}),
        ("mde-mock-admin-client", {"Alert.ReadWrite.All", "Machine.ReadWrite.All",
                                   "Machine.LiveResponse", "AdvancedQuery.Read.All"},
         {"Alert.Read.All", "Machine.Read.All"}),
    ])
    def test_defender_per_role(
        self, client: TestClient, role_client: str, present: set[str], absent: set[str],
    ) -> None:
        roles = set(self._roles(client, "/mde", role_client, MDE[3]))
        assert present <= roles
        assert not absent & roles

    @pytest.mark.parametrize("scope", [ARM[3], LOGS[3]])
    def test_arm_and_log_analytics_tokens_carry_none(
        self, client: TestClient, scope: str,
    ) -> None:
        """Both authorize an application by Azure RBAC, so Entra puts no ``roles`` in."""
        claims = _decode(_issue(client, *ARM[:3], scope)["access_token"])[1]
        assert "roles" not in claims

    @pytest.mark.parametrize("plan", ["plan1", "plan2", "defender_for_business", "none"])
    def test_graph_roles_follow_the_feature_gates(self, plan: str) -> None:
        """A plan the alerts, hunting and Intune gates open holds their permissions."""
        roles = set(graph_roles("reader", plan))
        opens = {feature: gate == "any" or plan in gate
                 for feature, gate in FEATURE_GATES.items()}
        assert ("SecurityAlert.Read.All" in roles) == opens["security/alerts_v2"]
        assert ("SecurityIncident.Read.All" in roles) == opens["security/incidents"]
        assert ("ThreatHunting.Read.All" in roles) == opens["security/runHuntingQuery"]
        assert ("DeviceManagementManagedDevices.Read.All" in roles) == opens["deviceManagement"]
        assert ("IdentityRiskyUser.Read.All" in roles) == opens["identityProtection"]

    def test_an_unknown_defender_role_reads_only(self) -> None:
        assert mde_roles("nobody") == mde_roles("viewer")


class TestTheServicePrincipalIsStable:
    """``oid`` and ``sub`` name the client's service principal, the same each time."""

    def test_same_client_same_oid_across_tokens_and_a_reset(self, client: TestClient) -> None:
        first = _decode(_issue(client, *GRAPH[:4])["access_token"])[1]
        assert client.post("/web/api/v2.1/_dev/reset", headers=ADMIN).status_code == 200
        second = _decode(_issue(client, *GRAPH[:4])["access_token"])[1]
        assert first["oid"] == second["oid"]
        assert first["uti"] != second["uti"]

    def test_each_client_has_its_own(self, client: TestClient) -> None:
        oids = {
            _decode(_issue(client, "/mde", f"mde-mock-{r}-client", f"mde-mock-{r}-secret",
                           MDE[3])["access_token"])[1]["oid"]
            for r in ("admin", "analyst", "viewer")
        }
        assert len(oids) == 3


class TestTheStoreStillDecides:
    """The signature mints and publishes; acceptance is still the token store's."""

    @pytest.mark.parametrize(("path", "status"), [("/graph/v1.0/users", 401),
                                                  ("/mde/api/machines", 401)])
    def test_a_validly_signed_token_never_issued_is_refused(
        self, client: TestClient, path: str, status: int,
    ) -> None:
        """Signed with the served key, carrying every claim, but not in the store."""
        from datetime import UTC, datetime
        forged = mint_access_token(
            tenant_id=TENANT, client_id="graph-mock-admin-client",
            audience="https://graph.microsoft.com", roles=["User.Read.All"],
            issued_at=datetime.now(UTC), lifetime_seconds=3599,
        )
        _verify(forged, _served_keys(client, "/graph"))
        response = client.get(path, headers={"Authorization": f"Bearer {forged}"})
        assert response.status_code == status

    @pytest.mark.parametrize(("mount", "cid", "secret", "scope", "aud", "probe"),
                             [GRAPH, MDE, ARM], ids=IDS[:3])
    def test_a_token_from_an_earlier_key_is_still_accepted(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch, mount: str, cid: str,
        secret: str, scope: str, aud: str, probe: str,
    ) -> None:
        """As after a restart with ``MOCKDR_PERSIST``: a new process, a new key.

        The token stays valid because the store holds it; it no longer
        verifies against the key set the new key replaced.
        """
        token = _issue(client, mount, cid, secret, scope)["access_token"]
        monkeypatch.setattr(entra_access_token, "_signing_key", None)
        assert client.get(probe, headers={"Authorization": f"Bearer {token}"}).status_code == 200
        with pytest.raises(InvalidSignature):
            _verify(token, [{**k, "kid": _decode(token)[0]["kid"]}
                            for k in _served_keys(client, mount)])


class TestTheKeyIsNeverExported:
    """``/_dev/export`` strips secrets; the signing key never reaches it."""

    def test_export_holds_no_private_key(self, client: TestClient) -> None:
        _issue(client, *GRAPH[:4])
        response = client.get("/web/api/v2.1/_dev/export", headers=ADMIN)
        assert response.status_code == 200
        exported = response.text
        assert "graph_oauth_tokens" in exported
        private = entra_access_token.signing_key().private_key.private_numbers()
        assert "PRIVATE KEY" not in exported
        assert str(private.d) not in exported
        d = base64.urlsafe_b64encode(
            private.d.to_bytes((private.d.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
        assert d not in exported
