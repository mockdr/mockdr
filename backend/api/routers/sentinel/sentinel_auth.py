"""Sentinel's Entra authority: token endpoint, discovery document and key set.

The same authority Graph and Defender front (:mod:`api.entra_authority`),
so the three answer one way: the secret in the body or in HTTP Basic, an
unknown application ``400 unauthorized_client`` AADSTS700016, a wrong
secret ``401 invalid_client``. This directory's own part is the token: it
is issued for whichever resource the ``scope`` names and remembers it as
its audience, and Azure Resource Manager and the Logs query API each refuse
a token issued for the other (:mod:`api.sentinel_auth`) -- so no scope rule
is applied here, the APIs apply it.

azure-identity's ``ClientSecretCredential`` -- the credential
``azure-mgmt-securityinsight`` and ``azure-monitor-query`` take -- hands its
authority to MSAL, which reads the discovery document before anything else
(``msal/authority.py``, ``tenant_discovery``), and the document advertises
``client_secret_basic``, which this directory did not accept until it shared
the authority.
"""
from __future__ import annotations

from api.entra_authority import EntraDirectory, entra_authority_router
from application.sentinel.commands.auth import find_client, mint_token, registered_clients

router = entra_authority_router(EntraDirectory(
    mount="/sentinel",
    find_client=find_client,
    clients=registered_clients,
    mint=mint_token,
), "Sentinel Auth")
