"""Seed Microsoft Graph service principals (enterprise applications)."""
from __future__ import annotations

from faker import Faker

from domain.graph.service_principal import GraphServicePrincipal
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.service_principal_repo import graph_service_principal_repo


def seed_graph_service_principals(fake: Faker) -> None:
    """Create eight service principals (enterprise applications).

    Includes a mix of verified and unverified publishers with varying
    OAuth2 permission scopes for realistic app governance testing.
    """
    principals: list[GraphServicePrincipal] = [
        # --- Verified first-party Microsoft apps ---
        GraphServicePrincipal(
            id=graph_uuid(),
            appId=graph_uuid(),
            displayName="Microsoft Teams",
            publisherName="Microsoft Corporation",
            verifiedPublisher={"displayName": "Microsoft Corporation"},
            oauth2PermissionGrants=[
                {"scope": "User.Read"},
                {"scope": "Team.ReadBasic.All"},
            ],
            servicePrincipalType="Application",
            accountEnabled=True,
            tags=["WindowsAzureActiveDirectoryIntegratedApp"],
        ),
        GraphServicePrincipal(
            id=graph_uuid(),
            appId=graph_uuid(),
            displayName="Microsoft Graph Explorer",
            publisherName="Microsoft Corporation",
            verifiedPublisher={"displayName": "Microsoft Corporation"},
            oauth2PermissionGrants=[
                {"scope": "User.Read"},
                {"scope": "Directory.Read.All"},
            ],
            servicePrincipalType="Application",
            accountEnabled=True,
            tags=["WindowsAzureActiveDirectoryIntegratedApp"],
        ),
        # --- Verified internal (AcmeCorp) apps ---
        GraphServicePrincipal(
            id=graph_uuid(),
            appId=graph_uuid(),
            displayName="SOAR-Integration",
            publisherName="AcmeCorp",
            verifiedPublisher={"displayName": "AcmeCorp"},
            oauth2PermissionGrants=[
                {"scope": "SecurityEvents.Read.All"},
                {"scope": "SecurityActions.ReadWrite.All"},
            ],
            servicePrincipalType="Application",
            accountEnabled=True,
            tags=[],
        ),
        GraphServicePrincipal(
            id=graph_uuid(),
            appId=graph_uuid(),
            displayName="SIEM-Connector",
            publisherName="AcmeCorp",
            verifiedPublisher={"displayName": "AcmeCorp"},
            oauth2PermissionGrants=[
                {"scope": "SecurityEvents.Read.All"},
                {"scope": "AuditLog.Read.All"},
            ],
            servicePrincipalType="Application",
            accountEnabled=True,
            tags=[],
        ),
        # --- Unverified apps (no verified publisher) ---
        GraphServicePrincipal(
            id=graph_uuid(),
            appId=graph_uuid(),
            displayName="Shadow IT App",
            publisherName="",
            verifiedPublisher={"displayName": None},
            oauth2PermissionGrants=[
                {"scope": "User.Read"},
                {"scope": "Mail.Read"},
                {"scope": "Files.ReadWrite.All"},
            ],
            servicePrincipalType="Application",
            accountEnabled=True,
            tags=[],
        ),
        GraphServicePrincipal(
            id=graph_uuid(),
            appId=graph_uuid(),
            displayName="Employee Expense Tool",
            publisherName="",
            verifiedPublisher={"displayName": None},
            oauth2PermissionGrants=[
                {"scope": "User.Read"},
                {"scope": "Mail.Read"},
                {"scope": "Files.ReadWrite.All"},
            ],
            servicePrincipalType="Application",
            accountEnabled=True,
            tags=[],
        ),
        # --- Verified third-party apps ---
        GraphServicePrincipal(
            id=graph_uuid(),
            appId=graph_uuid(),
            displayName="CRM Dashboard",
            publisherName="Salesforce",
            verifiedPublisher={"displayName": "Salesforce"},
            oauth2PermissionGrants=[
                {"scope": "User.Read"},
            ],
            servicePrincipalType="Application",
            accountEnabled=True,
            tags=["WindowsAzureActiveDirectoryIntegratedApp"],
        ),
        GraphServicePrincipal(
            id=graph_uuid(),
            appId=graph_uuid(),
            displayName="Backup Service",
            publisherName="Veeam",
            verifiedPublisher={"displayName": "Veeam"},
            oauth2PermissionGrants=[
                {"scope": "User.Read"},
                {"scope": "Files.ReadWrite.All"},
            ],
            servicePrincipalType="Application",
            accountEnabled=True,
            tags=[],
        ),
    ]

    for sp in principals:
        graph_service_principal_repo.save(sp)
