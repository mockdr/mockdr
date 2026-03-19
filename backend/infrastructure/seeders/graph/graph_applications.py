"""Seed Microsoft Graph application registrations."""
from __future__ import annotations

from faker import Faker

from domain.graph.application import GraphApplication
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.application_repo import graph_application_repo
from utils.dt import utc_now


def seed_graph_applications(fake: Faker) -> None:
    """Create five application registrations for the mock tenant."""
    now = utc_now()

    apps: list[GraphApplication] = [
        GraphApplication(
            id=graph_uuid(),
            appId=graph_uuid(),
            displayName="mockdr-test-app",
            signInAudience="AzureADMyOrg",
            createdDateTime=now,
            web={"redirectUris": ["https://localhost/callback"]},
            api={},
            requiredResourceAccess=[
                {
                    "resourceAppId": "00000003-0000-0000-c000-000000000000",
                    "resourceAccess": [
                        {"id": graph_uuid(), "type": "Scope"},
                    ],
                },
            ],
        ),
        GraphApplication(
            id=graph_uuid(),
            appId=graph_uuid(),
            displayName="SOAR-Integration",
            signInAudience="AzureADMyOrg",
            createdDateTime=now,
            web={},
            api={},
            requiredResourceAccess=[
                {
                    "resourceAppId": "00000003-0000-0000-c000-000000000000",
                    "resourceAccess": [
                        {"id": graph_uuid(), "type": "Role"},
                        {"id": graph_uuid(), "type": "Role"},
                    ],
                },
            ],
        ),
        GraphApplication(
            id=graph_uuid(),
            appId=graph_uuid(),
            displayName="SIEM-Connector",
            signInAudience="AzureADMyOrg",
            createdDateTime=now,
            web={},
            api={},
            requiredResourceAccess=[
                {
                    "resourceAppId": "00000003-0000-0000-c000-000000000000",
                    "resourceAccess": [
                        {"id": graph_uuid(), "type": "Role"},
                    ],
                },
            ],
        ),
        GraphApplication(
            id=graph_uuid(),
            appId=graph_uuid(),
            displayName="Automation-Script",
            signInAudience="AzureADMyOrg",
            createdDateTime=now,
            web={},
            api={},
            requiredResourceAccess=[],
        ),
        GraphApplication(
            id=graph_uuid(),
            appId=graph_uuid(),
            displayName="Dashboard-App",
            signInAudience="AzureADMultipleOrgs",
            createdDateTime=now,
            web={"redirectUris": ["https://dashboard.acmecorp.com/auth"]},
            api={},
            requiredResourceAccess=[
                {
                    "resourceAppId": "00000003-0000-0000-c000-000000000000",
                    "resourceAccess": [
                        {"id": graph_uuid(), "type": "Scope"},
                    ],
                },
            ],
        ),
    ]

    for app in apps:
        graph_application_repo.save(app)
