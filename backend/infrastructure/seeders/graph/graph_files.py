"""Seed Microsoft Graph OneDrive drives, drive items, and SharePoint sites."""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.drive import GraphDrive
from domain.graph.drive_item import GraphDriveItem
from domain.graph.sharepoint_site import GraphSharePointSite
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import GRAPH_DOMAIN, graph_uuid
from repository.graph.drive_item_repo import graph_drive_item_repo
from repository.graph.drive_repo import graph_drive_repo
from repository.graph.sharepoint_site_repo import graph_sharepoint_site_repo

# Item definitions: (name, is_folder, mimeType_or_None, size_range)
_ITEM_SPECS: list[tuple[str, bool, str | None, tuple[int, int]]] = [
    ("Documents", True, None, (0, 0)),
    ("Downloads", True, None, (0, 0)),
    ("report.docx", False, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", (50_000, 500_000)),
    ("budget.xlsx", False, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", (30_000, 300_000)),
    ("presentation.pptx", False, "application/vnd.openxmlformats-officedocument.presentationml.presentation", (1_000_000, 10_000_000)),
    ("photo.jpg", False, "image/jpeg", (500_000, 5_000_000)),
    ("notes.txt", False, "text/plain", (500, 5_000)),
    ("project-plan.pdf", False, "application/pdf", (100_000, 2_000_000)),
]


def seed_graph_files(fake: Faker, user_ids: list[str]) -> None:
    """Create OneDrive drives and items for first 5 users, plus SharePoint sites."""
    target_users = user_ids[:5]

    for user_id in target_users:
        drive_id = graph_uuid()
        owner_name = fake.name()

        graph_drive_repo.save(
            GraphDrive(
                id=drive_id,
                name="OneDrive",
                driveType="personal",
                owner={"user": {"id": user_id, "displayName": owner_name}},
                quota={
                    "total": 1_099_511_627_776,  # 1 TB
                    "used": random.randint(100_000_000, 50_000_000_000),
                    "remaining": 0,  # computed below
                },
                webUrl=f"https://{GRAPH_DOMAIN.replace('.onmicrosoft.com', '')}-my.sharepoint.com/personal/{user_id}",
                _user_id=user_id,
            ),
        )

        # Create root-level items
        root_path = "/drive/root:"
        folder_count = 0
        for item_name, is_folder, mime_type, size_range in _ITEM_SPECS:
            item_id = graph_uuid()
            created = rand_ago(max_days=180)
            modified = rand_ago(max_days=30)
            size = 0 if is_folder else random.randint(*size_range)

            file_prop = None if is_folder else {"mimeType": mime_type}
            folder_prop = {"childCount": random.randint(1, 10)} if is_folder else None
            if is_folder:
                folder_count += 1

            graph_drive_item_repo.save(
                GraphDriveItem(
                    id=item_id,
                    name=item_name,
                    size=size,
                    createdDateTime=created,
                    lastModifiedDateTime=modified,
                    webUrl=f"https://{GRAPH_DOMAIN.replace('.onmicrosoft.com', '')}-my.sharepoint.com/{item_name}",
                    file=file_prop,
                    folder=folder_prop,
                    parentReference={
                        "driveId": drive_id,
                        "id": "root",
                        "path": root_path,
                    },
                    createdBy={"user": {"id": user_id, "displayName": owner_name}},
                    lastModifiedBy={"user": {"id": user_id, "displayName": owner_name}},
                    _drive_id=drive_id,
                ),
            )

    # SharePoint sites
    _sites = [
        ("Company Intranet", "company-intranet"),
        ("IT Documentation", "it-documentation"),
    ]
    for display_name, slug in _sites:
        graph_sharepoint_site_repo.save(
            GraphSharePointSite(
                id=graph_uuid(),
                name=slug,
                displayName=display_name,
                webUrl=f"https://{GRAPH_DOMAIN.replace('.onmicrosoft.com', '')}.sharepoint.com/sites/{slug}",
                createdDateTime=rand_ago(max_days=365),
            ),
        )
