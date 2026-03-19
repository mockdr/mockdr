"""Seed Microsoft Graph mail messages and folders."""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.mail_folder import GraphMailFolder
from domain.graph.mail_message import GraphMailMessage
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import GRAPH_DOMAIN, graph_uuid
from repository.graph.mail_folder_repo import graph_mail_folder_repo
from repository.graph.mail_message_repo import graph_mail_message_repo

# Folder definitions: (displayName, message_count)
_FOLDER_SPECS: list[tuple[str, int]] = [
    ("Inbox", 8),
    ("Sent Items", 4),
    ("Drafts", 2),
    ("Deleted Items", 1),
    ("Archive", 0),
]

_SUBJECTS: list[str] = [
    "Q4 Budget Review",
    "Project Alpha Status Update",
    "Meeting Tomorrow at 10am",
    "Action Required: Security Training",
    "Re: Vendor Contract Renewal",
    "Weekly Team Standup Notes",
    "Invitation: All-Hands Meeting",
    "FYI: New Office Policy",
    "Re: Customer Escalation #4421",
    "Travel Approval Request",
    "Updated: Sprint Planning",
    "Reminder: Expense Reports Due Friday",
    "New Hire Onboarding Checklist",
    "Quarterly Performance Review",
    "IT Maintenance Window Tonight",
]


def seed_graph_mail(fake: Faker, user_ids: list[str]) -> None:
    """Create mail folders and messages for the first 5 Graph users."""
    target_users = user_ids[:5]

    for user_id in target_users:
        # Create folders
        folder_ids: dict[str, str] = {}
        for folder_name, msg_count in _FOLDER_SPECS:
            folder_id = graph_uuid()
            folder_ids[folder_name] = folder_id

            # Count unread for this folder (will be set after messages created)
            graph_mail_folder_repo.save(
                GraphMailFolder(
                    id=folder_id,
                    displayName=folder_name,
                    parentFolderId=None,
                    childFolderCount=0,
                    totalItemCount=msg_count,
                    unreadItemCount=0,
                    _user_id=user_id,
                ),
            )

        # Create 15 messages per user, distributed across folders
        unread_counts: dict[str, int] = {name: 0 for name, _ in _FOLDER_SPECS}
        subjects = list(_SUBJECTS)
        random.shuffle(subjects)

        msg_idx = 0
        for folder_name, msg_count in _FOLDER_SPECS:
            for _ in range(msg_count):
                subject = subjects[msg_idx % len(subjects)]
                is_read = random.random() < 0.7
                sender_name = fake.name()
                sender_addr = f"{fake.user_name()}@{random.choice([GRAPH_DOMAIN, 'contoso.com', 'fabrikam.com'])}"
                recipient_name = fake.name()
                recipient_addr = f"{fake.user_name()}@{GRAPH_DOMAIN}"
                body_preview = fake.sentence(nb_words=20)

                if not is_read:
                    unread_counts[folder_name] += 1

                graph_mail_message_repo.save(
                    GraphMailMessage(
                        id=graph_uuid(),
                        subject=subject,
                        bodyPreview=body_preview,
                        body={
                            "contentType": "html",
                            "content": f"<html><body><p>{body_preview}</p></body></html>",
                        },
                        sender={
                            "emailAddress": {
                                "name": sender_name,
                                "address": sender_addr,
                            },
                        },
                        toRecipients=[
                            {
                                "emailAddress": {
                                    "name": recipient_name,
                                    "address": recipient_addr,
                                },
                            },
                        ],
                        receivedDateTime=rand_ago(max_days=30),
                        isRead=is_read,
                        importance=random.choice(["normal", "normal", "normal", "high", "low"]),
                        hasAttachments=random.random() < 0.2,
                        categories=[],
                        _user_id=user_id,
                        _folder_id=folder_ids[folder_name],
                    ),
                )
                msg_idx += 1

        # Update folder unread counts
        for folder_name, _ in _FOLDER_SPECS:
            folder_id = folder_ids[folder_name]
            folder = GraphMailFolder(
                id=folder_id,
                displayName=folder_name,
                parentFolderId=None,
                childFolderCount=0,
                totalItemCount=dict(_FOLDER_SPECS)[folder_name],
                unreadItemCount=unread_counts[folder_name],
                _user_id=user_id,
            )
            graph_mail_folder_repo.save(folder)
