"""Seed Microsoft Graph Teams, channels, and channel messages."""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.channel import GraphChannel
from domain.graph.channel_message import GraphChannelMessage
from domain.graph.team import GraphTeam
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.channel_message_repo import graph_channel_message_repo
from repository.graph.channel_repo import graph_channel_repo
from repository.graph.team_repo import graph_team_repo

# Team definitions: (displayName, description, visibility, extra_channels)
_TEAM_SPECS: list[tuple[str, str, str, list[str]]] = [
    ("All Company", "Company-wide announcements and updates", "public", ["Announcements", "Social"]),
    ("IT Security", "Security operations and incident response", "private", ["Incidents"]),
    ("Sales Team", "Sales pipeline and deal tracking", "public", ["Pipeline", "Wins"]),
    ("Management", "Leadership and strategy discussions", "private", ["Strategy"]),
]

_MESSAGE_BODIES: list[str] = [
    "Hey team, just wanted to share a quick update on the project.",
    "Can someone review the latest pull request?",
    "Reminder: all-hands meeting tomorrow at 2pm.",
    "Great work on the Q4 numbers everyone!",
    "I've attached the latest report for your review.",
    "Does anyone have experience with the new tooling?",
    "Please make sure to update your timesheets by EOD Friday.",
    "Welcome to the team! Feel free to introduce yourself here.",
    "The deployment is complete and everything looks good.",
    "FYI: maintenance window scheduled for this weekend.",
]


def seed_graph_teams(fake: Faker, user_ids: list[str]) -> None:
    """Create Teams, channels, and channel messages."""
    total_messages = 0

    for team_name, description, visibility, extra_channels in _TEAM_SPECS:
        team_id = graph_uuid()

        graph_team_repo.save(
            GraphTeam(
                id=team_id,
                displayName=team_name,
                description=description,
                createdDateTime=rand_ago(max_days=365),
                visibility=visibility,
                memberSettings={
                    "allowCreateUpdateChannels": True,
                    "allowDeleteChannels": False,
                    "allowAddRemoveApps": True,
                },
                messagingSettings={
                    "allowUserEditMessages": True,
                    "allowUserDeleteMessages": True,
                    "allowTeamMentions": True,
                    "allowChannelMentions": True,
                },
            ),
        )

        # Always create General channel + extra channels
        all_channels = ["General"] + extra_channels
        for channel_name in all_channels:
            channel_id = graph_uuid()

            graph_channel_repo.save(
                GraphChannel(
                    id=channel_id,
                    displayName=channel_name,
                    description=f"{channel_name} channel for {team_name}",
                    membershipType="standard",
                    _team_id=team_id,
                ),
            )

            # Seed messages per channel — aim for ~30 total across all teams
            msg_count = random.randint(2, 4) if total_messages < 30 else 0
            for _ in range(msg_count):
                if total_messages >= 30:
                    break
                sender_id = random.choice(user_ids[:5]) if len(user_ids) >= 5 else random.choice(user_ids)
                body_text = random.choice(_MESSAGE_BODIES)

                graph_channel_message_repo.save(
                    GraphChannelMessage(
                        id=graph_uuid(),
                        body={
                            "content": body_text,
                            "contentType": "text",
                        },
                        createdDateTime=rand_ago(max_days=30),
                        importance=random.choice(["normal", "normal", "normal", "high"]),
                        _from={
                            "user": {
                                "id": sender_id,
                                "displayName": fake.name(),
                            },
                        },
                        _team_id=team_id,
                        _channel_id=channel_id,
                    ),
                )
                total_messages += 1
