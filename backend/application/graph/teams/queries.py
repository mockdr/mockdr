"""Read-side handlers for Microsoft Graph Teams."""
from __future__ import annotations

from dataclasses import asdict

from domain.graph.channel_message import GraphChannelMessage
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.channel_message_repo import graph_channel_message_repo
from repository.graph.channel_repo import graph_channel_repo
from repository.graph.team_repo import graph_team_repo
from utils.graph_response import build_graph_list_response


def _strip_internal(record: dict) -> dict:
    """Remove internal underscore-prefixed fields, mapping ``_from`` to ``from``."""
    result: dict = {}
    for k, v in record.items():
        if k == "_from":
            result["from"] = v
        elif not k.startswith("_"):
            result[k] = v
    return result


def list_teams() -> dict:
    """Return all teams.

    Returns:
        OData list response dict.
    """
    records = [asdict(t) for t in graph_team_repo.list_all()]
    return build_graph_list_response(
        value=records,
        context="https://graph.microsoft.com/v1.0/$metadata#teams",
    )


def get_team(team_id: str) -> dict | None:
    """Return a single team by ID.

    Args:
        team_id: The team's ``id``.

    Returns:
        Team dict or ``None`` if not found.
    """
    team = graph_team_repo.get(team_id)
    if team is None:
        return None
    return asdict(team)


def list_channels(team_id: str) -> dict:
    """Return channels for a team.

    Args:
        team_id: The team's ``id``.

    Returns:
        OData list response dict.
    """
    all_channels = graph_channel_repo.list_all()
    records: list[dict] = []
    for ch in all_channels:
        d = asdict(ch) if not isinstance(ch, dict) else dict(ch)
        if d.get("_team_id") != team_id:
            continue
        records.append(_strip_internal(d))

    return build_graph_list_response(
        value=records,
        context=f"https://graph.microsoft.com/v1.0/$metadata#teams('{team_id}')/channels",
    )


def list_channel_messages(
    team_id: str,
    channel_id: str,
    top: int = 25,
    skip: int = 0,
) -> dict:
    """Return messages in a channel.

    Args:
        team_id:    The team's ``id``.
        channel_id: The channel's ``id``.
        top:        Page size.
        skip:       Number of records to skip.

    Returns:
        OData list response dict.
    """
    all_messages = graph_channel_message_repo.list_all()
    records: list[dict] = []
    for msg in all_messages:
        d = asdict(msg) if not isinstance(msg, dict) else dict(msg)
        if d.get("_team_id") != team_id or d.get("_channel_id") != channel_id:
            continue
        records.append(_strip_internal(d))

    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        "https://graph.microsoft.com/v1.0/"
        f"teams/{team_id}/channels/{channel_id}/"
        f"messages?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context=f"https://graph.microsoft.com/v1.0/$metadata#teams('{team_id}')/channels('{channel_id}')/messages",
        next_link=next_link,
    )


def post_channel_message(
    team_id: str,
    channel_id: str,
    body: dict,
) -> dict:
    """Post a new message to a channel.

    Args:
        team_id:    The team's ``id``.
        channel_id: The channel's ``id``.
        body:       Request body with ``body`` content.

    Returns:
        The created message dict.
    """
    msg_body = body.get("body", {"content": "", "contentType": "text"})
    msg = GraphChannelMessage(
        id=graph_uuid(),
        body=msg_body,
        createdDateTime=rand_ago(max_days=0),
        importance=body.get("importance", "normal"),
        _from=body.get("from", {}),
        _team_id=team_id,
        _channel_id=channel_id,
    )
    graph_channel_message_repo.save(msg)
    return _strip_internal(asdict(msg))
