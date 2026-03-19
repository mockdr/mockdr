"""Read-side handlers for Microsoft Graph Mail."""
from __future__ import annotations

from dataclasses import asdict

from domain.graph.mail_message import GraphMailMessage
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.mail_folder_repo import graph_mail_folder_repo
from repository.graph.mail_message_repo import graph_mail_message_repo
from utils.graph_response import build_graph_list_response


def _strip_internal(record: dict) -> dict:
    """Remove internal underscore-prefixed fields from a dict."""
    return {k: v for k, v in record.items() if not k.startswith("_")}


def list_messages(
    user_id: str,
    folder_id: str | None = None,
    top: int = 25,
    skip: int = 0,
) -> dict:
    """Return mail messages for a user, optionally filtered by folder.

    Args:
        user_id:   The user's ``id``.
        folder_id: Optional mail folder ``id`` to filter by.
        top:       Page size.
        skip:      Number of records to skip.

    Returns:
        OData list response dict.
    """
    all_messages = graph_mail_message_repo.list_all()
    records: list[dict] = []
    for msg in all_messages:
        d = asdict(msg) if not isinstance(msg, dict) else dict(msg)
        if d.get("_user_id") != user_id:
            continue
        if folder_id and d.get("_folder_id") != folder_id:
            continue
        records.append(_strip_internal(d))

    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        f"https://graph.microsoft.com/v1.0/users/{user_id}/messages?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context=f"https://graph.microsoft.com/v1.0/$metadata#users('{user_id}')/messages",
        next_link=next_link,
    )


def get_message(user_id: str, message_id: str) -> dict | None:
    """Return a single mail message.

    Args:
        user_id:    The user's ``id``.
        message_id: The message ``id``.

    Returns:
        Message dict or ``None`` if not found.
    """
    msg = graph_mail_message_repo.get(f"{user_id}:{message_id}")
    if msg is None:
        return None
    d = asdict(msg) if not isinstance(msg, dict) else dict(msg)
    return _strip_internal(d)


def list_mail_folders(user_id: str) -> dict:
    """Return mail folders for a user.

    Args:
        user_id: The user's ``id``.

    Returns:
        OData list response dict.
    """
    all_folders = graph_mail_folder_repo.list_all()
    records: list[dict] = []
    for folder in all_folders:
        d = asdict(folder) if not isinstance(folder, dict) else dict(folder)
        if d.get("_user_id") != user_id:
            continue
        records.append(_strip_internal(d))

    return build_graph_list_response(
        value=records,
        context=f"https://graph.microsoft.com/v1.0/$metadata#users('{user_id}')/mailFolders",
    )


def send_mail(user_id: str, body: dict) -> dict:
    """Create a message in Sent Items and return 202 Accepted.

    Args:
        user_id: The user's ``id``.
        body:    Request body with ``message`` and optionally ``saveToSentItems``.

    Returns:
        Empty dict (202 Accepted response).
    """
    message_data = body.get("message", {})
    subject = message_data.get("subject", "")
    msg_body = message_data.get("body", {"contentType": "text", "content": ""})
    to_recipients = message_data.get("toRecipients", [])

    # Find Sent Items folder for this user
    sent_folder_id = ""
    for folder in graph_mail_folder_repo.list_all():
        d = asdict(folder) if not isinstance(folder, dict) else dict(folder)
        if d.get("_user_id") == user_id and d.get("displayName") == "Sent Items":
            sent_folder_id = d.get("id", "")
            break

    graph_mail_message_repo.save(
        GraphMailMessage(
            id=graph_uuid(),
            subject=subject,
            bodyPreview=msg_body.get("content", "")[:200],
            body=msg_body,
            sender={"emailAddress": {
                "name": "Me",
                "address": f"{user_id}@acmecorp.onmicrosoft.com",
            }},
            toRecipients=to_recipients,
            receivedDateTime=rand_ago(max_days=0),
            isRead=True,
            importance=message_data.get("importance", "normal"),
            hasAttachments=False,
            categories=[],
            _user_id=user_id,
            _folder_id=sent_folder_id,
        ),
    )

    return {}
