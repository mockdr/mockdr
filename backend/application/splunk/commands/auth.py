"""Splunk authentication command handlers."""
from __future__ import annotations

from api.splunk_auth import create_session
from repository.splunk.splunk_user_repo import splunk_user_repo
from utils.splunk.response import build_auth_response


def login(username: str, password: str) -> dict | None:
    """Authenticate a user and return a session key.

    Args:
        username: Splunk username.
        password: Splunk password.

    Returns:
        Auth response dict with ``sessionKey``, or None if invalid.
    """
    user = splunk_user_repo.authenticate(username, password)
    if not user:
        return None
    session_key = create_session(username)
    return build_auth_response(session_key)
