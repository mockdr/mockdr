"""Reads of the management console's own configuration."""

from __future__ import annotations

from repository.store import store

#: Where the console's settings live. One record: the console has one
#: configuration, and `PUT /system/configuration` changes that one.
SYSTEM_CONFIG_COLLECTION = "system_config"
SYSTEM_CONFIG_ID = "configuration"


def get_configuration() -> dict:
    """The settings this console currently has.

    Returns:
        The stored settings, empty until something has been set. The route
        completes them to the schema the 2.1 swagger declares.
    """
    stored = store.get(SYSTEM_CONFIG_COLLECTION, SYSTEM_CONFIG_ID)
    return dict(stored) if isinstance(stored, dict) else {}
