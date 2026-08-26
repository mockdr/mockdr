"""Writes to the management console's own configuration."""

from __future__ import annotations

from application.system.queries import (
    SYSTEM_CONFIG_COLLECTION,
    SYSTEM_CONFIG_ID,
    get_configuration,
)
from repository.store import store


class InvalidConfigurationError(ValueError):
    """A configuration change the 2.1 API would refuse."""


#: The settings `PUT /system/configuration` declares. Every other key in the
#: read schema is the console's to report, not a client's to set — the
#: licence counts and the value ranges among them.
SETTABLE = frozenset({
    "accessibleUrl",
    "advancedMode",
    "allowDuplicateSite",
    "allowedDomains",
    "cloudIntelligenceOn",
    "cloudLastConnectionTime",
    "earlyAccess",
    "earlyAccessPlatforms",
    "globalTwoFaEnabled",
    "passwordExpiration",
    "rememberMeLength",
    "tfaEnrollmentExpiration",
    "uiInactivityTimeoutSeconds",
})


def update_configuration(body: dict) -> dict:
    """Apply a configuration change and return the settings that resulted.

    The 2.1 swagger requires both `data` and `filter` on this call: the
    scope a change applies to is not implied. mockdr hosts one tenant, so
    every scope resolves to the same settings — but a body that names
    neither is the malformed request it is, not a silent no-op.

    Args:
        body: The request body, with `data` and `filter`.

    Returns:
        The settings after the change, ready to be completed to the schema.

    Raises:
        InvalidConfigurationError: A member is missing, or nothing settable
            was named.
    """
    data = body.get("data")
    if not isinstance(data, dict):
        msg = "data is required"
        raise InvalidConfigurationError(msg)
    if not isinstance(body.get("filter"), dict):
        msg = "filter is required"
        raise InvalidConfigurationError(msg)

    changes = {key: value for key, value in data.items() if key in SETTABLE}
    if not changes:
        named = ", ".join(sorted(data)) or "nothing"
        msg = f"no setting of this console is named by {named}"
        raise InvalidConfigurationError(msg)

    settings = {**get_configuration(), **changes}
    store.save(SYSTEM_CONFIG_COLLECTION, SYSTEM_CONFIG_ID, settings)
    return settings
