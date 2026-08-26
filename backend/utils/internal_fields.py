"""Internal-field sets used to strip mock-only fields before API responses.

Each set names the dataclass fields that exist on a domain object for internal
bookkeeping but must NEVER appear in any real SentinelOne API response.

Centralised here so the domain layer remains free of DTO concerns.  Consumed
by the application layer (queries and commands) via ``utils.strip.strip_fields``.
"""

AGENT_INTERNAL_FIELDS: frozenset[str] = frozenset({
    "passphrase", "localIp", "isInfected", "installedAt",
    "agentLicenseType", "cpuUsage", "memoryUsage",
    "decommissionedAt",  # a filter field; AgentViewSchema does not declare it
})

#: Falcon's device model has no `hidden` property: whether a host has been
#: hidden is mockdr's bookkeeping, and it is visible in the answer only as
#: the host's absence from the listings and its presence in
#: `/devices/combined/devices-hidden/v1`.
CS_HOST_INTERNAL_FIELDS: frozenset[str] = frozenset({"hidden"})

DEVICE_CONTROL_INTERNAL_FIELDS: frozenset[str] = frozenset({"siteId"})

EXCLUSION_INTERNAL_FIELDS: frozenset[str] = frozenset({"siteId"})

FIREWALL_INTERNAL_FIELDS: frozenset[str] = frozenset({"siteId"})

GROUP_INTERNAL_FIELDS: frozenset[str] = frozenset({"siteName", "accountId", "accountName"})

SITE_INTERNAL_FIELDS: frozenset[str] = frozenset({"location"})

USER_INTERNAL_FIELDS: frozenset[str] = frozenset({"role", "accountId", "accountName", "_apiToken"})

THREAT_INTERNAL_FIELDS: frozenset[str] = frozenset({"_fetched_file"})
