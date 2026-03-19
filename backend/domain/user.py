from dataclasses import dataclass, field


@dataclass
class User:
    """Represents a SentinelOne management console user."""

    id: str
    email: str
    fullName: str
    source: str             # "mgmt" | "sso"
    dateJoined: str
    lastLogin: str
    twoFaEnabled: bool
    twoFaConfigured: bool
    twoFaStatus: str        # "configured" | "not_configured"
    twoFaEnabledReadOnly: bool
    primaryTwoFaMethod: str  # "application" | "sms"
    scope: str              # "tenant" | "site" | "account"
    lowestRole: str         # "Admin" | "Viewer" | "SOC Analyst"
    isSystem: bool = False
    emailVerified: bool = True
    emailReadOnly: bool = False
    fullNameReadOnly: bool = False
    groupsReadOnly: bool = False
    canGenerateApiToken: bool = True
    firstLogin: str | None = None
    globalOrganizationId: str | None = None
    globalUserId: str | None = None
    scopeRoles: list = field(default_factory=list)
    siteRoles: list = field(default_factory=list)
    tenantRoles: list = field(default_factory=list)
    apiToken: str | None = None    # always None in real API response
    agreedEula: bool = False
    agreementUrl: str | None = None
    allowRemoteShell: bool = False

    # Internal only — not returned to API callers
    role: str = ""
    accountId: str = ""
    accountName: str = ""
    _apiToken: str = ""     # stored for auth; never serialised by asdict
