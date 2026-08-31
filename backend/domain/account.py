from dataclasses import dataclass, field


@dataclass
class Account:
    """Represents a SentinelOne management account."""

    id: str
    name: str
    createdAt: str
    updatedAt: str
    state: str
    numberOfSites: int
    numberOfAgents: int
    activeAgents: int
    numberOfUsers: int
    accountType: str
    isDefault: bool
    expiration: str | None = None
    # Declared on the account response with enums of their own; nothing set
    # them, so the answer carried the swagger's example values, identical for
    # every account and matched by no filter.
    # Four more the account's own answer schema declares and nothing set, so
    # the answer carried the swagger's examples and a write to them was
    # dropped — the same shape as `billingMode` and `usageType` below.
    # Both are declared `string` with no `x-nullable`, so the answer must
    # carry a string: a `None` default made the response schema test fail
    # with "None is not of type 'string'".
    externalId: str = ""
    salesforceId: str = ""
    unlimitedExpiration: bool = False
    makeSocDefaultUi: bool = False
    # The account's own licence document and the SKUs under it, both
    # declared on its answer and set by nothing — so `?module=` and `?sku=`
    # could match no account, and neither could `?expiration=`. The sites
    # carry the same shape; this is theirs summarised.
    licenses: dict = field(default_factory=dict)
    skus: list = field(default_factory=list)
    billingMode: str = "subscription"
    usageType: str = "customer"
    totalLicenses: int = 0
