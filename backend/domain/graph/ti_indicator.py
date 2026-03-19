"""Domain model for Microsoft Graph Threat Intelligence Indicator."""
from dataclasses import dataclass


@dataclass
class GraphTiIndicator:
    """Represents a TI indicator from the Microsoft Graph Security API."""

    id: str  # noqa: A003
    action: str = "alert"  # alert, allow, block
    description: str = ""
    expirationDateTime: str = ""  # noqa: N815
    targetProduct: str = "Microsoft Defender ATP"  # noqa: N815
    threatType: str = "Malware"  # noqa: N815
    tlpLevel: str = "green"  # noqa: N815
    indicatorValue: str = ""  # noqa: N815 -- IP, domain, URL, or hash
    indicatorType: str = ""  # noqa: N815 -- ipAddress, domainName, url, fileSha256
    createdDateTime: str = ""  # noqa: N815
    lastReportedDateTime: str = ""  # noqa: N815
