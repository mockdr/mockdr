"""Microsoft Defender for Endpoint File/Domain/IP info query handlers."""
from __future__ import annotations

from utils.dt import utc_now


def get_file_info(file_hash: str) -> dict:
    """Get synthetic file information for a given hash.

    Args:
        file_hash: SHA1 or SHA256 file hash.

    Returns:
        File info dict matching MDE ``/api/files/{hash}`` response format.
    """
    return {
        "sha1": file_hash if len(file_hash) == 40 else "",
        "sha256": file_hash if len(file_hash) == 64 else "",
        "md5": "",
        "globalPrevalence": 142,
        "globalFirstObserved": "2024-01-15T08:30:00Z",
        "globalLastObserved": utc_now(),
        "size": 245760,
        "fileType": "PortableExecutable",
        "isPeFile": True,
        "filePublisher": "Acme Corp",
        "fileProductName": "AcmeAgent",
        "signer": "Acme Corp Code Signing CA",
        "issuer": "DigiCert SHA2 Assured ID Code Signing CA",
        "signerHash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "isValidCertificate": True,
        "determinationType": "Unknown",
        "determinationValue": "",
    }


def get_file_stats(file_hash: str) -> dict:
    """Get synthetic file statistics for a given hash.

    Args:
        file_hash: SHA1 or SHA256 file hash.

    Returns:
        File statistics dict matching MDE ``/api/files/{hash}/stats`` response.
    """
    return {
        "sha1": file_hash if len(file_hash) == 40 else "",
        "sha256": file_hash if len(file_hash) == 64 else "",
        "organizationPrevalence": 12,
        "orgFirstSeen": "2024-02-01T10:00:00Z",
        "orgLastSeen": utc_now(),
        "topFileNames": ["agent.exe", "updater.exe"],
    }


def get_domain_info(domain: str) -> dict:
    """Get synthetic domain information.

    Args:
        domain: Domain name to look up.

    Returns:
        Domain info dict matching MDE ``/api/domains/{domain}`` response.
    """
    return {
        "host": domain,
        "orgPrevalence": "Medium",
        "orgFirstSeen": "2024-03-01T12:00:00Z",
        "orgLastSeen": utc_now(),
        "registrar": "GoDaddy.com, LLC",
        "registrant": "REDACTED FOR PRIVACY",
        "firstSeenDateTime": "2024-03-01T12:00:00Z",
        "lastSeenDateTime": utc_now(),
        "isInOrgWhitelist": False,
    }


def get_domain_stats(domain: str) -> dict:
    """Get synthetic domain statistics.

    Args:
        domain: Domain name to look up.

    Returns:
        Domain statistics dict matching MDE ``/api/domains/{domain}/stats``.
    """
    return {
        "host": domain,
        "orgPrevalence": 8,
        "orgFirstSeen": "2024-03-01T12:00:00Z",
        "orgLastSeen": utc_now(),
        "topDevices": [
            {"deviceId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "deviceName": "ws-fin-001"},
            {"deviceId": "b2c3d4e5-f6a7-8901-bcde-f12345678901", "deviceName": "srv-dc-01"},
        ],
    }


def get_ip_info(ip: str) -> dict:
    """Get synthetic IP address information.

    Args:
        ip: IPv4 or IPv6 address to look up.

    Returns:
        IP info dict matching MDE ``/api/ips/{ip}`` response.
    """
    return {
        "ipAddress": ip,
        "orgPrevalence": "Low",
        "orgFirstSeen": "2024-04-01T14:00:00Z",
        "orgLastSeen": utc_now(),
        "firstSeenDateTime": "2024-04-01T14:00:00Z",
        "lastSeenDateTime": utc_now(),
        "countryCode": "US",
        "autonomousSystem": "AS13335 Cloudflare, Inc.",
    }


def get_ip_stats(ip: str) -> dict:
    """Get synthetic IP address statistics.

    Args:
        ip: IPv4 or IPv6 address to look up.

    Returns:
        IP statistics dict matching MDE ``/api/ips/{ip}/stats``.
    """
    return {
        "ipAddress": ip,
        "orgPrevalence": 3,
        "orgFirstSeen": "2024-04-01T14:00:00Z",
        "orgLastSeen": utc_now(),
        "topDevices": [
            {"deviceId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "deviceName": "ws-fin-001"},
        ],
    }
