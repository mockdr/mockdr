"""Cortex XDR Distribution query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.xdr_distribution_repo import xdr_distribution_repo
from utils.xdr_response import build_xdr_list_reply, build_xdr_reply


def get_versions() -> dict:
    """List all available agent versions.

    Returns:
        XDR reply with version data from distribution records.
    """
    distributions = xdr_distribution_repo.list_all()
    versions = sorted({d.agent_version for d in distributions if d.agent_version})

    version_list = [
        {"agent_version": v, "os_type": "windows"}
        for v in versions
    ]
    if not version_list:
        version_list = [
            {"agent_version": "8.3.0.12345", "os_type": "windows"},
            {"agent_version": "8.3.0.12345", "os_type": "linux"},
            {"agent_version": "8.3.0.12345", "os_type": "macos"},
        ]

    return build_xdr_list_reply(version_list, total_count=len(version_list))


def get_distribution_url(distribution_id: str) -> dict | None:
    """Return a synthetic download URL for a distribution package.

    Args:
        distribution_id: The distribution identifier.

    Returns:
        XDR reply with download URL, or None if not found.
    """
    dist = xdr_distribution_repo.get(distribution_id)
    if not dist:
        return None

    return build_xdr_reply({
        "distribution_id": distribution_id,
        "distribution_url": (
            f"https://xdr-mock.acmecorp.internal/distributions/{distribution_id}/download"
        ),
    })


def get_distribution_status(distribution_id: str) -> dict | None:
    """Return the status of a distribution package.

    Args:
        distribution_id: The distribution identifier.

    Returns:
        XDR reply with distribution status, or None if not found.
    """
    dist = xdr_distribution_repo.get(distribution_id)
    if not dist:
        return None

    return build_xdr_reply(asdict(dist))
