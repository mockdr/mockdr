"""Cortex XDR Distribution query handlers (read-only)."""
from __future__ import annotations

from repository.xdr_distribution_repo import xdr_distribution_repo
from utils.serde import record_dict
from utils.xdr_response import build_xdr_reply

#: The platforms `get_versions` answers for, in the recorded order.
_VERSION_PLATFORMS = ("windows", "linux", "macos")


def get_versions() -> dict:
    """List the agent versions a distribution can be built from, per platform.

    Cortex answers ``{"windows": [...], "linux": [...], "macos": [...]}`` --
    one list of version strings per platform and nothing else (XSOAR test_data
    ``get_distribution_versions.json``; the CoreIRApiModule's
    ``get_distribution_versions_command`` iterates the reply's keys and tables
    each one's list). The mock answered the three platforms *empty* beside an
    invented ``data`` list of ``{agent_version, os_type}`` -- every version
    labelled ``windows`` -- and ``total_count``/``result_count`` integers, so
    the command raised ``object of type 'int' has no len()`` on a count it was
    never meant to see.

    Returns:
        XDR reply mapping each platform to its sorted version strings.
    """
    by_platform: dict[str, set[str]] = {p: set() for p in _VERSION_PLATFORMS}
    for dist in xdr_distribution_repo.list_all():
        if dist.agent_version and dist.platform in by_platform:
            by_platform[dist.platform].add(dist.agent_version)
    return build_xdr_reply({p: sorted(v) for p, v in by_platform.items()})


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

    return build_xdr_reply(record_dict(dist))
