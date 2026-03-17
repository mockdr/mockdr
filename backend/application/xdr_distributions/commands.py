"""Cortex XDR Distribution command handlers (mutations)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime

from domain.xdr_distribution import XdrDistribution
from repository.xdr_distribution_repo import xdr_distribution_repo
from utils.xdr_response import build_xdr_reply


def create_distribution(request_data: dict) -> dict:
    """Create a new agent distribution package.

    Args:
        request_data: Dict with ``name``, ``platform``, ``package_type``,
            and ``agent_version``.

    Returns:
        XDR reply with the new distribution ID.
    """
    dist_id = str(uuid.uuid4())
    now_ms = int(datetime.now(UTC).timestamp() * 1000)

    dist = XdrDistribution(
        distribution_id=dist_id,
        name=request_data.get("name", "Agent Package"),
        platform=request_data.get("platform", "windows"),
        package_type=request_data.get("package_type", "standalone"),
        status="ready",
        agent_version=request_data.get("agent_version", "8.3.0.12345"),
        creation_timestamp=now_ms,
    )
    xdr_distribution_repo.save(dist)

    return build_xdr_reply({
        "distribution_id": dist_id,
        "status": "ready",
    })
