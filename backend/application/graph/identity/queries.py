"""Read-side handlers for Microsoft Graph Identity / Conditional Access."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.conditional_access_policy_repo import graph_ca_policy_repo
from utils.graph_response import build_graph_list_response


def list_ca_policies() -> dict:
    """Return all conditional access policies.

    Returns:
        OData list response containing conditional access policy records.
    """
    records = [asdict(p) for p in graph_ca_policy_repo.list_all()]
    return build_graph_list_response(
        value=records,
        context="https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies",
    )


def get_ca_policy(policy_id: str) -> dict | None:
    """Return a single conditional access policy by ID.

    Args:
        policy_id: The policy's ``id``.

    Returns:
        Policy dict or ``None`` if not found.
    """
    policy = graph_ca_policy_repo.get(policy_id)
    if policy is None:
        return None
    return asdict(policy)
