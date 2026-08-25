"""Read-side handlers for Microsoft Graph Identity / Conditional Access."""
from __future__ import annotations

from repository.graph.conditional_access_policy_repo import graph_ca_policy_repo
from utils.graph_odata import apply_graph_filter, apply_odata_select, select_fields
from utils.graph_response import build_graph_list_response
from utils.serde import record_dict


def list_ca_policies(
    filter_str: str | None = None, select: str | None = None,
) -> dict:
    """Return all conditional access policies.

    Args:
        filter_str: OData ``$filter`` expression.
        select:     OData ``$select`` expression.

    Returns:
        OData list response containing conditional access policy records.
    """
    records = [record_dict(p) for p in graph_ca_policy_repo.list_all()]
    if filter_str:
        records = apply_graph_filter(records, filter_str)
    records = apply_odata_select(records, select)
    return build_graph_list_response(
        value=records,
        context="https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies",
    )


def get_ca_policy(policy_id: str, select: str | None = None) -> dict | None:
    """Return a single conditional access policy by ID.

    Args:
        policy_id: The policy's ``id``.
        select:    OData ``$select`` expression.

    Returns:
        Policy dict or ``None`` if not found.
    """
    policy = graph_ca_policy_repo.get(policy_id)
    if policy is None:
        return None
    return select_fields(record_dict(policy), select)
