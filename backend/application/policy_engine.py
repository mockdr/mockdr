"""Policy engine — evaluates a threat against the applicable SentinelOne policy.

Decision tree mirrors the real SentinelOne agent behavior:

  1. Resolve applicable policy: group policy → site policy (most specific wins)
  2. Determine confidence verdict from threat.threatInfo["confidenceLevel"]
        malicious  → governed by policy.mitigationMode
        suspicious → governed by policy.mitigationModeSuspicious
  3. If mode == "protect" and policy.autoMitigate == True
        → return the auto-mitigation action
     Else
        → return None (detect-only; threat stays active for analyst review)

Auto-mitigation actions by confidence level:
  malicious  → "quarantine"  (kill + move files to vault)
  suspicious → "kill"        (terminate only, no file changes)
"""

from __future__ import annotations

from repository.policy_repo import policy_repo

# S1 action strings for the mitigationStatus field
_ACTION_FOR_CONFIDENCE: dict[str, str] = {
    "malicious": "quarantine",
    "suspicious": "kill",
}


def resolve_policy(agent: object) -> object | None:
    """Return the most specific policy for *agent* (group > site), or None."""
    group_id = getattr(agent, "groupId", None)
    site_id = getattr(agent, "siteId", None)

    if group_id:
        policy = policy_repo.get_for_group(group_id)
        if policy:
            return policy

    if site_id:
        return policy_repo.get_for_site(site_id)

    return None


def _resolve_confidence_and_mode(
    threat: object, policy: object,
) -> tuple[str, str]:
    """Extract the confidence level from the threat and the applicable policy mode.

    Args:
        threat: A ``Threat`` domain object (must have ``threatInfo`` dict).
        policy: A resolved policy object.

    Returns:
        Tuple of (confidence, mode).
    """
    confidence = (threat.threatInfo if hasattr(threat, "threatInfo") else {}).get(
        "confidenceLevel", "suspicious"
    )
    if confidence == "malicious":
        mode = getattr(policy, "mitigationMode", "detect")
    else:
        mode = getattr(policy, "mitigationModeSuspicious", "detect")
    return confidence, mode


def evaluate(threat: object, agent: object) -> str | None:
    """Decide whether to auto-mitigate *threat* based on the applicable policy.

    Args:
        threat: A ``Threat`` domain object (must have ``threatInfo`` dict).
        agent:  A ``Agent`` domain object (must have ``groupId`` / ``siteId``).

    Returns:
        Mitigation action string (e.g. ``"quarantine"``, ``"kill"``) if the
        policy dictates an automatic response, or ``None`` if the policy is in
        detect-only mode or no policy could be resolved.
    """
    policy = resolve_policy(agent)
    if not policy:
        return None

    if not getattr(policy, "autoMitigate", False):
        return None

    confidence, mode = _resolve_confidence_and_mode(threat, policy)

    if mode == "protect":
        return _ACTION_FOR_CONFIDENCE.get(confidence, "kill")

    return None


def describe(threat: object, agent: object) -> str:
    """Return a human-readable description of the policy decision for activity logs."""
    policy = resolve_policy(agent)
    if not policy:
        return "No policy found — threat left active for analyst review"

    if not getattr(policy, "autoMitigate", False):
        return "Policy has autoMitigate disabled — threat left active for analyst review"

    confidence, mode = _resolve_confidence_and_mode(threat, policy)
    action = _ACTION_FOR_CONFIDENCE.get(confidence, "kill")

    if mode == "protect":
        return (
            f"Policy mode '{mode}' — auto-mitigation triggered: "
            f"{action} applied to {confidence} threat"
        )

    return (
        f"Policy mode '{mode}' — detect only: "
        f"threat remains active for analyst review"
    )
