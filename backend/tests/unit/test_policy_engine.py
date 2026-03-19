"""Unit tests for application.policy_engine.

Covers:
- resolve_policy: group policy preferred over site policy, site fallback, None when absent
- evaluate: protect/detect mode × malicious/suspicious confidence × autoMitigate flag
- describe: human-readable policy decision strings
"""

from application import policy_engine
from domain.policy import Policy
from domain.threat import Threat
from repository.policy_repo import policy_repo

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_policy(
    scope_type: str,
    scope_id: str,
    mitigation_mode: str = "protect",
    mitigation_mode_suspicious: str = "detect",
    auto_mitigate: bool = True,
) -> Policy:
    """Create a minimal Policy for testing."""
    return Policy(
        id="pol-" + scope_id,
        scopeId=scope_id,
        scopeType=scope_type,
        mitigationMode=mitigation_mode,
        mitigationModeSuspicious=mitigation_mode_suspicious,
        monitorOnWrite=True,
        monitorOnExecute=True,
        blockOnWrite=True,
        blockOnExecute=True,
        scanNewAgents=True,
        scanOnWritten=True,
        autoMitigate=auto_mitigate,
        updatedAt="2026-01-01T00:00:00.000Z",
    )


class _FakeAgent:
    """Minimal agent stub used across tests."""
    def __init__(self, group_id: str = "g1", site_id: str = "s1") -> None:
        self.groupId = group_id
        self.siteId = site_id


def _malicious_threat() -> Threat:
    return Threat(id="t1", threatInfo={"confidenceLevel": "malicious", "threatName": "Evil.exe"})


def _suspicious_threat() -> Threat:
    return Threat(id="t2", threatInfo={"confidenceLevel": "suspicious", "threatName": "Maybe.exe"})


# ── resolve_policy ─────────────────────────────────────────────────────────────

class TestResolvePolicy:
    """Tests for policy_engine.resolve_policy()."""

    def test_returns_group_policy_when_present(self) -> None:
        """Group policy takes precedence over site policy."""
        group_pol = _make_policy("group", "g1", mitigation_mode="detect")
        site_pol = _make_policy("site", "s1", mitigation_mode="protect")
        policy_repo.save_for_group("g1", group_pol)
        policy_repo.save_for_site("s1", site_pol)
        agent = _FakeAgent(group_id="g1", site_id="s1")

        result = policy_engine.resolve_policy(agent)
        assert result is not None
        assert result.mitigationMode == "detect"  # group policy wins

    def test_falls_back_to_site_policy_when_no_group_policy(self) -> None:
        """Site policy is used when no group policy exists."""
        site_pol = _make_policy("site", "s1", mitigation_mode="protect")
        policy_repo.save_for_site("s1", site_pol)
        agent = _FakeAgent(group_id="no-such-group", site_id="s1")

        result = policy_engine.resolve_policy(agent)
        assert result is not None
        assert result.mitigationMode == "protect"

    def test_returns_none_when_no_policy_exists(self) -> None:
        """Returns None if neither group nor site policy exists."""
        agent = _FakeAgent(group_id="unknown-g", site_id="unknown-s")
        result = policy_engine.resolve_policy(agent)
        assert result is None

    def test_returns_none_when_agent_has_no_ids(self) -> None:
        """An agent with empty groupId and siteId resolves to None."""
        agent = _FakeAgent(group_id="", site_id="")
        result = policy_engine.resolve_policy(agent)
        assert result is None


# ── evaluate ──────────────────────────────────────────────────────────────────

class TestEvaluate:
    """Tests for policy_engine.evaluate()."""

    def test_protect_mode_malicious_returns_quarantine(self) -> None:
        """Malicious threat + protect mode → quarantine action."""
        policy_repo.save_for_site("s1", _make_policy("site", "s1", mitigation_mode="protect"))
        agent = _FakeAgent(group_id="no-g", site_id="s1")
        action = policy_engine.evaluate(_malicious_threat(), agent)
        assert action == "quarantine"

    def test_protect_mode_suspicious_returns_kill(self) -> None:
        """Suspicious threat + protect mode (for suspicious) → kill action."""
        pol = _make_policy("site", "s1", mitigation_mode_suspicious="protect")
        policy_repo.save_for_site("s1", pol)
        agent = _FakeAgent(group_id="no-g", site_id="s1")
        action = policy_engine.evaluate(_suspicious_threat(), agent)
        assert action == "kill"

    def test_detect_mode_malicious_returns_none(self) -> None:
        """Malicious threat + detect mode → no auto-action."""
        policy_repo.save_for_site("s1", _make_policy("site", "s1", mitigation_mode="detect"))
        agent = _FakeAgent(group_id="no-g", site_id="s1")
        action = policy_engine.evaluate(_malicious_threat(), agent)
        assert action is None

    def test_detect_mode_suspicious_returns_none(self) -> None:
        """Suspicious threat + detect mode (default) → no auto-action."""
        pol = _make_policy("site", "s1", mitigation_mode_suspicious="detect")
        policy_repo.save_for_site("s1", pol)
        agent = _FakeAgent(group_id="no-g", site_id="s1")
        action = policy_engine.evaluate(_suspicious_threat(), agent)
        assert action is None

    def test_auto_mitigate_false_returns_none_even_in_protect_mode(self) -> None:
        """autoMitigate=False disables auto-response regardless of mode."""
        pol = _make_policy("site", "s1", mitigation_mode="protect", auto_mitigate=False)
        policy_repo.save_for_site("s1", pol)
        agent = _FakeAgent(group_id="no-g", site_id="s1")
        action = policy_engine.evaluate(_malicious_threat(), agent)
        assert action is None

    def test_no_policy_returns_none(self) -> None:
        """No policy at all → no auto-action."""
        agent = _FakeAgent(group_id="ghost-g", site_id="ghost-s")
        action = policy_engine.evaluate(_malicious_threat(), agent)
        assert action is None

    def test_group_policy_overrides_site_policy_for_evaluation(self) -> None:
        """Group policy (detect) takes precedence over site policy (protect)."""
        group_pol = _make_policy("group", "g1", mitigation_mode="detect")
        site_pol = _make_policy("site", "s1", mitigation_mode="protect")
        policy_repo.save_for_group("g1", group_pol)
        policy_repo.save_for_site("s1", site_pol)
        agent = _FakeAgent(group_id="g1", site_id="s1")
        # Group is detect → should return None despite site being protect
        action = policy_engine.evaluate(_malicious_threat(), agent)
        assert action is None

    def test_missing_confidence_level_treated_as_suspicious(self) -> None:
        """A threat without confidenceLevel falls back to suspicious handling."""
        pol = _make_policy("site", "s1", mitigation_mode_suspicious="detect")
        policy_repo.save_for_site("s1", pol)
        agent = _FakeAgent(group_id="no-g", site_id="s1")
        threat = Threat(id="t3", threatInfo={})  # no confidenceLevel key
        action = policy_engine.evaluate(threat, agent)
        assert action is None  # suspicious default → detect mode → None


# ── describe ──────────────────────────────────────────────────────────────────

class TestDescribe:
    """Tests for policy_engine.describe()."""

    def test_protect_mode_malicious_describes_quarantine(self) -> None:
        """Protect mode malicious threat → description mentions quarantine."""
        policy_repo.save_for_site("s1", _make_policy("site", "s1", mitigation_mode="protect"))
        agent = _FakeAgent(group_id="no-g", site_id="s1")
        desc = policy_engine.describe(_malicious_threat(), agent)
        assert "protect" in desc
        assert "quarantine" in desc

    def test_detect_mode_describes_detect_only(self) -> None:
        """Detect mode → description mentions 'detect' and 'analyst'."""
        policy_repo.save_for_site("s1", _make_policy("site", "s1", mitigation_mode="detect"))
        agent = _FakeAgent(group_id="no-g", site_id="s1")
        desc = policy_engine.describe(_malicious_threat(), agent)
        assert "detect" in desc
        assert "analyst" in desc

    def test_no_policy_describes_no_policy(self) -> None:
        """No policy → description mentions 'No policy'."""
        agent = _FakeAgent(group_id="ghost-g", site_id="ghost-s")
        desc = policy_engine.describe(_malicious_threat(), agent)
        assert "No policy" in desc

    def test_auto_mitigate_false_describes_disabled(self) -> None:
        """autoMitigate=False → description mentions disabled."""
        pol = _make_policy("site", "s1", auto_mitigate=False)
        policy_repo.save_for_site("s1", pol)
        agent = _FakeAgent(group_id="no-g", site_id="s1")
        desc = policy_engine.describe(_malicious_threat(), agent)
        assert "disabled" in desc

    def test_describe_returns_string(self) -> None:
        """describe() always returns a non-empty string."""
        agent = _FakeAgent(group_id="no-g", site_id="s1")
        policy_repo.save_for_site("s1", _make_policy("site", "s1"))
        result = policy_engine.describe(_malicious_threat(), agent)
        assert isinstance(result, str)
        assert len(result) > 0
