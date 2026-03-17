"""Unit tests for application.playbook.executor._execute_step and _run_playbook.

Tests each action type directly without running the background thread,
verifying that each step correctly mutates the in-memory store.
"""
import pytest

from application.playbook._run_state import PlaybookRun, StepResult, reset_cancel, set_run
from application.playbook.executor import _execute_step, _run_playbook
from domain.policy import Policy
from repository.activity_repo import activity_repo
from repository.agent_repo import agent_repo
from repository.alert_repo import alert_repo
from repository.policy_repo import policy_repo
from repository.threat_repo import threat_repo

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture()
def agent():
    """Return the first seeded agent."""
    return agent_repo.list_all()[0]


@pytest.fixture()
def run(agent) -> PlaybookRun:
    """Minimal PlaybookRun needed by _execute_step (unused by action handlers)."""
    r = PlaybookRun(
        playbookId="test",
        agentId=agent.id,
        status="running",
        steps=[StepResult(stepId="s1", status="pending")],
    )
    set_run(r)
    reset_cancel()
    return r


@pytest.fixture()
def protect_policy(agent) -> Policy:
    """Attach a protect-mode site policy to the agent's site."""
    pol = Policy(
        id="test-pol",
        scopeId=agent.siteId,
        scopeType="site",
        mitigationMode="protect",
        mitigationModeSuspicious="detect",
        monitorOnWrite=True,
        monitorOnExecute=True,
        blockOnWrite=True,
        blockOnExecute=True,
        scanNewAgents=True,
        scanOnWritten=True,
        autoMitigate=True,
        updatedAt="2026-01-01T00:00:00.000Z",
    )
    # Override any group policy so the site policy is used
    if agent.groupId:
        policy_repo.save_for_group(agent.groupId, pol.__class__(
            id="test-group-pol",
            scopeId=agent.groupId,
            scopeType="group",
            mitigationMode="protect",
            mitigationModeSuspicious="detect",
            monitorOnWrite=True,
            monitorOnExecute=True,
            blockOnWrite=True,
            blockOnExecute=True,
            scanNewAgents=True,
            scanOnWritten=True,
            autoMitigate=True,
            updatedAt="2026-01-01T00:00:00.000Z",
        ))
    policy_repo.save_for_site(agent.siteId, pol)
    return pol


@pytest.fixture()
def detect_policy(agent) -> Policy:
    """Attach a detect-mode policy to the agent's group and site."""
    pol = Policy(
        id="detect-pol",
        scopeId=agent.siteId,
        scopeType="site",
        mitigationMode="detect",
        mitigationModeSuspicious="detect",
        monitorOnWrite=True,
        monitorOnExecute=True,
        blockOnWrite=True,
        blockOnExecute=True,
        scanNewAgents=True,
        scanOnWritten=True,
        autoMitigate=True,
        updatedAt="2026-01-01T00:00:00.000Z",
    )
    if agent.groupId:
        policy_repo.save_for_group(agent.groupId, pol.__class__(
            id="detect-group-pol",
            scopeId=agent.groupId,
            scopeType="group",
            mitigationMode="detect",
            mitigationModeSuspicious="detect",
            monitorOnWrite=True,
            monitorOnExecute=True,
            blockOnWrite=True,
            blockOnExecute=True,
            scanNewAgents=True,
            scanOnWritten=True,
            autoMitigate=True,
            updatedAt="2026-01-01T00:00:00.000Z",
        ))
    policy_repo.save_for_site(agent.siteId, pol)
    return pol


# ── Activity step ─────────────────────────────────────────────────────────────

class TestActivityStep:
    """Tests for action == 'activity'."""

    def test_creates_activity_in_repo(self, agent, run) -> None:
        """Activity step appends a new Activity to the repo."""
        before = len(activity_repo.list_all())
        step = {"action": "activity", "activityType": 2, "description": "Test activity"}
        _execute_step(step, agent, run, [])
        assert len(activity_repo.list_all()) == before + 1

    def test_activity_uses_correct_type(self, agent, run) -> None:
        """Activity step sets the activityType from the step definition."""
        step = {"action": "activity", "activityType": 1109, "description": "Isolated"}
        _execute_step(step, agent, run, [])
        latest = activity_repo.list_all()[0]
        assert latest.activityType == 1109

    def test_activity_resolves_agent_name_template(self, agent, run) -> None:
        """The {agentName} placeholder is replaced with the agent's computer name."""
        step = {"action": "activity", "activityType": 2, "description": "Alert on {agentName}"}
        _execute_step(step, agent, run, [])
        latest = activity_repo.list_all()[0]
        assert agent.computerName in latest.primaryDescription


# ── Threat step ───────────────────────────────────────────────────────────────

class TestThreatStep:
    """Tests for action == 'threat'."""

    def test_creates_threat_in_repo(self, agent, run) -> None:
        """Threat step saves a new Threat to the repo."""
        before = len(threat_repo.list_all())
        step = {
            "action": "threat",
            "threatName": "Test.Malware",
            "fileName": "evil.exe",
            "classification": "Trojan",
            "confidenceLevel": "malicious",
        }
        threat_id_ref: list[str] = []
        _execute_step(step, agent, run, threat_id_ref)
        assert len(threat_repo.list_all()) == before + 1
        assert len(threat_id_ref) == 1

    def test_threat_has_correct_threat_name(self, agent, run) -> None:
        """Threat step sets threatName from the step definition."""
        step = {"action": "threat", "threatName": "Ransom.LockBit", "confidenceLevel": "malicious"}
        threat_id_ref: list[str] = []
        _execute_step(step, agent, run, threat_id_ref)
        tid = threat_id_ref[0]
        saved = threat_repo.get(tid)
        assert saved is not None
        assert saved.threatInfo["threatName"] == "Ransom.LockBit"

    def test_threat_step_logs_policy_evaluation_activity(self, agent, run, protect_policy) -> None:
        """Threat step immediately logs a policy evaluation activity."""
        _before = len(activity_repo.list_all())
        step = {"action": "threat", "threatName": "Test", "confidenceLevel": "malicious"}
        _execute_step(step, agent, run, [])
        activities = activity_repo.list_all()
        # Should have added a policy evaluation activity (type 3010)
        policy_acts = [a for a in activities if a.activityType == 3010]
        assert len(policy_acts) >= 1

    def test_threat_refs_cleared_on_new_threat(self, agent, run) -> None:
        """Each threat step clears and replaces threat_id_ref."""
        step = {"action": "threat", "threatName": "First", "confidenceLevel": "malicious"}
        threat_id_ref: list[str] = ["old-id"]
        _execute_step(step, agent, run, threat_id_ref)
        assert len(threat_id_ref) == 1
        assert threat_id_ref[0] != "old-id"


# ── Alert step ────────────────────────────────────────────────────────────────

class TestAlertStep:
    """Tests for action == 'alert'."""

    def test_creates_alert_in_repo(self, agent, run) -> None:
        """Alert step saves a new Alert to the repo."""
        before = len(alert_repo.list_all())
        step = {"action": "alert", "severity": "HIGH", "category": "Malware", "description": "Test"}
        _execute_step(step, agent, run, [])
        assert len(alert_repo.list_all()) == before + 1

    def test_alert_has_correct_severity(self, agent, run) -> None:
        """Alert step sets the severity from the step definition."""
        step = {"action": "alert", "severity": "CRITICAL", "category": "Ransomware", "description": "X"}
        _execute_step(step, agent, run, [])
        latest_alert = alert_repo.list_all()[-1]
        assert latest_alert.ruleInfo["severity"] == "CRITICAL"


# ── Agent state step ──────────────────────────────────────────────────────────

class TestAgentStateStep:
    """Tests for action == 'agent_state'."""

    def test_marks_agent_infected(self, agent, run) -> None:
        """Agent state step sets infected=True on the agent."""
        step = {"action": "agent_state", "infected": True, "activeThreats": 2}
        _execute_step(step, agent, run, [])
        updated = agent_repo.get(agent.id)
        assert updated.infected is True
        assert updated.isInfected is True
        assert updated.activeThreats == 2

    def test_clears_agent_infection(self, agent, run) -> None:
        """Agent state step can set infected=False to clear infection."""
        agent.infected = True
        agent.isInfected = True
        agent_repo.save(agent)
        step = {"action": "agent_state", "infected": False, "activeThreats": 0}
        _execute_step(step, agent, run, [])
        updated = agent_repo.get(agent.id)
        assert updated.infected is False

    def test_updates_network_status(self, agent, run) -> None:
        """Agent state step updates networkStatus when provided."""
        step = {"action": "agent_state", "networkStatus": "disconnected"}
        _execute_step(step, agent, run, [])
        updated = agent_repo.get(agent.id)
        assert updated.networkStatus == "disconnected"


# ── Mitigate step ─────────────────────────────────────────────────────────────

class TestMitigateStep:
    """Tests for action == 'mitigate'."""

    def _inject_threat(self, agent, run, confidence: str = "malicious") -> str:
        """Helper: inject a threat and return its ID."""
        threat_id_ref: list[str] = []
        step = {"action": "threat", "threatName": "Test", "confidenceLevel": confidence}
        _execute_step(step, agent, run, threat_id_ref)
        return threat_id_ref[0]

    def test_protect_mode_quarantines_malicious_threat(self, agent, run, protect_policy) -> None:
        """In protect mode, a malicious threat is quarantined."""
        threat_id_ref = [self._inject_threat(agent, run, "malicious")]
        step = {"action": "mitigate"}
        _execute_step(step, agent, run, threat_id_ref)
        threat = threat_repo.get(threat_id_ref[0])
        assert threat.threatInfo["mitigationStatus"] == "quarantined"
        assert threat.threatInfo["initiatedBy"] == "agent_policy"

    def test_protect_mode_kills_suspicious_threat(self, agent, run) -> None:
        """In protect mode (for suspicious), a suspicious threat is killed."""
        pol = Policy(
            id="sus-pol", scopeId=agent.groupId, scopeType="group",
            mitigationMode="protect", mitigationModeSuspicious="protect",
            monitorOnWrite=True, monitorOnExecute=True,
            blockOnWrite=True, blockOnExecute=True,
            scanNewAgents=True, scanOnWritten=True,
            autoMitigate=True, updatedAt="2026-01-01T00:00:00.000Z",
        )
        policy_repo.save_for_group(agent.groupId, pol)
        threat_id_ref = [self._inject_threat(agent, run, "suspicious")]
        step = {"action": "mitigate"}
        _execute_step(step, agent, run, threat_id_ref)
        threat = threat_repo.get(threat_id_ref[0])
        assert threat.threatInfo["mitigationStatus"] == "killed"

    def test_detect_mode_does_not_change_mitigation_status(self, agent, run, detect_policy) -> None:
        """In detect mode, the mitigate step does not quarantine — logs activity instead."""
        threat_id_ref = [self._inject_threat(agent, run, "malicious")]
        original_status = threat_repo.get(threat_id_ref[0]).threatInfo["mitigationStatus"]
        _before_acts = len(activity_repo.list_all())
        step = {"action": "mitigate"}
        _execute_step(step, agent, run, threat_id_ref)
        threat = threat_repo.get(threat_id_ref[0])
        # mitigationStatus must not change
        assert threat.threatInfo["mitigationStatus"] == original_status
        # A detect-mode activity (type 3011) must have been logged
        new_acts = activity_repo.list_all()
        detect_acts = [a for a in new_acts if a.activityType == 3011]
        assert len(detect_acts) >= 1

    def test_protect_mitigation_sets_initiated_by_agent_policy(
        self, agent, run, protect_policy
    ) -> None:
        """Auto-mitigated threats must have initiatedBy='agent_policy'."""
        threat_id_ref = [self._inject_threat(agent, run, "malicious")]
        _execute_step({"action": "mitigate"}, agent, run, threat_id_ref)
        threat = threat_repo.get(threat_id_ref[0])
        assert threat.threatInfo["initiatedBy"] == "agent_policy"
        assert threat.threatInfo["initiatedByDescription"] == "Agent Policy"

    def test_protect_mitigation_does_not_resolve_incident(
        self, agent, run, protect_policy
    ) -> None:
        """Auto-mitigation by policy must NOT close the incident — analyst must do that."""
        threat_id_ref = [self._inject_threat(agent, run, "malicious")]
        _execute_step({"action": "mitigate"}, agent, run, threat_id_ref)
        threat = threat_repo.get(threat_id_ref[0])
        assert threat.threatInfo.get("incidentStatus") != "resolved"
        assert threat.threatInfo.get("resolved") is not True

    def test_mitigate_with_empty_threat_ref_is_noop(self, agent, run) -> None:
        """Mitigate step with no threat IDs in ref does nothing."""
        before = len(activity_repo.list_all())
        _execute_step({"action": "mitigate"}, agent, run, [])
        assert len(activity_repo.list_all()) == before


# ── Bulk steps ────────────────────────────────────────────────────────────────

class TestBulkSteps:
    """Tests for resolve_all_threats and heal_all_agents."""

    def test_resolve_all_threats_marks_all_resolved(self, agent, run) -> None:
        """resolve_all_threats sets incidentStatus=resolved on every threat."""
        step = {"action": "resolve_all_threats"}
        _execute_step(step, agent, run, [])
        for t in threat_repo.list_all():
            assert t.threatInfo["incidentStatus"] == "resolved"
            assert t.threatInfo["resolved"] is True

    def test_heal_all_agents_restores_all_agents(self, agent, run) -> None:
        """heal_all_agents sets all agents online and uninfected."""
        # Dirty a couple of agents first
        for ag in agent_repo.list_all()[:3]:
            ag.infected = True
            ag.networkStatus = "disconnected"
            agent_repo.save(ag)
        step = {"action": "heal_all_agents"}
        _execute_step(step, agent, run, [])
        for ag in agent_repo.list_all():
            assert ag.infected is False
            assert ag.networkStatus == "connected"
            assert ag.isActive is True


# ── _run_playbook thread-target paths ─────────────────────────────────────────

class TestRunPlaybookThread:
    """Tests for _run_playbook called synchronously to cover thread-target paths."""

    def _make_run(self, agent, steps: list) -> PlaybookRun:
        r = PlaybookRun(
            playbookId="test",
            agentId=agent.id,
            status="running",
            steps=[StepResult(stepId=s["stepId"], status="pending") for s in steps],
        )
        set_run(r)
        reset_cancel()
        return r

    def test_invalid_agent_id_sets_error_status(self, agent) -> None:
        """When the agent cannot be found the run status must be set to 'error'."""
        steps = [{"stepId": "s1", "action": "activity", "activityType": 2, "description": "x", "delayMs": 0}]
        r = self._make_run(agent, steps)
        playbook = {"id": "test", "steps": steps}
        _run_playbook(playbook, "nonexistent-agent-id")
        assert r.status == "error"

    def test_empty_steps_playbook_sets_done_status(self, agent) -> None:
        """A playbook with zero steps must reach 'done' immediately."""
        r = PlaybookRun(playbookId="test", agentId=agent.id, status="running", steps=[])
        set_run(r)
        reset_cancel()
        _run_playbook({"id": "test", "steps": []}, agent.id)
        assert r.status == "done"

    def test_single_step_playbook_completes(self, agent) -> None:
        """A single zero-delay step must complete and leave status='done'."""
        steps = [{"stepId": "s1", "action": "activity", "activityType": 2, "description": "x", "delayMs": 0}]
        r = self._make_run(agent, steps)
        _run_playbook({"id": "test", "steps": steps}, agent.id)
        assert r.status == "done"
        assert r.steps[0].status == "done"

    def test_step_exception_marks_step_as_error(self, agent) -> None:
        """An unknown action raises no exception at the runner level — step is marked 'error' via try/except."""
        # We'll inject an action that raises inside _execute_step by using a step
        # that triggers a deliberate error (passing bad activityType won't raise,
        # so we monkey-patch threat_repo.save to raise during a threat step).
        import unittest.mock as mock
        steps = [{"stepId": "s1", "action": "threat", "threatName": "X", "confidenceLevel": "malicious", "delayMs": 0}]
        r = self._make_run(agent, steps)
        with mock.patch("application.playbook.executor.threat_repo.save", side_effect=RuntimeError("boom")):
            _run_playbook({"id": "test", "steps": steps}, agent.id)
        # Step should be marked error, run continues to done
        assert r.steps[0].status == "error"
        assert r.steps[0].error == "boom"

    def test_mitigate_with_nonexistent_threat_id_is_skipped(self, agent) -> None:
        """Mitigate step with a stale/bad threat ID must skip (continue) silently."""
        steps = [{"stepId": "s1", "action": "mitigate", "delayMs": 0}]
        r = self._make_run(agent, steps)
        # Put a nonexistent ID in ref — simulates a stale ref
        stale_ref: list[str] = ["does-not-exist"]
        _execute_step({"action": "mitigate"}, agent, r, stale_ref)
        # No exception; step handler silently skips the missing threat
        assert r.status == "running"  # run state unchanged by _execute_step

    def test_run_with_no_active_run_state_returns_early(self, agent) -> None:
        """If get_run() returns None the thread target must exit silently."""
        from application.playbook._run_state import set_run
        set_run(None)  # No active run
        reset_cancel()
        steps = [{"stepId": "s1", "action": "activity", "activityType": 2, "description": "x", "delayMs": 0}]
        # Must not raise, must exit without mutating anything
        _run_playbook({"id": "test", "steps": steps}, agent.id)

    def test_cancel_during_step_loop_stops_execution(self, agent) -> None:
        """Requesting cancel before the loop iteration sets status='cancelled'."""
        from application.playbook._run_state import request_cancel
        steps = [
            {"stepId": "s1", "action": "activity", "activityType": 2, "description": "x", "delayMs": 0},
            {"stepId": "s2", "action": "activity", "activityType": 2, "description": "y", "delayMs": 0},
        ]
        r = self._make_run(agent, steps)
        # Request cancel before the run starts — the loop checks is_cancelled() at top
        request_cancel()
        _run_playbook({"id": "test", "steps": steps}, agent.id)
        assert r.status == "cancelled"
