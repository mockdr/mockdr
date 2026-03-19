"""Background thread executor for playbook steps."""
import threading
import time

from application import policy_engine
from application.playbook._run_state import (
    PlaybookRun,
    StepResult,
    get_run,
    is_cancelled,
    request_cancel,
    reset_cancel,
    set_run,
)
from domain.activity import Activity, ActivityType
from domain.agent import Agent
from domain.alert import Alert
from domain.threat import Threat
from repository.activity_repo import activity_repo
from repository.agent_repo import agent_repo
from repository.alert_repo import alert_repo
from repository.threat_repo import threat_repo
from utils.dt import utc_now
from utils.id_gen import new_id

_executor_thread: threading.Thread | None = None


def _resolve_template(text: str, agent: Agent) -> str:
    """Replace ``{agentName}`` and similar template placeholders in *text*.

    Args:
        text: Template string potentially containing ``{agentName}`` or
            ``{agentId}`` placeholders.
        agent: Agent domain object providing substitution values.

    Returns:
        Resolved string with all placeholders replaced.
    """
    return (
        text
        .replace("{agentName}", agent.computerName)
        .replace("{agentId}", agent.id)
    )


def _execute_step(step: dict, agent: Agent, run: PlaybookRun, threat_id_ref: list) -> None:
    """Execute a single playbook step, mutating mock state as a side effect.

    Args:
        step: Step dict containing ``action`` and action-specific fields.
        agent: Agent domain object the step targets.
        run: Current :class:`PlaybookRun` instance (available for future
            step-level state annotation).
        threat_id_ref: Mutable list used to share the most-recently created
            threat ID between a ``"threat"`` step and subsequent ``"mitigate"``
            steps within the same playbook run.
    """
    action = step.get("action", "")
    now = utc_now()

    if action == "activity":
        desc = _resolve_template(step.get("description", ""), agent)
        act = Activity(
            id=new_id(),
            activityType=step.get("activityType", ActivityType.PROCESS_EVENT),
            primaryDescription=desc,
            description=desc,
            createdAt=now,
            updatedAt=now,
            agentId=agent.id,
            siteId=agent.siteId,
            userId=None,
            data={"subordinateActivityType": step.get("activityType", 2)},
        )
        activity_repo.append(act)

    elif action == "threat":
        tid = new_id()
        threat_id_ref.clear()
        threat_id_ref.append(tid)
        threat = Threat(
            id=tid,
            threatInfo={
                "threatId": tid,
                "threatName": step.get("threatName", "Unknown"),
                "fileName": step.get("fileName", "unknown.exe"),
                "classification": step.get("classification", "Malware"),
                "confidenceLevel": step.get("confidenceLevel", "malicious"),
                "mitigationStatus": "active",
                "incidentStatus": "unresolved",
                "analystVerdict": "undefined",
                "resolved": False,
                "sha1": step.get("sha1", ""),
                "createdAt": now,
                "updatedAt": now,
                "mitreTactic": step.get("mitreTactic", ""),
                "mitreTechnique": step.get("mitreTechnique", ""),
            },
            agentDetectionInfo={
                "agentId": agent.id,
                "agentComputerName": agent.computerName,
                "siteId": agent.siteId,
                "groupId": agent.groupId,
            },
            agentRealtimeInfo={
                "agentId": agent.id,
                "agentComputerName": agent.computerName,
            },
        )
        threat_repo.save(threat)

        # Log the policy decision as an activity right after threat injection
        policy_desc = policy_engine.describe(threat, agent)
        policy_act = Activity(
            id=new_id(),
            activityType=ActivityType.POLICY_EVALUATED,
            primaryDescription=policy_desc,
            description=policy_desc,
            createdAt=now,
            updatedAt=now,
            agentId=agent.id,
            siteId=agent.siteId,
            userId=None,
            data={
                "subordinateActivityType": ActivityType.POLICY_EVALUATED,
                "policyEvaluation": True,
            },
        )
        activity_repo.append(policy_act)

    elif action == "alert":
        aid = new_id()
        alert = Alert(
            alertInfo={
                "alertId": aid,
                "eventType": "Process",
                "analystVerdict": "undefined",
                "incidentStatus": "unresolved",
                "createdAt": now,
                "updatedAt": now,
                "reportedAt": now,
                "hitType": "Events",
                "source": "playbook",
                "isEdr": True,
                "dvEventId": None,
                "srcIp": None, "dstIp": None, "srcPort": None, "dstPort": None,
                "srcMachineIp": None, "netEventDirection": None,
                "dnsRequest": None, "dnsResponse": None,
                "registryKeyPath": None, "registryPath": None,
                "registryValue": None, "registryOldValue": None, "registryOldValueType": None,
                "modulePath": None, "moduleSha1": None,
                "loginAccountDomain": None, "loginAccountSid": None,
                "loginIsSuccessful": None, "loginIsAdministratorEquivalent": None,
                "loginType": None, "loginsUserName": None,
                "indicatorName": None, "indicatorCategory": None, "indicatorDescription": None,
                "tiIndicatorType": None, "tiIndicatorSource": None,
                "tiIndicatorComparisonMethod": None, "tiIndicatorValue": None,
            },
            ruleInfo={
                "name": step.get("category", "Malware") + " Detection Rule",
                "description": _resolve_template(step.get("description", ""), agent),
                "severity": step.get("severity", "High"),
                "queryLang": "1.0",
                "scopeLevel": "site",
                "queryType": "events",
                "treatAsThreat": "MALICIOUS",
            },
            sourceProcessInfo={
                "name": "unknown",
                "filePath": "",
                "user": "",
                "commandline": "",
                "fileHashSha1": "",
                "fileHashSha256": "",
                "fileHashMd5": "",
                "pid": 0,
                "pidStarttime": "",
                "storyline": "",
                "uniqueId": "",
                "integrityLevel": "MEDIUM",
                "subsystem": "SYS_WIN32",
                "effectiveUser": None, "realUser": None,
                "loginUser": None, "fileSignerIdentity": None,
            },
            agentDetectionInfo={
                "uuid": agent.uuid,
                "name": agent.computerName,
                "version": agent.agentVersion,
                "siteId": agent.siteId,
                "accountId": agent.accountId,
                "machineType": agent.machineType,
                "osName": agent.osName,
                "osFamily": agent.osType,
                "osRevision": agent.osRevision,
            },
            agentRealtimeInfo={
                "id": agent.uuid,
                "name": agent.computerName,
                "os": agent.osType,
                "agentVersion": agent.agentVersion,
                "siteId": agent.siteId,
                "accountId": agent.accountId,
            },
        )
        alert_repo.save(alert)

    elif action == "agent_state":
        if step.get("infected") is not None:
            agent.infected = step["infected"]
            agent.isInfected = step["infected"]
        if step.get("activeThreats") is not None:
            agent.activeThreats = step["activeThreats"]
        if step.get("networkStatus"):
            agent.networkStatus = step["networkStatus"]
        agent_repo.save(agent)

    elif action == "mitigate":
        for threat_id in threat_id_ref:
            t = threat_repo.get(threat_id)
            if not t:
                continue

            auto_action = policy_engine.evaluate(t, agent)

            if auto_action is None:
                # Policy is in detect mode — do not mitigate, log the reason
                desc = policy_engine.describe(t, agent)
                detect_act = Activity(
                    id=new_id(),
                    activityType=ActivityType.POLICY_DETECT_ONLY,
                    primaryDescription=desc,
                    description=desc,
                    createdAt=now,
                    updatedAt=now,
                    agentId=agent.id,
                    siteId=agent.siteId,
                    userId=None,
                    data={
                        "subordinateActivityType": ActivityType.POLICY_DETECT_ONLY,
                        "policyEvaluation": True,
                    },
                )
                activity_repo.append(detect_act)
            else:
                # Policy is in protect mode — apply auto-mitigation.
                # mitigationStatus uses the S1 past-tense form (same as /threats/mitigate/{action}).
                # incidentStatus is NOT changed here — that is analyst territory.
                _mitigation_map = {
                    "quarantine": "quarantined",
                    "kill": "killed",
                    "remediate": "remediated",
                    "rollback-remediation": "rollback",
                }
                t.threatInfo["mitigationStatus"] = _mitigation_map.get(auto_action, auto_action)  # noqa: E501
                t.threatInfo["initiatedBy"] = "agent_policy"
                t.threatInfo["initiatedByDescription"] = "Agent Policy"
                t.threatInfo["updatedAt"] = now
                threat_repo.save(t)

    elif action == "resolve_all_threats":
        for threat in threat_repo.list_all():
            threat.threatInfo["incidentStatus"] = "resolved"
            threat.threatInfo["resolved"] = True
            threat.threatInfo["analystVerdict"] = "false_positive"
            threat.threatInfo["updatedAt"] = now
            threat_repo.save(threat)

    elif action == "heal_all_agents":
        for ag in agent_repo.list_all():
            ag.isInfected = False
            ag.infected = False
            ag.activeThreats = 0
            ag.networkStatus = "connected"
            ag.isActive = True
            agent_repo.save(ag)


def _run_playbook(playbook: dict, agent_id: str) -> None:
    """Thread target: iterate playbook steps, sleeping between them and updating run state.

    Args:
        playbook: Playbook dict with ``id`` and ``steps``.
        agent_id: ID of the target agent; execution aborts early if not found.
    """
    agent = agent_repo.get(agent_id)
    if not agent:
        run = get_run()
        if run:
            run.status = "error"
            run.completedAt = utc_now()
        return

    run = get_run()
    if not run:
        return

    steps = playbook.get("steps", [])
    threat_id_ref: list[str] = []  # mutable reference shared across steps
    last_delay = 0

    for i, step in enumerate(steps):
        if is_cancelled():
            run.status = "cancelled"
            run.completedAt = utc_now()
            return

        # Sleep for the delta between this step's delay and the last
        delay_ms = step.get("delayMs", 0)
        sleep_s = max(0, (delay_ms - last_delay)) / 1000.0
        if sleep_s > 0:
            # Check cancel during sleep in small increments
            deadline = time.monotonic() + sleep_s
            while time.monotonic() < deadline:
                if is_cancelled():
                    run.status = "cancelled"
                    run.completedAt = utc_now()
                    return
                time.sleep(min(0.1, deadline - time.monotonic()))
        last_delay = delay_ms

        run.currentStep = i
        step_result = run.steps[i]
        step_result.status = "running"
        step_result.startedAt = utc_now()

        try:
            _execute_step(step, agent, run, threat_id_ref)
            step_result.status = "done"
        except Exception as exc:
            step_result.status = "error"
            step_result.error = str(exc)

        step_result.completedAt = utc_now()

    run.status = "done"
    run.completedAt = utc_now()


def start(playbook: dict, agent_id: str) -> PlaybookRun:
    """Start playbook execution in a background thread.

    Cancels any currently running playbook before starting the new one.

    Args:
        playbook: Playbook dict with ``id`` and ``steps``.
        agent_id: ID of the agent to run the playbook against.

    Returns:
        The new :class:`PlaybookRun` instance with status ``"running"``.
    """
    global _executor_thread

    # Cancel existing run if any
    if _executor_thread and _executor_thread.is_alive():
        request_cancel()
        _executor_thread.join(timeout=3.0)

    reset_cancel()

    steps = [StepResult(stepId=s["stepId"], status="pending") for s in playbook.get("steps", [])]
    run = PlaybookRun(
        playbookId=playbook["id"],
        agentId=agent_id,
        status="running",
        steps=steps,
        currentStep=0,
        startedAt=utc_now(),
    )
    set_run(run)

    _executor_thread = threading.Thread(target=_run_playbook, args=(playbook, agent_id), daemon=True)  # noqa: E501
    _executor_thread.start()

    return run


def cancel() -> bool:
    """Request cancellation of the running playbook.

    Returns:
        ``True`` if there was an active run to cancel, ``False`` otherwise.
    """
    run = get_run()
    if run and run.status == "running":
        request_cancel()
        return True
    return False
