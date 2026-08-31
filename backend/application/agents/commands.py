import io
import json
import uuid as _uuid
import zipfile
from typing import cast

from application import bridge
from application.agents.queries import FILTER_SPECS as AGENT_FILTER_SPECS
from application.documented_filters import DOCUMENTED_FILTERS
from application.webhooks import commands as webhook_commands
from domain.tag import Tag
from domain.webhook import AGENT_OFFLINE
from repository.activity_repo import activity_repo
from repository.agent_repo import agent_repo
from repository.group_repo import group_repo
from repository.site_repo import site_repo
from repository.store import store
from repository.tag_repo import tag_repo
from utils.dt import utc_now
from utils.filtering import apply_filters
from utils.serde import record_dict


class UnscopedActionError(ValueError):
    """Raised when an agent action carries no filter that selects anything.

    SentinelOne requires one of ``ids``, ``groupIds`` or ``filterId`` on every
    ``/agents/actions/*`` body. Treating an absent filter as "everything" turned
    a scoped request into a fleet-wide one, so an unscoped call is refused.
    """


def _tag_by_key() -> dict[str, Tag]:
    """The tag definitions keyed by their ``key``, built once per call site.

    Looking a definition up by key used to scan the whole tag collection,
    inside the loop over an agent's tags, inside the loop over the agents a
    bulk action names: a thousand agents scanned it a thousand times.
    """
    return {t.key: t for t in tag_repo.list_all()}


def _resolve_ids(body: dict) -> list[str]:
    """Resolve an action body's filter to the agent IDs it selects.

    The whole documented filter is honoured, not just ``ids``: a body scoped by
    ``groupIds`` or ``osTypes`` previously matched nothing here and fell through
    to *every* agent, so an action aimed at one group ran against the fleet and
    reported success.

    Args:
        body: Request body carrying ``filter`` (or a bare ``ids`` list).

    Returns:
        IDs of the agents the filter selects.

    Raises:
        UnscopedActionError: If the body names no filter at all.
    """
    if body.get("ids"):
        return cast(list[str], body["ids"])

    raw_filter = body.get("filter") or {}
    if not raw_filter:
        msg = (
            "A filter is required. Supply at least one of: "
            "ids, groupIds, siteIds, accountIds."
        )
        raise UnscopedActionError(msg)

    if raw_filter.get("ids"):
        return cast(list[str], raw_filter["ids"])

    # Everything else goes through the same filter engine the list endpoint
    # uses, so an action selects exactly what a GET with those params returns
    # — the documented specs as well as the hand-written ones, because the
    # seventeen hand-written ones alone were not the set the GET applies.
    specs = [*AGENT_FILTER_SPECS, *DOCUMENTED_FILTERS.get("/agents", [])]
    params = {k: v for k, v in raw_filter.items() if v is not None}

    # A member this mock cannot apply is refused, not ignored. `apply_filters`
    # answers with every record when nothing matches a spec, so an action
    # scoped by a filter the mock does not know — a typo, or a parameter the
    # vendor documents and this does not — selected the whole fleet and did
    # its work on all of it. `approve-uninstall` scoped to sixteen servers
    # uninstalled all sixty and answered `{"affected": 60}`.
    known = {spec.param for spec in specs} | {"ids"}
    unknown = sorted(set(params) - known)
    if unknown:
        msg = (
            f"The filter names {'members' if len(unknown) > 1 else 'a member'} "
            f"this endpoint cannot select on: {', '.join(unknown)}."
        )
        raise UnscopedActionError(msg)

    records = [record_dict(a) for a in agent_repo.list_all()]
    matched = apply_filters(records, params, specs)
    return [str(r["id"]) for r in matched]


#: Actions the swagger documents that leave no mark on the agent record —
#: a shell session, a passphrase reset, a broadcast. S1 answers them the
#: same way it answers the rest, with a count and an activity, and so does
#: this: the client's next read has nothing new to find either way.
_ACTIVITY_ONLY_ACTIONS = frozenset({
    "restart-services", "fetch-logs", "broadcast", "restart-machine",
    "set-external-id", "fetch-installed-apps", "fetch-firewall-rules",
    "reset-local-config", "move-to-console",
    "set-config", "start-remote-shell", "can-start-remote-shell",
    "terminate-remote-shell", "clear-remote-shell-session", "firewall-logging",
    "local-upgrade-authorization", "reset-passphrase", "capability",
    "approve-stateless-upgrade",
})

KNOWN_ACTIONS = frozenset({
    "connect", "disconnect", "initiate-scan", "abort-scan", "shutdown",
    "enable-agent", "disable-agent", "uninstall", "decommission",
    "mark-up-to-date", "randomize-uuid", "move-to-site", "move-to-group",
    "manage-tags",
    # Documented on `/agents/actions/<name>` and answered 400 here until now,
    # so a client could not run half the actions its own console offers.
    "approve-uninstall", "reject-uninstall", "update-software",
    "ranger-enable", "ranger-disable", "start-profiling", "stop-profiling",
}) | _ACTIVITY_ONLY_ACTIONS


def execute_action(action: str, body: dict, actor_user_id: str | None = None) -> dict:
    """Apply an agent action to the resolved set of agents and log activity.

    Args:
        action: The action name (e.g. ``"connect"``, ``"disconnect"``).
        body: Request body containing optional ``filter`` or ``ids`` keys.
        actor_user_id: ID of the user performing the action, if authenticated.

    Returns:
        Dict with ``data.affected`` indicating how many agents were updated.

    Raises:
        ValueError: If the action name is not recognised.
    """
    if action not in KNOWN_ACTIONS:
        raise ValueError(f"Unknown agent action: {action!r}")

    ids = _resolve_ids(body)
    extra_data = body.get("data") or {}
    affected = 0

    for agent_id in ids:
        agent = agent_repo.get(agent_id)
        if not agent:
            continue

        if action == "connect":
            agent.networkStatus = "connected"
        elif action == "disconnect":
            agent.networkStatus = "disconnected"
            # NOTE: AGENT_INFECTED event is not fired here because no action currently
            # sets agent.infected = True via execute_action. Add firing here when
            # such an action is introduced.
        elif action == "initiate-scan":
            agent.scanStatus = "started"
            agent.scanStartedAt = utc_now()
        elif action == "abort-scan":
            agent.scanStatus = "aborted"
            agent.scanAbortedAt = utc_now()
        elif action == "shutdown":
            agent.isActive = False
        elif action == "enable-agent":
            agent.isActive = True
        elif action == "disable-agent":
            agent.isActive = False
        elif action == "uninstall":
            agent.isPendingUninstall = True
        elif action == "decommission":
            agent.isDecommissioned = True
            agent.isActive = False
        elif action in ("mark-up-to-date", "update-software"):
            # "Update the Agent version on endpoints that match the filter":
            # what a client reads afterwards is an agent that is up to date.
            agent.isUpToDate = True
        elif action == "approve-uninstall":
            # The request the endpoint's user raised is granted, so the agent
            # is no longer waiting on the console — it uninstalls.
            agent.isPendingUninstall = False
            agent.isUninstalled = True
            agent.isActive = False
        elif action == "reject-uninstall":
            agent.isPendingUninstall = False
        elif action == "ranger-enable":
            agent.rangerStatus = "Enabled"
        elif action == "ranger-disable":
            agent.rangerStatus = "Disabled"
        elif action == "start-profiling":
            agent.remoteProfilingState = "enabled"
        elif action == "stop-profiling":
            agent.remoteProfilingState = "disabled"
        elif action == "randomize-uuid":
            agent.uuid = str(_uuid.uuid4())
        elif action == "move-to-site":
            target_site_id = extra_data.get("targetSiteId")
            if target_site_id:
                target_site = site_repo.get(target_site_id)
                if target_site:
                    groups = group_repo.get_by_site(target_site_id)
                    default_group = next(
                        (g for g in groups if g.isDefault), groups[0] if groups else None
                    )
                    agent.siteId = target_site_id
                    agent.siteName = target_site.name
                    if default_group:
                        agent.groupId = default_group.id
                        agent.groupName = default_group.name
        elif action == "move-to-group":
            target_group_id = extra_data.get("targetGroupId")
            if target_group_id:
                target_group = group_repo.get(target_group_id)
                if target_group:
                    agent.groupId = target_group_id
                    agent.groupName = target_group.name
        elif action == "manage-tags":
            current: list[dict] = list(agent.tags.get("sentinelone", []))

            if isinstance(extra_data, list):
                # Real S1 format: [{"tagId": "...", "operation": "add|remove|override"}]
                for op in extra_data:
                    tag_id = op.get("tagId", "")
                    operation = op.get("operation", "")
                    tag_def = tag_repo.get(tag_id)

                    if operation == "remove":
                        current = [t for t in current if t.get("id") != tag_id]
                    elif operation == "override" and tag_def:
                        current = [{
                            "id": tag_def.id,
                            "key": tag_def.key,
                            "value": tag_def.value,
                            "assignedAt": utc_now(),
                            "assignedBy": "user",
                            "assignedById": actor_user_id or "",
                        }]
                    elif operation == "add" and tag_def:
                        existing_ids = {t.get("id") for t in current}
                        if tag_def.id not in existing_ids:
                            current.append({
                                "id": tag_def.id,
                                "key": tag_def.key,
                                "value": tag_def.value,
                                "assignedAt": utc_now(),
                                "assignedBy": "user",
                                "assignedById": actor_user_id or "",
                            })
            else:
                # Legacy format: {"tagsToAdd": [...], "tagsToRemove": [...]}
                tags_to_add = extra_data.get("tagsToAdd", [])
                tags_to_remove = set(extra_data.get("tagsToRemove", []))
                current = [t for t in current if t.get("key") not in tags_to_remove]
                existing_keys = {t.get("key") for t in current}
                for key in tags_to_add:
                    if key not in existing_keys:
                        # By key, from an index built once: the definition was
                        # looked up with a full scan of the tag collection, per
                        # tag, per agent — a bulk action over a thousand agents
                        # scanned it a thousand times over.
                        matched = _tag_by_key().get(key)
                        current.append({
                            "id": matched.id if matched else str(_uuid.uuid4()),
                            "key": key,
                            "value": matched.value if matched else key,
                            "assignedAt": utc_now(),
                            "assignedBy": "user",
                            "assignedById": actor_user_id or "",
                        })

            updated = dict(agent.tags) if agent.tags else {}
            updated["sentinelone"] = current
            agent.tags = updated
        elif action in _ACTIVITY_ONLY_ACTIONS:
            pass  # nothing on the record changes; the activity is the answer

        agent_repo.save(agent)
        # The SIEM mounts learn what this action did (ADR-009): the Splunk
        # view of the agent used to keep answering the state it was seeded
        # with, however many actions a client had run against it.
        bridge.agent_changed(agent)
        activity_repo.create(
            activity_type=52 if action == "disconnect" else 53,
            description=f"Agent action '{action}' executed",
            agent_id=agent_id,
            user_id=actor_user_id,
            site_id=agent.siteId,
        )
        if action == "disconnect":
            webhook_commands.fire_event(AGENT_OFFLINE, record_dict(agent))
        affected += 1

    return {"data": {"affected": affected}}


def fetch_files(
    agent_id: str,
    files: list[str],
    password: str,
    user_id: str | None = None,
) -> dict:
    """Queue a file collection from an agent and store a fake zip for download.

    Implements POST /agents/{id}/actions/fetch-files.
    The generated zip contains ``manifest.json`` plus the requested file;
    use ``GET /agents/{id}/uploads/{activity_id}`` to retrieve it.

    Args:
        agent_id: ID of the agent to collect the file from.
        files: List of file paths to collect (mock uses first entry).
        password: Password the caller will use to decrypt the zip.
        user_id: ID of the acting user, if authenticated.

    Returns:
        Dict with ``data.affected`` (1 on success, 0 if agent not found).
    """
    agent = agent_repo.get(agent_id)
    if not agent:
        return {"data": {"affected": 0}}

    file_path = files[0] if files else "/tmp/sample.txt"  # nosec B108 — mock default path, not real temp usage
    # Normalise to a zip-safe entry name (S1 convention: forward-slash, no drive colon)
    zip_entry = file_path.replace("\\", "/").lstrip("/").replace(":", "")
    if not zip_entry:
        zip_entry = "sample.txt"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "manifest.json",
            json.dumps({"files": [{"path": file_path, "status": "SUCCESS"}]}),
        )
        zf.writestr(
            zip_entry,
            (
                f"MOCK FETCHED FILE — SentinelOne Mock API\n"
                f"Agent: {agent.computerName}\n"
                f"Path: {file_path}\n"
                f"FetchedAt: {utc_now()}\n"
                f"\n[Simulated file content. No actual data.]\n"
            ).encode(),
        )

    activity = activity_repo.create(
        80,
        f"File collected: {file_path}",
        agent_id=agent_id,
        user_id=user_id,
        site_id=agent.siteId,
    )
    store.save("agent_uploads", activity.id, buf.getvalue())
    return {"data": {"affected": 1}}


def execute_remote_script(body: dict, user_id: str | None = None) -> dict:
    """Execute a remote script on specified agents.

    Implements POST /remote-scripts/execute. Creates a simulated
    execution record and logs activity.

    Args:
        body: Request body with ``data`` (script info) and ``filter`` (agent IDs).
        user_id: ID of the acting user.

    Returns:
        Dict with execution metadata including ``affected`` count and ``parentTaskId``.
    """
    data = body.get("data") or body
    agent_ids = _resolve_ids(body)
    script_id = data.get("scriptId", "")
    output_destination = data.get("outputDestination", "SentinelCloud")
    task_description = data.get("taskDescription", "Remote script execution")
    timeout = data.get("timeout", 600)

    affected = 0
    task_id = str(_uuid.uuid4())

    for agent_id in agent_ids:
        agent = agent_repo.get(agent_id)
        if not agent or agent.isDecommissioned:
            continue
        run_id = str(_uuid.uuid4())
        store.save("remote_script_runs", run_id, {
            "id": run_id,
            "parentTaskId": task_id,
            "agentId": agent_id,
            "scriptId": script_id,
            "status": "completed",
            "outputDestination": output_destination,
            "taskDescription": task_description,
            "timeout": timeout,
            "createdAt": utc_now(),
        })
        activity_repo.create(
            activity_type=81,
            description=f"Remote script executed: {task_description}",
            agent_id=agent_id,
            user_id=user_id,
            site_id=agent.siteId,
        )
        affected += 1

    return {
        "data": {
            "affected": affected,
            "parentTaskId": task_id,
        }
    }
