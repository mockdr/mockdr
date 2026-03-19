import io
import json
import uuid as _uuid
import zipfile
from dataclasses import asdict
from typing import cast

from application.webhooks import commands as webhook_commands
from domain.webhook import AGENT_OFFLINE
from repository.activity_repo import activity_repo
from repository.agent_repo import agent_repo
from repository.group_repo import group_repo
from repository.site_repo import site_repo
from repository.store import store
from repository.tag_repo import tag_repo
from utils.dt import utc_now


def _resolve_ids(body: dict) -> list[str]:
    """Extract agent IDs from body: supports {filter: {ids: [...]}} or {ids: [...]}."""
    if body.get("filter") and body["filter"].get("ids"):
        return cast(list[str], body["filter"]["ids"])
    if body.get("ids"):
        return cast(list[str], body["ids"])
    # If no IDs specified, apply to all non-decommissioned agents
    return [a.id for a in agent_repo.list_all() if not a.isDecommissioned]


_KNOWN_ACTIONS = frozenset({
    "connect", "disconnect", "initiate-scan", "abort-scan", "shutdown",
    "enable-agent", "disable-agent", "uninstall", "decommission",
    "mark-up-to-date", "randomize-uuid", "move-to-site", "move-to-group",
    "manage-tags",
    "restart-services", "fetch-logs", "broadcast", "restart-machine",
    "set-external-id", "fetch-installed-apps", "fetch-firewall-rules",
    "reset-local-config", "move-to-console",
})


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
    if action not in _KNOWN_ACTIONS:
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
        elif action == "mark-up-to-date":
            agent.isUpToDate = True
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
                        # Look up tag definition by key for a real ID
                        matched = next(
                            (td for td in tag_repo.list_all() if td.key == key),
                            None,
                        )
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
        elif action in (
            "restart-services", "fetch-logs", "broadcast", "restart-machine",
            "set-external-id", "fetch-installed-apps", "fetch-firewall-rules",
            "reset-local-config", "move-to-console",
        ):
            pass  # no-op; log activity only

        agent_repo.save(agent)
        activity_repo.create(
            activity_type=52 if action == "disconnect" else 53,
            description=f"Agent action '{action}' executed",
            agent_id=agent_id,
            user_id=actor_user_id,
            site_id=agent.siteId,
        )
        if action == "disconnect":
            webhook_commands.fire_event(AGENT_OFFLINE, asdict(agent))
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
