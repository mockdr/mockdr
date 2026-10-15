"""The application permissions an access token's ``roles`` claim lists, per seeded client.

"The client credential flow uses this set of permission in place of user
scopes for application tokens"
(https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference,
``roles``). A real tenant's token lists what an admin consented to for the
app; the mock's seeded clients have no consent record, so their
permissions are derived from what the mock already lets each client do:
its role (who may write) and, on Graph, its plan (which features the
licence opens, :data:`api.graph_auth.FEATURE_GATES`).

The claim describes the client; it does not decide anything. Each mount
still authorizes a call by the role and plan stored with the token, as it
always has, so a client switched with ``POST /_dev/graph/plan`` keeps the
``roles`` its token was minted with until it fetches a new one.

Permission names are the resources' own: Microsoft Graph's from the Graph
permissions reference (https://learn.microsoft.com/en-us/graph/permissions-reference);
Defender's from each API page's Permissions table on
learn.microsoft.com/en-us/defender-endpoint/api/ (``Machine.Isolate`` on
isolate-machine, ``Ti.ReadWrite.All`` on post-ti-indicator,
``AdvancedQuery.Read.All`` on run-advanced-query-api, ``URL.Read.All`` on
get-domain-statistics, ``Alert.Read.All`` on api-hello-world, ...).

Azure Resource Manager and the Log Analytics API authorize an application
by Azure RBAC role assignment, not by app permissions (Microsoft's
Log Analytics API setup grants the app a role on the workspace,
https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/access-api),
so their tokens carry no ``roles`` claim -- "Claims are present only if a
value exists to fill it".
"""
from __future__ import annotations

# ── Microsoft Graph ──────────────────────────────────────────────────────────

#: What every Graph client reads: the directory and mail, open on every plan.
_GRAPH_DIRECTORY_READ = (
    "Application.Read.All",
    "AuditLog.Read.All",
    "Device.Read.All",
    "Directory.Read.All",
    "Group.Read.All",
    "Mail.Read",
    "Policy.Read.All",
    "User.Read.All",
)

#: Read permission -> the write permission a contributor holds instead.
_GRAPH_CONTRIBUTOR_WRITES = {
    "Mail.Read": "Mail.ReadWrite",
    "SecurityAlert.Read.All": "SecurityAlert.ReadWrite.All",
    "SecurityIncident.Read.All": "SecurityIncident.ReadWrite.All",
    "IdentityRiskyUser.Read.All": "IdentityRiskyUser.ReadWrite.All",
    "DeviceManagementManagedDevices.Read.All": "DeviceManagementManagedDevices.ReadWrite.All",
}

#: Read permission -> the write permission only an owner holds.
_GRAPH_OWNER_WRITES = {
    "Application.Read.All": "Application.ReadWrite.All",
    "Directory.Read.All": "Directory.ReadWrite.All",
    "Group.Read.All": "Group.ReadWrite.All",
    "User.Read.All": "User.ReadWrite.All",
}

#: Security alerts and incidents, and Intune: Plan 2 or Defender for Business.
_GRAPH_SECURITY_READ = (
    "DeviceManagementManagedDevices.Read.All",
    "SecurityAlert.Read.All",
    "SecurityIncident.Read.All",
)

#: Advanced hunting, Secure Score, Identity Protection, attack simulation: Plan 2.
_GRAPH_PLAN2_READ = (
    "AttackSimulation.Read.All",
    "IdentityRiskyUser.Read.All",
    "SecurityEvents.Read.All",
    "ThreatHunting.Read.All",
)

_GRAPH_WRITE_ROLES = frozenset({"owner", "contributor"})


def graph_roles(role: str, plan: str) -> list[str]:
    """The Graph application permissions a client with *role* and *plan* holds.

    ============================  =================================================
    every client                  Application, AuditLog, Device, Directory, Group,
                                  Policy, User ``.Read.All``; ``Mail.Read``
    plan2, defender_for_business  ``SecurityAlert.Read.All``,
                                  ``SecurityIncident.Read.All``,
                                  ``DeviceManagementManagedDevices.Read.All``
    plan2                         ``ThreatHunting.Read.All``,
                                  ``SecurityEvents.Read.All``,
                                  ``IdentityRiskyUser.Read.All``,
                                  ``AttackSimulation.Read.All``
    contributor, owner            ``ReadWrite`` in place of ``Read`` for mail,
                                  alerts, incidents, risky users and managed
                                  devices; plus
                                  ``DeviceManagementManagedDevices.PrivilegedOperations.All``
                                  where managed devices are open
    owner                         ``ReadWrite.All`` for applications, directory,
                                  groups and users; plus
                                  ``Policy.ReadWrite.ConditionalAccess``
    ============================  =================================================
    """
    granted = list(_GRAPH_DIRECTORY_READ)
    if plan in {"plan2", "defender_for_business"}:
        granted += _GRAPH_SECURITY_READ
    if plan == "plan2":
        granted += _GRAPH_PLAN2_READ
    if role in _GRAPH_WRITE_ROLES:
        granted = [_GRAPH_CONTRIBUTOR_WRITES.get(p, p) for p in granted]
        if "DeviceManagementManagedDevices.ReadWrite.All" in granted:
            granted.append("DeviceManagementManagedDevices.PrivilegedOperations.All")
    if role == "owner":
        granted = [_GRAPH_OWNER_WRITES.get(p, p) for p in granted]
        granted.append("Policy.ReadWrite.ConditionalAccess")
    return sorted(granted)


# ── Microsoft Defender for Endpoint (WindowsDefenderATP) ─────────────────────

_MDE_VIEWER = (
    "AdvancedQuery.Read.All",
    "Alert.Read.All",
    "File.Read.All",
    "Ip.Read.All",
    "Machine.Read.All",
    "Score.Read.All",
    "SecurityRecommendation.Read.All",
    "Software.Read.All",
    "URL.Read.All",
    "User.Read.All",
    "Vulnerability.Read.All",
)

#: The analyst triages alerts, runs the response actions and writes indicators.
_MDE_ANALYST_ADDS = (
    "Machine.CollectForensics",
    "Machine.Isolate",
    "Machine.RestrictExecution",
    "Machine.Scan",
    "Machine.StopAndQuarantine",
    "Ti.ReadWrite.All",
)

#: The admin also writes machines (tags, owner), runs live response and offboards.
_MDE_ADMIN_ADDS = ("Machine.LiveResponse", "Machine.Offboard")


def mde_roles(role: str) -> list[str]:
    """The WindowsDefenderATP application permissions a client with *role* holds.

    =======  ==========================================================
    viewer   ``Alert.Read.All``, ``Machine.Read.All``,
             ``AdvancedQuery.Read.All``, ``Vulnerability.Read.All``,
             ``Software.Read.All``, ``SecurityRecommendation.Read.All``,
             ``Score.Read.All``, ``File.Read.All``, ``Ip.Read.All``,
             ``URL.Read.All``, ``User.Read.All``
    analyst  the viewer's, with ``Alert.ReadWrite.All`` for
             ``Alert.Read.All``; plus ``Machine.Isolate``,
             ``Machine.RestrictExecution``, ``Machine.Scan``,
             ``Machine.CollectForensics``, ``Machine.StopAndQuarantine``,
             ``Ti.ReadWrite.All``
    admin    the analyst's, with ``Machine.ReadWrite.All`` for
             ``Machine.Read.All``; plus ``Machine.LiveResponse``,
             ``Machine.Offboard``
    =======  ==========================================================

    An unknown role holds the viewer's.
    """
    granted = list(_MDE_VIEWER)
    if role in {"analyst", "admin"}:
        granted = [("Alert.ReadWrite.All" if p == "Alert.Read.All" else p) for p in granted]
        granted += _MDE_ANALYST_ADDS
    if role == "admin":
        granted = [("Machine.ReadWrite.All" if p == "Machine.Read.All" else p) for p in granted]
        granted += _MDE_ADMIN_ADDS
    return sorted(granted)
