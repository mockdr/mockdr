"""Seed the Cortex XDR user directory this tenant assigns work to.

`rbac/get_users` answered three canned role accounts while every incident
was assigned to a fresh invented name — so a client that read an incident's
`assigned_user_mail` and looked the person up in the tenant's own user list
found nobody, every time. The people who are assigned incidents have to be
people the tenant has.
"""

from __future__ import annotations

from faker import Faker

from repository.store import store

#: Where the seeded directory lives; `application/xdr_rbac` reads it back.
XDR_USERS_COLLECTION = "xdr_users"

#: The three role accounts every mockdr install has, matching the other
#: platforms' admin/analyst/viewer. The address is the role, which is what
#: the rest of this install uses to address them.
_ROLE_ACCOUNTS: tuple[tuple[str, str, str, str, str], ...] = (
    ("admin", "Admin", "User", "admin", "XDR Admins"),
    ("analyst", "SOC", "Analyst", "analyst", "SOC Team"),
    ("viewer", "Viewer", "User", "viewer", "Read Only"),
)

#: How many analysts the tenant employs beside the role accounts. Incidents
#: are assigned among them, so the number bounds how many distinct assignees
#: a client can meet.
_ANALYSTS = 8


def seed_xdr_users(fake: Faker) -> list[dict]:
    """Create the tenant's user directory and return it.

    Args:
        fake: Shared Faker instance (seeded externally).

    Returns:
        The user records, role accounts first.
    """
    users: list[dict] = [
        {
            "user_email": f"{mailbox}@acmecorp.internal",
            "user_first_name": first,
            "user_last_name": last,
            "role": role,
            "status": "active",
            "pretty_name": f"{first} {last}",
            "groups": [group],
        }
        for mailbox, first, last, role, group in _ROLE_ACCOUNTS
    ]

    for _ in range(_ANALYSTS):
        name = fake.name()
        first, _, last = name.partition(" ")
        users.append({
            "user_email": f"{name.lower().replace(' ', '.')}@acmecorp.internal",
            "user_first_name": first,
            "user_last_name": last or first,
            "role": "analyst",
            "status": "active",
            "pretty_name": name,
            "groups": ["SOC Team"],
        })

    for user in users:
        store.save(XDR_USERS_COLLECTION, str(user["user_email"]), user)
    return users
