"""Seed Microsoft Graph User Registration Details (authentication methods)."""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.user_registration_detail import GraphUserRegistrationDetail
from repository.graph.user_registration_detail_repo import (
    graph_user_registration_detail_repo,
)
from repository.store import store


def seed_graph_user_auth(fake: Faker, user_ids: list[str]) -> None:
    """Create one registration detail per user with realistic MFA distributions.

    Approximately 80% of users have MFA registered, 60% also have phone
    authentication, and 30% have FIDO2 security keys.
    """
    for user_id in user_ids:
        # Look up user record from the graph_users collection for display info
        user = store.get("graph_users", user_id)
        if user is None:
            upn = f"{user_id}@acmecorp.onmicrosoft.com"
            display_name = user_id
        else:
            upn = getattr(user, "userPrincipalName", f"{user_id}@acmecorp.onmicrosoft.com")
            display_name = getattr(user, "displayName", user_id)

        mfa_registered = random.random() < 0.80

        methods: list[str] = []
        default_method = ""
        is_passwordless = False

        if mfa_registered:
            methods.append("microsoftAuthenticatorPush")
            default_method = "microsoftAuthenticatorPush"

            if random.random() < 0.60:
                methods.append("phoneAuthentication")

            if random.random() < 0.30:
                methods.append("fido2")
                is_passwordless = True

        sspr_enabled = mfa_registered
        sspr_registered = mfa_registered and random.random() < 0.90
        sspr_capable = sspr_registered

        detail = GraphUserRegistrationDetail(
            id=user_id,
            userPrincipalName=upn,
            userDisplayName=display_name,
            isMfaRegistered=mfa_registered,
            isMfaCapable=mfa_registered,
            methodsRegistered=methods,
            defaultMfaMethod=default_method,
            isPasswordlessCapable=is_passwordless,
            isSsprRegistered=sspr_registered,
            isSsprEnabled=sspr_enabled,
            isSsprCapable=sspr_capable,
        )
        graph_user_registration_detail_repo.save(detail)
