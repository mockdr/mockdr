"""The guard for control routes a public instance does not offer.

On an instance started with ``MOCKDR_PUBLIC=true`` the admin token is still
the documented constant, so "admin only" protects nothing. The routes this
guard sits on are the ones whose effect reaches past the visitor who called
them: replacing the whole store (and with it the tokens everyone signs in
with), making every visitor's requests fail or slow down, or throttling the
instance for everybody. The mocked vendor APIs, ``/_dev/reset`` and the
scenarios stay, since they only change mock data and a reset restores it.
"""
from __future__ import annotations

from fastapi import HTTPException

import config


def refuse_on_public_instance() -> None:
    """Answer 403 when the instance runs in public mode."""
    if config.PUBLIC_MODE:
        raise HTTPException(
            status_code=403,
            detail="this control route is disabled on a public instance (MOCKDR_PUBLIC)",
        )
