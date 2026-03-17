"""ASGI middleware that enforces account-level tenant isolation.

Non-admin users automatically receive an ``accountIds`` query filter scoped
to their own account.  Admin users and ``/_dev/`` paths are exempt.
"""
from __future__ import annotations

from urllib.parse import parse_qs

from starlette.types import ASGIApp, Receive, Scope, Send

from repository.store import store


class TenantScopeMiddleware:
    """Inject accountIds query parameter for non-admin users.

    If the authenticated user is not an Admin and the request does not
    already carry an ``accountIds`` query parameter, the middleware
    appends ``accountIds=<user's accountId>`` to the query string.
    This ensures non-admin tokens can only access data belonging to
    their own account.

    ``/_dev/`` paths and unauthenticated requests pass through unchanged.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")

        # Dev and CrowdStrike paths are exempt
        if "/_dev/" in path or path.startswith("/cs"):
            await self.app(scope, receive, send)
            return

        # Extract token from Authorization header
        token: str | None = None
        for header_name, header_value in scope.get("headers", []):
            if header_name == b"authorization":
                raw = header_value.decode("utf-8", errors="replace")
                if raw.startswith("ApiToken "):
                    token = raw[len("ApiToken "):]
                break

        if not token:
            await self.app(scope, receive, send)
            return

        # Look up token record
        record = store.get("api_tokens", token)
        if not record:
            await self.app(scope, receive, send)
            return

        # Admin users see everything
        if record.get("role") == "Admin":
            await self.app(scope, receive, send)
            return

        # Check if accountIds is already in query string
        qs = scope.get("query_string", b"").decode("utf-8", errors="replace")
        parsed = parse_qs(qs, keep_blank_values=True)

        if "accountIds" in parsed:
            # Non-admin user provided explicit accountIds — validate it matches
            # their own accountId to prevent cross-tenant access.
            user_account_id = record.get("accountId", "")
            provided_ids = parsed["accountIds"]
            if user_account_id and any(aid != user_account_id for aid in provided_ids):
                # Override with the user's own accountId
                qs_without = "&".join(
                    f"{k}={v}" for k, vals in parse_qs(qs, keep_blank_values=True).items()
                    if k != "accountIds" for v in vals
                )
                if qs_without:
                    new_qs = f"{qs_without}&accountIds={user_account_id}"
                else:
                    new_qs = f"accountIds={user_account_id}"
                scope["query_string"] = new_qs.encode("utf-8")
            await self.app(scope, receive, send)
            return

        # Inject the user's accountId
        account_id = record.get("accountId", "")
        if not account_id:
            await self.app(scope, receive, send)
            return

        # Append accountIds to the query string
        if qs:
            new_qs = f"{qs}&accountIds={account_id}"
        else:
            new_qs = f"accountIds={account_id}"

        scope["query_string"] = new_qs.encode("utf-8")
        await self.app(scope, receive, send)
