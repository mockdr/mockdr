"""ASGI middleware that enforces account-level tenant isolation.

Non-admin users automatically receive an ``accountIds`` query filter scoped
to their own account.  Admin users and ``/_dev/`` paths are exempt.
"""
from __future__ import annotations

from urllib.parse import parse_qs

from starlette.types import ASGIApp, Receive, Scope, Send

from repository.store import store


def _confined_sites(record: dict) -> str:
    """The sites a caller is confined to, as a comma-separated list.

    A user's `scope` may be `tenant`, `account` or `site` — the swagger's own
    enum — and this mock answered `scope: "site"` and the site roles that go
    with it while showing that caller every site's records. The account axis
    beside this one was already enforced, and its comment records why: "the
    scoping was inert and every caller saw the whole store". This is the same
    sentence one axis over.

    The user is read rather than the token, so a scope changed after the
    token was issued takes effect on the next request rather than the next
    token.
    """
    from repository.user_repo import user_repo  # noqa: PLC0415 - avoids a cycle

    user = user_repo.get(str(record.get("userId", "")))
    if user is None or getattr(user, "scope", "") != "site":
        return ""
    sites: list[str] = []
    for role in (getattr(user, "siteRoles", None) or []):
        if isinstance(role, dict) and role.get("id"):
            sites.append(str(role["id"]))
    return ",".join(dict.fromkeys(sites))


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
        allowed = _confined_sites(record)
        if allowed and "siteIds" in parsed:
            # A caller may narrow within their own scope and no further. The
            # account branch above guards its axis the same way: asking for
            # someone else's site returned that site's records in full.
            wanted = {
                value.strip()
                for entry in parsed["siteIds"] for value in entry.split(",") if value.strip()
            }
            permitted = [s for s in allowed.split(",") if s in wanted]
            qs = "&".join(
                f"{key}={value}"
                for key, values in parsed.items() if key != "siteIds"
                for value in values
            )
            # Nothing in common means nothing this caller may see, and an
            # empty `siteIds` would read as "no filter" — so their own scope
            # stands and the answer is empty on its own terms.
            allowed = ",".join(permitted) if permitted else allowed
        sites = allowed
        if not account_id and not sites:
            await self.app(scope, receive, send)
            return

        additions = []
        if account_id:
            additions.append(f"accountIds={account_id}")
        if sites:
            additions.append(f"siteIds={sites}")
        new_qs = "&".join([qs, *additions]) if qs else "&".join(additions)

        scope["query_string"] = new_qs.encode("utf-8")
        await self.app(scope, receive, send)
