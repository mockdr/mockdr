"""ASGI middleware that enforces account-level tenant isolation.

Non-admin users automatically receive an ``accountIds`` query filter scoped
to their own account.  Admin users and ``/_dev/`` paths are exempt.
"""
from __future__ import annotations

from urllib.parse import parse_qs, urlencode

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

        # Both axes, in one pass. They used to be two branches, and the
        # account one returned before the site one could run — so a caller
        # confined to one site escaped that confinement by naming their own
        # account, which is the query string a console sends anyway.
        qs = scope.get("query_string", b"").decode("utf-8", errors="replace")
        parsed = parse_qs(qs, keep_blank_values=True)

        def confine(key: str, allowed: list[str]) -> list[str] | None:
            """What this caller may ask for on one axis, or None to leave it.

            A caller may narrow within their own scope and no further. Asking
            for something outside it leaves their own scope standing rather
            than widening to what they asked for, and an empty intersection
            keeps their scope too — an empty value would read as "no filter".
            """
            if not allowed:
                return None
            if key not in parsed:
                return allowed
            wanted = {
                value.strip()
                for entry in parsed[key] for value in entry.split(",") if value.strip()
            }
            permitted = [one for one in allowed if one in wanted]
            return permitted or allowed

        account_id = str(record.get("accountId", "") or "")
        accounts = confine("accountIds", [account_id] if account_id else [])
        confined = _confined_sites(record)
        sites = confine("siteIds", confined.split(",") if confined else [])
        if accounts is None and sites is None:
            await self.app(scope, receive, send)
            return

        # Rebuilt with `urlencode`, not an f-string: the old spelling dropped
        # every other parameter's percent-encoding, so a `%26` inside a value
        # split into a parameter of its own and silently changed the request.
        rebuilt = {
            key: values for key, values in parsed.items()
            if key not in ("accountIds", "siteIds")
        }
        if accounts is not None:
            rebuilt["accountIds"] = [",".join(accounts)]
        if sites is not None:
            rebuilt["siteIds"] = [",".join(sites)]

        scope["query_string"] = urlencode(rebuilt, doseq=True).encode("utf-8")
        await self.app(scope, receive, send)
