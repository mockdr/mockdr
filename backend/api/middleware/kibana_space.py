"""Kibana serves every API under `/s/{space_id}/` as well as at the root.

The spaces plugin's on-request interceptor strips the prefix and remembers
the space (`getSpaceIdFromPath`, `^/s/([a-z0-9_\\-]+)`; spaces plugin at
kibana v8.15.0), so `/s/default/api/cases/_find` is `/api/cases/_find` in
the default space. mockdr had no such routes: a client configured with a
space URL — which is how a multi-space deployment is addressed, the
default space included — got 404 for every call.

Deliberately not imitated: a space other than `default` is not rewritten,
and so answers the 404 an unserved path does. Kibana does not check that a
space exists on an API path (`on_post_auth_interceptor.ts` checks only
`/app` paths) and would answer from that space — empty, for a space nobody
created. mockdr holds one space; serving the default space's rules, cases
and alerts under another id would be the worse lie, so the request fails
where a client can see it.
"""
from __future__ import annotations

import re

from starlette.types import ASGIApp, Receive, Scope, Send

_MOUNT = "/kibana"
_SPACE_PATH = re.compile(r"^/kibana/s/([a-z0-9_\-]+)(/.*)?$")

#: The spaces this mock holds — the ones `GET /api/spaces/space` lists.
_SERVED_SPACES = frozenset({"default"})


class KibanaSpaceMiddleware:
    """Serve `/kibana/s/default/...` as `/kibana/...`."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            match = _SPACE_PATH.match(scope.get("path", ""))
            if match and match.group(1) in _SERVED_SPACES:
                prefix = f"{_MOUNT}/s/{match.group(1)}"
                path = _MOUNT + (match.group(2) or "")
                raw = scope.get("raw_path") or path.encode()
                if raw.startswith(prefix.encode()):
                    raw = _MOUNT.encode() + raw[len(prefix):]
                scope = {**scope, "path": path, "raw_path": raw}
        await self.app(scope, receive, send)
