"""splunkd's `Link` header on everything addressed through a search job.

Every answer under `/services/search/jobs/{sid}` carries a `Link` back to
the job itself — on 200, 204, 404 and 405 alike — and the link is *relative
to the request*: the job itself gets `<{sid}>`, a sub-resource `<../{sid}>`,
and one level deeper `<../../{sid}>`.  The job collection carries none, and
neither do `jobs/export`, `typeahead` or `parser`, which are not jobs.

Measured on Splunk 10.4.2 against a job that exists and sids that do not.
It is the only `Link` splunkd sends, and a client following it reaches the
job a partial answer belongs to — which is the whole reason a 204 from
`/results` carries one.
"""
from __future__ import annotations

import re

from starlette.types import ASGIApp, Message, Receive, Scope, Send

#: The job, and whatever is addressed through it.  `export` is a sibling
#: endpoint rather than a sid, and answers with no `Link` at all.
_JOB = re.compile(
    r"^/splunk/services/search/(?:v2/)?jobs/(?!export(?:/|$))(?P<sid>[^/]+)(?P<rest>.*)$",
)


class SplunkJobLinkMiddleware:
    """Add splunkd's `Link: <sid>; rel=info` to every job-addressed answer."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        match = _JOB.match(scope.get("path", ""))
        if match is None:
            await self.app(scope, receive, send)
            return
        # One `../` per segment between the request and the job; a trailing
        # slash counts as a segment, which is why the count is of separators.
        target = "../" * match["rest"].count("/") + match["sid"]
        value = f"<{target}>; rel=info".encode()

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = message.setdefault("headers", [])
                if not any(name.lower() == b"link" for name, _ in headers):
                    headers.append((b"link", value))
            await send(message)

        await self.app(scope, receive, send_wrapper)
