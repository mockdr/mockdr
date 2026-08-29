"""What Kibana does with a `Content-Type` it cannot parse.

Hapi decides after routing, and only for the verbs that carry a payload — a
`GET` is never judged, whatever it sends.  Three outcomes, measured on 8.15:

* a header that is not `type/subtype` — `json`, `text/`, `/plain` — is
  `400 Invalid content-type header`;
* `text/*`, `application/json` (any casing, any parameters),
  `application/x-www-form-urlencoded`, `multipart/form-data` and
  `application/octet-stream` are parsed, so the route's own validation
  answers;
* every other syntactically valid media type — `application/yaml`,
  `application/xml`, `foo/bar`, `*/*`, `application/*` — is
  `415 Unsupported Media Type`.

A header that is *absent* is parsed, not refused: absent is not invalid.  And
the body need not be there at all — a `POST` with no body under `foo/bar` is
415 all the same, which is where this differs from Elasticsearch, whose 406
is only raised for a request that actually carries one.
"""
from __future__ import annotations

import re

from fastapi import HTTPException, Request

from utils.es_response import build_kbn_error_response

#: `type/subtype`, both parts non-empty; parameters are ignored.
_MEDIA_TYPE = re.compile(r"^[^\s/;]+/[^\s/;]+$")

#: What Hapi has a parser for.  `text/*` is read as text, which is why a
#: `text/plain` body reaches the route and fails *its* validation instead.
_PARSED = frozenset({
    "application/json",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "application/octet-stream",
})

#: The verbs Hapi treats as carrying a payload.
_PAYLOAD_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def refuse_unreadable_content_type(request: Request) -> None:
    """Refuse the content type the way 8.15 refuses it, or say nothing.

    Raises:
        HTTPException: 400 for a malformed media type, 415 for one Hapi has
            no parser for.
    """
    if request.method not in _PAYLOAD_METHODS:
        return
    header = request.headers.get("content-type")
    if header is None:
        return
    base = header.split(";", 1)[0].strip().lower()
    if not _MEDIA_TYPE.match(base):
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, "Invalid content-type header",
        ))
    if base in _PARSED or base.startswith("text/"):
        return
    raise HTTPException(status_code=415, detail=build_kbn_error_response(
        415, "Unsupported Media Type",
    ))
