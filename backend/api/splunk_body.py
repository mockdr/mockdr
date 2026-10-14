"""The parameters of a Splunk write request, whichever way the client sent them."""
from __future__ import annotations

from typing import Any, cast

from fastapi import Request


async def parse_body(request: Request) -> dict:
    """The request's parameters, from a form body or a JSON object.

    splunklib posts forms; other clients post JSON. A JSON ``null``, array
    or scalar is not a parameter set and reads as an empty one, so the route
    reports the parameter it needed instead of a 500 from ``.get()``.
    """
    content_type = request.headers.get("content-type", "")
    if "form" in content_type:
        form = await request.form()
        return {k: str(v) for k, v in form.items()}
    try:
        parsed = await request.json()
    except Exception:
        return {}
    return cast(dict[str, Any], parsed) if isinstance(parsed, dict) else {}
