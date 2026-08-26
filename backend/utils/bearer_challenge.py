"""The challenge a Bearer-protected 401 has to carry.

RFC 6750 §3: a resource server that refuses a request protected by a Bearer
token answers with `WWW-Authenticate`, and the challenge is where a client
learns *where* to go and get one. Every mocked OAuth mount answered 401 with
a body and no challenge at all, so a client that follows the standard — the
Microsoft identity libraries do, and it is how the authority is discovered —
had nothing to follow, and one built against mockdr would be written without
the step the real service requires.

The same section draws a distinction worth keeping: when the request carried
no credentials at all, the challenge names no error, because nothing was
wrong with a token that was never sent. An `error="invalid_token"` belongs
only on a token that was sent and refused.
"""
from __future__ import annotations

from starlette.requests import Request


def bearer_challenge(
    request: Request | None,
    token_path: str,
    description: str = "",
) -> dict[str, str]:
    """Build the `WWW-Authenticate` header for a refused Bearer request.

    Args:
        request:     The refused request, read for the base URL the client
                     reached this mock at — a relative authorization_uri is
                     no use to a client that has to call it.
        token_path:  The mount's own token endpoint.
        description: What was wrong with the token that was sent. Empty when
                     none was sent, which the challenge then stays silent
                     about.

    Returns:
        A single-entry header mapping, ready to hand to ``HTTPException``.
    """
    base = str(request.base_url).rstrip("/") if request is not None else ""
    parts = [f'Bearer realm="{base or "mockdr"}"',
             f'authorization_uri="{base}{token_path}"']
    if description:
        parts.append('error="invalid_token"')
        parts.append(f'error_description="{description}"')
    return {"WWW-Authenticate": ", ".join(parts)}
