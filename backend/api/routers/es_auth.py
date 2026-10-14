"""Elasticsearch's token service: `POST` and `DELETE /_security/oauth2/token`.

Modelled on the get-token and invalidate-token references (8.15) and on
`RestGetTokenAction`, `TransportCreateTokenAction`, `CreateTokenRequest` and
`TokenService` at v8.15.0:

* the endpoint is not anonymous — the caller authenticates like any other
  request, and a `password` grant then authenticates the user in the body;
* the access token is used as `Authorization: Bearer <access_token>` and
  lives 20 minutes (`xpack.security.authc.token.timeout`);
* `password` and `refresh_token` grants answer a `refresh_token` beside it,
  `client_credentials` does not; every grant answers the `authentication`
  the token stands for;
* a refresh token is single-use, with the 30-second window in which a second
  refresh answers the same pair;
* refusals of the request itself come back in OAuth2's own shape —
  `{"error": "invalid_grant", "error_description": ...}` — not in
  Elasticsearch's error envelope.

mockdr issued a bare uuid that its own Bearer check then refused, without
asking who was calling, valid for an hour, with no refresh token.

Pre-seeded mock credentials:

* Admin:   ``elastic`` / ``mock-elastic-password``
* Analyst: ``analyst`` / ``mock-analyst-password``
* Viewer:  ``viewer`` / ``mock-viewer-password``
"""
from __future__ import annotations

import base64
import hmac
import secrets
import time

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import JSONResponse

from api.es_auth import _USERS, require_es_auth
from repository.store import store
from utils.es_response import build_es_auth_error, build_es_error_response

router = APIRouter(tags=["Elastic Security Auth"])

#: `TokenService.TOKEN_EXPIRATION`'s default: twenty minutes.
TOKEN_LIFETIME_SECONDS: int = 1200

#: How long a refresh token keeps answering a repeated refresh with the same
#: pair (`checkMultipleRefreshes`).
_REFRESH_REUSE_SECONDS = 30

#: `CreateTokenRequest.SUPPORTED_GRANT_TYPES`, in its EnumSet order.
_GRANT_TYPES = ("password", "_kerberos", "refresh_token", "client_credentials")

#: The transport action a failed password grant names (`CreateTokenAction.NAME`).
_CREATE_ACTION = "cluster:admin/xpack/security/token/create"

_ROLES = {"admin": ["superuser"], "analyst": ["analyst"], "viewer": ["viewer"]}


def _oauth_error(error: str, description: str) -> JSONResponse:
    """RFC 6749 §5.2, which is the shape `sendTokenErrorResponse` writes."""
    return JSONResponse(status_code=400, content={
        "error": error, "error_description": description,
    })


def _authentication(username: str, role: str) -> dict:
    """The `authentication` member: who the token stands for."""
    return {
        "username": username,
        "roles": list(_ROLES.get(role, [role])),
        "full_name": None,
        "email": None,
        "metadata": {},
        "enabled": True,
        "authentication_realm": {"name": "native", "type": "native"},
        "lookup_realm": {"name": "native", "type": "native"},
        "authentication_type": "realm",
    }


def _mint(username: str, role: str, *, with_refresh: bool) -> dict:
    """Store a new access token (and refresh token) and answer with them."""
    access_token = base64.b64encode(secrets.token_bytes(48)).decode()
    record = {
        "user": username, "role": role,
        "expires_at": time.time() + TOKEN_LIFETIME_SECONDS,
        "invalidated": False,
    }
    store.save("es_tokens", access_token, record)
    response: dict = {
        "access_token": access_token,
        "type": "Bearer",
        "expires_in": TOKEN_LIFETIME_SECONDS,
    }
    if with_refresh:
        refresh_token = secrets.token_urlsafe(15)
        store.save("es_refresh_tokens", refresh_token, {
            "user": username, "role": role, "access_token": access_token,
            "invalidated": False, "refreshed_at": None, "superseded_by": None,
        })
        response["refresh_token"] = refresh_token
    response["authentication"] = _authentication(username, role)
    return response


def _validation_problems(grant: str | None, body: dict) -> list[str]:
    """`CreateTokenRequest.validate()`, message for message."""
    def unsupported(*fields: str) -> list[str]:
        return [f"{field} is not supported with the {grant} grant_type"
                for field in fields if body.get(field) is not None]

    def required(*fields: str) -> list[str]:
        return [f"{field} is missing" for field in fields if not body.get(field)]

    if grant == "password":
        return unsupported("kerberos_ticket", "refresh_token") + required("username", "password")
    if grant == "refresh_token":
        return unsupported("username", "password", "kerberos_ticket") + required("refresh_token")
    if grant == "client_credentials":
        return unsupported("username", "password", "kerberos_ticket", "refresh_token")
    if grant == "_kerberos":
        return unsupported("username", "password", "refresh_token") + required("kerberos_ticket")
    return [f"grant_type only supports the values: [{', '.join(_GRANT_TYPES)}]"]


def _validation_message(problems: list[str]) -> str:
    return "Validation Failed: " + "".join(
        f"{n}: {problem};" for n, problem in enumerate(problems, 1))


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------

@router.post("/_security/oauth2/token", response_model=None)
async def create_token(
    body: dict = Body(...),
    caller: dict = Depends(require_es_auth),
) -> dict | JSONResponse:
    """Create an access token for the caller, or for the user it names.

    Raises:
        HTTPException: 401 if a ``password`` grant's credentials are wrong.
    """
    grant = body.get("grant_type")
    grant = str(grant) if grant is not None else None
    problems = _validation_problems(grant, body)
    if problems:
        error = ("unsupported_grant_type"
                 if any("grant_type" in p for p in problems) else "invalid_request")
        return _oauth_error(error, _validation_message(problems))

    if grant == "password":
        username = str(body.get("username", ""))
        user = _USERS.get(username)
        if user is None or not hmac.compare_digest(user["password"], str(body.get("password", ""))):
            raise HTTPException(status_code=401, detail=build_es_auth_error(
                401, f"unable to authenticate user [{username}] for action [{_CREATE_ACTION}]",
            ))
        return _mint(username, user["role"], with_refresh=True)

    if grant == "client_credentials":
        return _mint(str(caller.get("user", "")), str(caller.get("role", "viewer")),
                     with_refresh=False)

    if grant == "refresh_token":
        return _refresh(str(body.get("refresh_token")))

    # `_kerberos`: there is no Kerberos realm to authenticate the ticket.
    raise HTTPException(status_code=401, detail=build_es_auth_error(
        401, f"unable to authenticate user [_kerberos] for action [{_CREATE_ACTION}]",
    ))


def _refresh(refresh_token: str) -> dict | JSONResponse:
    """Trade a refresh token for a new pair, once (`TokenService.refreshToken`)."""
    record = store.get("es_refresh_tokens", refresh_token)
    if record is None:
        return _oauth_error("invalid_grant", "could not refresh the requested token")
    if record.get("invalidated"):
        return _oauth_error("invalid_grant", "token has been invalidated")
    refreshed_at = record.get("refreshed_at")
    if refreshed_at is not None:
        if time.time() > float(refreshed_at) + _REFRESH_REUSE_SECONDS:
            return _oauth_error(
                "invalid_grant",
                "token has already been refreshed more than 30 seconds in the past",
            )
        # Inside the window a concurrent refresh gets the same answer.
        return dict(record["superseded_by"])
    response = _mint(str(record["user"]), str(record["role"]), with_refresh=True)
    store.save("es_refresh_tokens", refresh_token, {
        **record, "refreshed_at": time.time(), "superseded_by": response,
    })
    return response


@router.delete("/_security/oauth2/token", response_model=None)
async def invalidate_token(
    body: dict = Body(default={}),
    _: dict = Depends(require_es_auth),
) -> JSONResponse:
    """Invalidate one token, or every token of a user.

    Answers `TokensInvalidationResult`; a token nobody holds is a 404 with
    every count at zero (`TokensInvalidationResult.emptyResult(NOT_FOUND)`).
    """
    token = body.get("token")
    refresh_token = body.get("refresh_token")
    username = body.get("username")
    realm = body.get("realm_name")
    if username or realm:
        if token or refresh_token:
            problem = "token string must not be provided when realm name or username is specified"
            raise HTTPException(status_code=400, detail=build_es_error_response(
                400, "action_request_validation_exception", _validation_message([problem])))
        return _invalidate_all(str(username) if username else None)
    if not token and not refresh_token:
        problem = "token string must be provided when not specifying a realm name or a username"
        raise HTTPException(status_code=400, detail=build_es_error_response(
            400, "action_request_validation_exception", _validation_message([problem])))
    collection = "es_tokens" if token else "es_refresh_tokens"
    key = str(token or refresh_token)
    record = store.get(collection, key)
    if record is None:
        return _invalidation(0, 0, status=404)
    if record.get("invalidated"):
        return _invalidation(0, 1)
    store.save(collection, key, {**record, "invalidated": True})
    return _invalidation(1, 0)


def _invalidate_all(username: str | None) -> JSONResponse:
    """Every token of *username* (or of everyone, for the one realm there is).

    A pair is one token document on the cluster, so it counts once; its
    refresh token goes with it.
    """
    invalidated = previously = 0
    for key, record in store.get_all_with_keys("es_tokens").items():
        if username is not None and record.get("user") != username:
            continue
        if record.get("invalidated"):
            previously += 1
            continue
        store.save("es_tokens", key, {**record, "invalidated": True})
        invalidated += 1
    for key, record in store.get_all_with_keys("es_refresh_tokens").items():
        if username is None or record.get("user") == username:
            store.save("es_refresh_tokens", key, {**record, "invalidated": True})
    return _invalidation(invalidated, previously)


def _invalidation(invalidated: int, previously: int, *, status: int = 200) -> JSONResponse:
    return JSONResponse(status_code=status, content={
        "invalidated_tokens": invalidated,
        "previously_invalidated_tokens": previously,
        "error_count": 0,
    })
