"""HTTP Event Collector request validation.

Codes and messages come from Splunk's published HEC error table. mockdr
previously accepted several bodies that real HEC rejects — a payload with no
``event`` key, a blank event, an unknown index, an acknowledged request with no
data channel — and answered ``Success`` to all of them, so a misconfigured
forwarder looked healthy. Two other bodies raised through the handler and
returned a plain-text ``500``: a non-numeric ``time`` and a JSON array.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

__all__ = [
    "EVENT_BLANK",
    "EVENT_REQUIRED",
    "INCORRECT_INDEX",
    "INVALID_FORMAT",
    "NO_CHANNEL",
    "NO_DATA",
    "QUERY_STRING_AUTH_DISABLED",
    "HecError",
    "index_allowed",
    "parse_hec_payload",
    "require_channel",
    "validate_event",
]

# Splunk's documented HEC status codes.
NO_DATA = (5, "No data")
INVALID_FORMAT = (6, "Invalid data format")
INCORRECT_INDEX = (7, "Incorrect index")
NO_CHANNEL = (10, "Data channel is missing")
EVENT_REQUIRED = (12, "Event field is required")
EVENT_BLANK = (13, "Event field cannot be blank")
QUERY_STRING_AUTH_DISABLED = (16, "Query string authorization is not enabled")


@dataclass
class HecError(Exception):
    """An HEC rejection carrying the vendor's code and message."""

    code: int
    text: str
    status_code: int = 400

    def body(self) -> dict[str, object]:
        """Render the HEC error envelope."""
        return {"text": self.text, "code": self.code}


def _fail(spec: tuple[int, str]) -> HecError:
    code, text = spec
    return HecError(code, text)


def parse_hec_payload(text: str) -> list[dict]:
    """Parse an HEC request body into a list of event objects.

    HEC accepts one JSON object, several separated by newlines, **and several
    concatenated with no separator at all** — the last of which was rejected as
    invalid JSON. A top-level array is not valid HEC input and previously
    reached the handler as a list, raising ``AttributeError`` and a 500.

    Raises:
        HecError: If the body is empty or is not well-formed HEC input.
    """
    stripped = text.strip()
    if not stripped:
        raise _fail(NO_DATA)

    decoder = json.JSONDecoder()
    events: list[dict] = []
    index = 0
    length = len(stripped)
    while index < length:
        while index < length and stripped[index].isspace():
            index += 1
        if index >= length:
            break
        try:
            value, end = decoder.raw_decode(stripped, index)
        except json.JSONDecodeError as exc:
            raise _fail(INVALID_FORMAT) from exc
        if not isinstance(value, dict):
            # HEC takes objects; an array is "Invalid data format", not a batch.
            raise _fail(INVALID_FORMAT)
        events.append(value)
        index = end

    if not events:
        raise _fail(NO_DATA)
    return events


def validate_event(event: dict, token: dict) -> None:
    """Check one event object against HEC's rules and the token's settings.

    Raises:
        HecError: If the event would be rejected by real HEC.
    """
    if "event" not in event and "fields" not in event:
        raise _fail(EVENT_REQUIRED)

    if "event" in event:
        value = event["event"]
        if value is None or (isinstance(value, str) and not value.strip()):
            raise _fail(EVENT_BLANK)
        if isinstance(value, (list, dict)) and not value:
            raise _fail(EVENT_BLANK)

    if "time" in event and _as_epoch(event["time"]) is None:
        # A non-numeric time raised ValueError out of the handler as a 500.
        raise _fail(INVALID_FORMAT)

    requested = str(event.get("index") or "").strip()
    if requested and not index_allowed(requested, token):
        raise _fail(INCORRECT_INDEX)


def _as_epoch(value: object) -> float | None:
    """Coerce an HEC ``time`` value, or None when it is not a number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def index_allowed(requested: str, token: dict) -> bool:
    """Whether *requested* is within the token's allowed indexes."""
    allowed = {
        name.strip()
        for name in str(token.get("indexes") or "").split(",")
        if name.strip()
    }
    default = str(token.get("index") or "").strip()
    if default:
        allowed.add(default)
    if not allowed:
        return True
    return requested in allowed


def require_channel(use_ack: bool, channel: str | None) -> None:
    """Enforce that an acknowledged request carries a data channel.

    Raises:
        HecError: If acknowledgement is requested without a channel header.
    """
    if use_ack and not channel:
        raise _fail(NO_CHANNEL)
