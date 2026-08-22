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
from collections.abc import Callable
from dataclasses import dataclass

__all__ = [
    "EVENT_BLANK",
    "EVENT_REQUIRED",
    "INCORRECT_INDEX",
    "INVALID_FORMAT",
    "NO_CHANNEL",
    "NO_DATA",
    "INDEXED_FIELDS_ERROR",
    "ACK_DISABLED",
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
INDEXED_FIELDS_ERROR = (15, "Error in handling indexed fields")
QUERY_STRING_AUTH_DISABLED = (16, "Query string authorization is not enabled")
ACK_DISABLED = (14, "ACK is disabled")



@dataclass
class HecError(Exception):
    """An HEC rejection carrying the vendor's code and message.

    ``event_number`` is the zero-based position of the event that failed,
    when the failure belongs to an event rather than to the request.
    """

    code: int
    text: str
    status_code: int = 400
    event_number: int | None = None

    def body(self) -> dict[str, object]:
        """Render the HEC error envelope.

        ``invalid-event-number`` is the position of the first failing event,
        zero-based: ``[ok, ok, bad]`` reports 2. Measured on Splunk 10.4.2 —
        with one exception it also reproduces: code 7 (``Incorrect index``)
        reports one *higher* than the others for the same position, a
        splunkd quirk a client written against it has adapted to. Request-
        level failures (no data, no token, no channel) carry no position and
        no key, because there was no event to point at.
        """
        envelope: dict[str, object] = {"text": self.text, "code": self.code}
        if self.event_number is not None:
            off_by_one = 1 if self.code == INCORRECT_INDEX[0] else 0
            envelope["invalid-event-number"] = self.event_number + off_by_one
        return envelope


def _fail(spec: tuple[int, str], position: int | None = None) -> HecError:
    code, text = spec
    return HecError(code, text, event_number=position)


def parse_hec_payload(
    text: str, on_event: Callable[[dict, int], None] | None = None,
) -> list[dict]:
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
        except (json.JSONDecodeError, RecursionError) as exc:
            # The stdlib decoder recurses per nesting level and gives up
            # around a thousand deep with RecursionError, not a decode
            # error. That escaped as a 500; to HEC it is malformed data.
            raise _fail(INVALID_FORMAT, position=len(events)) from exc
        # A top-level array is accepted as a batch of its elements
        # (measured on 10.4.2: 200 Success); anything else is not an event.
        items = value if isinstance(value, list) else [value]
        for item in items:
            if not isinstance(item, dict):
                raise _fail(INVALID_FORMAT, position=len(events))
            events.append(item)
            if on_event is not None:
                # Validate as soon as it is parsed: HEC streams, so a blank
                # event at 0 is reported before broken JSON at 1 is reached.
                on_event(item, len(events) - 1)
        index = end

    if not events:
        raise _fail(NO_DATA)
    return events


def validate_event(event: dict, token: dict, position: int = 0) -> None:
    """Check one event object against HEC's rules and the token's settings.

    Args:
        event:    The event object.
        token:    The HEC token context.
        position: Where the event sits in its batch, for the error envelope.

    Raises:
        HecError: If the event would be rejected by real HEC.
    """
    if "event" not in event and "fields" not in event:
        raise _fail(EVENT_REQUIRED, position)

    if "event" in event:
        value = event["event"]
        if value is None or (isinstance(value, str) and not value.strip()):
            raise _fail(EVENT_BLANK, position)
        if isinstance(value, (list, dict)) and not value:
            raise _fail(EVENT_BLANK, position)

    if "time" in event and _as_epoch(event["time"]) is None:
        # A non-numeric time is an indexed-field error, code 15 — not a
        # data-format error. Measured on 10.4.2.
        raise _fail(INDEXED_FIELDS_ERROR, position)

    requested = str(event.get("index") or "").strip()
    if requested and not index_allowed(requested, token):
        raise _fail(INCORRECT_INDEX, position)


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
