"""
Verifying and parsing what a client's SIEM posts.

This backs the only unauthenticated route in the platform, so it is written to
be small and to refuse early. The threat it guards against is specific: the
workflow's output is a statement that a client's detections work, and anyone
who could post an unsigned alert could manufacture that statement. A forged
pass on a security scorecard is worse than no scorecard.

Protections, in the order they apply:

    signature   HMAC-SHA256 over "timestamp.body" with the endpoint's secret,
                compared in constant time. Signing the timestamp together with
                the body is what stops a captured request being replayed with a
                fresh timestamp.
    freshness   a timestamp outside MAX_CLOCK_SKEW_SECONDS is refused, so a
                captured request stops working within minutes.
    size        a body over MAX_BODY_BYTES is refused before it is parsed.

Parsing is deliberately forgiving about everything that is not security: a SIEM
that omits a field gets an accepted alert with that field empty, because a
rejected alert becomes a false "your SIEM missed this", which is the most
damaging thing this feature can say.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

SIGNATURE_HEADER = "HTTP_X_MAYATRAIL_SIGNATURE"
TIMESTAMP_HEADER = "HTTP_X_MAYATRAIL_TIMESTAMP"

# A signed request older than this is refused. Long enough to absorb ordinary
# clock drift between a client's SIEM and us, short enough that a captured
# request is not useful for long.
MAX_CLOCK_SKEW_SECONDS = 300

# Alert payloads are small. Anything larger is either a misconfiguration or an
# attempt to make the parser do expensive work, and is refused unparsed.
MAX_BODY_BYTES = 64 * 1024

# Values a field may be nested under, in the order they are tried. Different
# SIEMs name the same thing differently even when mapping to our schema, and
# accepting the obvious variants costs nothing.
_RULE_ID_KEYS = ("ruleId", "rule_id", "sigmaId", "sigma_id")
_RULE_NAME_KEYS = ("ruleName", "rule_name", "title", "name")
_TECHNIQUE_KEYS = ("technique", "mitreTechnique", "mitre_technique", "attackTechnique")
_SEVERITY_KEYS = ("severity", "level", "priority")
_FIRED_AT_KEYS = ("firedAt", "fired_at", "timestamp", "eventTime")


class IngestRejected(Exception):
    """
    Raised when a posted alert must not be accepted.

    Carries the reason for the log, never for the response: telling a caller
    why a signature failed helps an attacker more than a client, and a client
    with the secret does not need to be told.
    """


def expected_signature(secret: str, timestamp: str, body: bytes) -> str:
    """
    Compute the signature a correctly configured SIEM would send.

    Args:
        secret: The endpoint's shared secret.
        timestamp: The value of the timestamp header, as sent.
        body: The raw request body, before any parsing.

    Returns:
        A "sha256=<hex>" string, matching the format the client is asked to send.
    """
    payload = timestamp.encode() + b"." + body
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify(secret: str, timestamp: str, signature: str, body: bytes, *, now: float | None = None) -> None:
    """
    Check that a request was signed by the holder of the endpoint's secret.

    Args:
        secret: The endpoint's shared secret.
        timestamp: Value of the timestamp header.
        signature: Value of the signature header.
        body: Raw request body.
        now: Override for the current epoch seconds, for tests.

    Raises:
        IngestRejected: When the body is oversized, the timestamp is missing,
            unparseable or stale, or the signature does not match.
    """
    if len(body) > MAX_BODY_BYTES:
        raise IngestRejected(f"body exceeded {MAX_BODY_BYTES} bytes")

    if not timestamp or not signature:
        raise IngestRejected("missing signature or timestamp header")

    try:
        sent_at = float(timestamp)
    except ValueError as exc:
        raise IngestRejected("timestamp is not a number") from exc

    moment = time.time() if now is None else now
    if abs(moment - sent_at) > MAX_CLOCK_SKEW_SECONDS:
        raise IngestRejected("timestamp outside the accepted window")

    # compare_digest rather than ==, so a wrong signature takes the same time
    # to reject regardless of how many leading characters were correct.
    if not hmac.compare_digest(expected_signature(secret, timestamp, body), signature):
        raise IngestRejected("signature mismatch")


def _first(payload: dict[str, Any], keys: tuple[str, ...]) -> str:
    """
    Return the first present, non-empty value among several possible keys.

    Args:
        payload: The posted alert.
        keys: Key names to try, in order of preference.

    Returns:
        The value as a string, or an empty string when none is present.
    """
    for key in keys:
        value = payload.get(key)
        if value not in (None, "", [], {}):
            return str(value)
    return ""


def parse_alert(payload: dict[str, Any]) -> dict[str, Any]:
    """
    Reduce a posted alert to the fields correlation matches on.

    Args:
        payload: The decoded JSON body.

    Returns:
        Dict with ruleId, ruleName, technique, severity, firedAt and the whole
        payload under `raw`. Missing fields come back empty rather than raising:
        an alert we cannot fully parse is still evidence that the SIEM caught
        something, and discarding it would understate the client's coverage.
    """
    technique = _first(payload, _TECHNIQUE_KEYS)
    if not technique:
        # Many teams tag techniques as a list, and some put them only in tags.
        tags = payload.get("tags") or payload.get("mitreTactics") or []
        if isinstance(tags, (list, tuple)):
            technique = " ".join(str(tag) for tag in tags)

    return {
        "ruleId": _first(payload, _RULE_ID_KEYS)[:200],
        "ruleName": _first(payload, _RULE_NAME_KEYS)[:400],
        "technique": technique[:200],
        "severity": _first(payload, _SEVERITY_KEYS)[:32],
        "firedAt": _first(payload, _FIRED_AT_KEYS),
        "raw": payload,
    }
