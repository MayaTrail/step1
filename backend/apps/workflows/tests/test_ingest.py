"""
Tests for webhook verification and alert parsing.

The signature cases matter more than the parsing ones. This endpoint is the
only unauthenticated route in the platform, and what it guards is the claim
that a client's detections work: anyone able to post an unsigned alert could
manufacture a passing score on a security scorecard.
"""

import json

from django.test import SimpleTestCase

from apps.workflows.ingest import (
    MAX_BODY_BYTES,
    MAX_CLOCK_SKEW_SECONDS,
    IngestRejected,
    expected_signature,
    parse_alert,
    verify,
)

SECRET = "s3cret-value"
NOW = 1_757_000_000.0


def signed(body: bytes, *, secret: str = SECRET, timestamp: str = str(int(NOW))):
    """
    Build the headers a correctly configured SIEM would send.

    Args:
        body: The raw request body.
        secret: Secret to sign with; a different one simulates a wrong key.
        timestamp: Timestamp to sign and send.

    Returns:
        Tuple of (timestamp, signature).
    """
    return timestamp, expected_signature(secret, timestamp, body)


class SignatureTests(SimpleTestCase):
    """What the endpoint accepts and refuses."""

    def test_a_correctly_signed_request_is_accepted(self):
        """The happy path a client's webhook action produces."""
        body = json.dumps({"ruleName": "IAM key created"}).encode()
        timestamp, signature = signed(body)
        verify(SECRET, timestamp, signature, body, now=NOW)

    def test_a_tampered_body_is_refused(self):
        """
        Signing covers the body, so editing it after signing invalidates it.

        Without this an attacker could take one genuine alert and rewrite which
        rule it claims fired.
        """
        body = json.dumps({"ruleName": "IAM key created"}).encode()
        timestamp, signature = signed(body)
        with self.assertRaises(IngestRejected):
            verify(SECRET, timestamp, signature, body + b" ", now=NOW)

    def test_the_wrong_secret_is_refused(self):
        """Holding the URL is not enough; the secret is what authorises."""
        body = b"{}"
        timestamp, signature = signed(body, secret="not-the-secret")
        with self.assertRaises(IngestRejected):
            verify(SECRET, timestamp, signature, body, now=NOW)

    def test_a_stale_request_is_refused(self):
        """
        A captured request stops working within minutes.

        The timestamp is signed along with the body, so it cannot be refreshed
        without the secret, which is what makes this a replay defence rather
        than a formality.
        """
        body = b"{}"
        old = str(int(NOW - MAX_CLOCK_SKEW_SECONDS - 1))
        timestamp, signature = signed(body, timestamp=old)
        with self.assertRaises(IngestRejected):
            verify(SECRET, timestamp, signature, body, now=NOW)

    def test_a_request_from_a_fast_clock_is_still_accepted(self):
        """Ordinary drift in the client's direction must not reject good alerts."""
        body = b"{}"
        timestamp, signature = signed(body, timestamp=str(int(NOW + 60)))
        verify(SECRET, timestamp, signature, body, now=NOW)

    def test_an_oversized_body_is_refused_before_parsing(self):
        """Refused on length alone, so a large payload costs no parsing work."""
        body = b"x" * (MAX_BODY_BYTES + 1)
        timestamp, signature = signed(body)
        with self.assertRaises(IngestRejected):
            verify(SECRET, timestamp, signature, body, now=NOW)

    def test_missing_headers_are_refused(self):
        """An unsigned post is refused rather than treated as anonymous."""
        with self.assertRaises(IngestRejected):
            verify(SECRET, "", "", b"{}", now=NOW)

    def test_a_non_numeric_timestamp_is_refused(self):
        """Refused rather than coerced, since a bad timestamp defeats freshness."""
        with self.assertRaises(IngestRejected):
            verify(SECRET, "not-a-number", "sha256=deadbeef", b"{}", now=NOW)


class ParseTests(SimpleTestCase):
    """
    Turning a posted payload into the fields correlation matches on.

    Parsing is forgiving on purpose. A rejected alert becomes a false "your
    SIEM missed this", which is the most damaging thing this feature can say,
    so a field we cannot read comes back empty rather than raising.
    """

    def test_the_documented_schema_is_read(self):
        """The shape the client is asked to map their SIEM onto."""
        parsed = parse_alert({
            "ruleId": "D0C9C024-A07E-51CF-9A04-9A3196CFC77C",
            "ruleName": "IAM access key created for another user",
            "technique": "T1098.001",
            "severity": "high",
            "firedAt": "2026-09-10T06:12:00Z",
        })
        self.assertEqual(parsed["ruleName"], "IAM access key created for another user")
        self.assertEqual(parsed["technique"], "T1098.001")
        self.assertEqual(parsed["severity"], "high")

    def test_snake_case_variants_are_accepted(self):
        """SIEMs name the same field differently even when mapping to our schema."""
        parsed = parse_alert({"rule_id": "abc", "rule_name": "Something", "level": "medium"})
        self.assertEqual(parsed["ruleId"], "abc")
        self.assertEqual(parsed["ruleName"], "Something")
        self.assertEqual(parsed["severity"], "medium")

    def test_a_technique_carried_only_in_tags_is_found(self):
        """Many teams tag the technique rather than giving it a field."""
        parsed = parse_alert({"ruleName": "Backdoor", "tags": ["attack.persistence", "attack.t1098.001"]})
        self.assertIn("t1098.001", parsed["technique"])

    def test_an_empty_payload_parses_to_empty_fields(self):
        """Accepted with nothing known, rather than refused."""
        parsed = parse_alert({})
        self.assertEqual(parsed["ruleId"], "")
        self.assertEqual(parsed["raw"], {})

    def test_the_original_payload_is_kept(self):
        """A verdict must always be traceable to the evidence that produced it."""
        payload = {"ruleName": "X", "custom": {"nested": True}}
        self.assertEqual(parse_alert(payload)["raw"], payload)

    def test_long_values_are_truncated_not_rejected(self):
        """A verbose SIEM should not be able to overflow a column."""
        parsed = parse_alert({"ruleName": "n" * 900, "ruleId": "i" * 900})
        self.assertEqual(len(parsed["ruleName"]), 400)
        self.assertEqual(len(parsed["ruleId"]), 200)
