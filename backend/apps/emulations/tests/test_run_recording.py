"""
Tests for turning a real run into a publishable recording.

The destination is a public marketing page, so most of this is about what must
never survive the trip. The allowlist tests matter more than the shape tests:
a wrong shape is a broken animation, a leak is someone's AWS account topology
on the internet.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.emulations.run_recording import (
    build_events,
    find_leaks,
    scrub,
)


class ScrubTests(SimpleTestCase):
    """Redaction of free text."""

    def test_redacts_each_identifier_shape(self):
        """Every shape we know about is replaced, not merely detected."""
        cases = [
            ("arn:aws:iam::123456789012:role/admin", "<ARN>"),
            ("AKIAIOSFODNN7EXAMPLE", "<AWS_KEY_ID>"),
            ("ASIAY34FZKBOKMUTVV7A", "<AWS_KEY_ID>"),
            ("123456789012", "<ACCOUNT_ID>"),
            ("responder@example.com", "<EMAIL>"),
            ("8.8.8.8", "<IP>"),
            ("i-0abc123def4567890", "<RESOURCE_ID>"),
            ("vpc-0a1b2c3d4e5f6a7b8", "<RESOURCE_ID>"),
        ]
        for raw, placeholder in cases:
            with self.subTest(raw=raw):
                out = scrub(f"before {raw} after")
                self.assertIn(placeholder, out)
                self.assertNotIn(raw, out)

    def test_arn_is_redacted_whole(self):
        """
        An ARN embeds an account id and often a role name. Redacting only the
        account id would leave 'arn:aws:iam::<ACCOUNT_ID>:role/prod-admin',
        which still leaks the role.
        """
        out = scrub("arn:aws:iam::123456789012:role/prod-admin-breakglass")
        self.assertEqual(out, "<ARN>")
        self.assertNotIn("breakglass", out)

    def test_non_routable_addresses_are_left_alone(self):
        """
        A private, loopback or documentation address identifies nothing outside
        its own network, and 169.254.169.254 is the instance metadata endpoint -
        the same constant in every AWS account, and unavoidable when describing
        a credential-theft step. Redacting those would damage the content
        without protecting anyone.
        """
        for benign in ["10.99.0.0", "169.254.169.254", "192.168.1.1", "203.0.113.42"]:
            with self.subTest(ip=benign):
                self.assertEqual(scrub(benign), benign)
                self.assertEqual(find_leaks({"note": benign}), [])

    def test_aws_managed_policy_arn_is_left_alone(self):
        """
        An AWS-managed policy ARN uses the literal "aws" as its account segment
        and is identical everywhere, so it leaks nothing - and naming it is
        unavoidable when describing a privilege escalation.
        """
        arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        self.assertEqual(scrub(arn), arn)
        self.assertEqual(find_leaks({"note": arn}), [])

    def test_a_bucket_arn_is_still_flagged(self):
        """
        arn:aws:s3:::bucket has an empty account segment, so an exemption based
        on "no account id present" would let a bucket name through. It must
        stay flagged.
        """
        arn = "arn:aws:s3:::acme-payments-prod"
        self.assertEqual(scrub(arn), "<ARN>")
        self.assertTrue(find_leaks({"note": arn}))

    def test_leaves_ordinary_text_alone(self):
        """Redaction must not mangle the prose around it."""
        text = "The attacker disabled CloudTrail in two regions."
        self.assertEqual(scrub(text), text)

    def test_handles_empty_input(self):
        """A missing field is empty, not a crash."""
        self.assertEqual(scrub(""), "")


class FindLeaksTests(SimpleTestCase):
    """The publish-time backstop."""

    def test_finds_a_routable_address_nested_anywhere(self):
        """A public IP in any field is a leak."""
        self.assertTrue(find_leaks({"infra": {"egress": "8.8.8.8"}}))

    def test_finds_an_identifier_nested_anywhere(self):
        """
        The walk has to reach every string, because the whole point is catching
        a field nobody thought about.
        """
        payload = {"chain": [{"events": [{"note": "role arn:aws:iam::123456789012:role/x"}]}]}
        leaks = find_leaks(payload)
        self.assertTrue(leaks)
        self.assertIn("chain[0].events[0].note", leaks[0])

    def test_clean_payload_reports_nothing(self):
        """A properly built recording must pass cleanly."""
        payload = {
            "run_id": "20260426_053635",
            "chain": [
                {
                    "step": 1,
                    "name": "Execute malicious container",
                    "events": [
                        {"eventSource": "ecs.amazonaws.com", "eventName": "RunTask", "t_offset_s": 0.6}
                    ],
                }
            ],
        }
        self.assertEqual(find_leaks(payload), [])

    def test_placeholders_are_not_flagged_as_leaks(self):
        """
        Redacted text contains the placeholder, not the identifier. Flagging
        '<ACCOUNT_ID>' would make the check cry wolf on its own output and
        train whoever runs it to ignore the result.
        """
        self.assertEqual(find_leaks({"note": "assumed <ARN> from <IP>"}), [])

    def test_catches_a_bare_account_id(self):
        """Twelve digits on their own are an account id."""
        self.assertTrue(find_leaks({"region": "123456789012"}))


class BuildEventsTests(SimpleTestCase):
    """Projecting CloudTrail onto the player's event shape."""

    def _record(self, name, source="ecs.amazonaws.com", t="2026-04-26T05:36:35Z", **extra):
        return {"eventTime": t, "event": {"eventName": name, "eventSource": source, **extra}}

    def test_only_allowlisted_fields_survive(self):
        """
        This is the load-bearing test. A CloudTrail record carries the account
        id, the ARN, the session name and the source IP; an event that reaches
        the website must carry exactly three keys and none of that.
        """
        events = build_events([
            self._record(
                "RunTask",
                sourceIPAddress="52.94.236.248",
                userIdentity={"arn": "arn:aws:sts::123456789012:assumed-role/x/someone@corp.com"},
                requestParameters={"cluster": "prod-payments"},
                recipientAccountId="123456789012",
            )
        ])
        self.assertEqual(len(events), 1)
        self.assertEqual(set(events[0]), {"eventSource", "eventName", "t_offset_s"})
        self.assertEqual(find_leaks(events), [])

    def test_offsets_are_relative_to_the_first_event(self):
        """The timeline starts at zero, so no wall-clock date is published."""
        events = build_events([
            self._record("A", t="2026-04-26T05:36:35Z"),
            self._record("B", t="2026-04-26T05:37:05Z"),
        ])
        self.assertEqual([e["t_offset_s"] for e in events], [0.0, 30.0])

    def test_events_are_sorted_by_time(self):
        """Archive order is not guaranteed; the replay depends on sequence."""
        events = build_events([
            self._record("Late", t="2026-04-26T05:40:00Z"),
            self._record("Early", t="2026-04-26T05:36:35Z"),
        ])
        self.assertEqual([e["eventName"] for e in events], ["Early", "Late"])

    def test_rejects_a_source_that_is_not_an_aws_endpoint(self):
        """
        eventSource is AWS vocabulary. Anything else did not come from where we
        think it did, and publishing it would be publishing unvalidated input.
        """
        events = build_events([self._record("RunTask", source="evil.example.com")])
        self.assertEqual(events, [])

    def test_rejects_a_malformed_event_name(self):
        """Same reasoning for the API call name."""
        events = build_events([self._record("Run Task; DROP")])
        self.assertEqual(events, [])

    def test_skips_records_with_no_source_or_name(self):
        """An incomplete record is dropped rather than half-published."""
        self.assertEqual(build_events([{"eventTime": "2026-04-26T05:36:35Z", "event": {}}]), [])

    def test_empty_archive_yields_no_events(self):
        """A run with no records produces an empty timeline, not an error."""
        self.assertEqual(build_events([]), [])

    def test_unparseable_timestamp_does_not_crash(self):
        """A bad eventTime degrades to offset zero rather than sinking the run."""
        events = build_events([self._record("RunTask", t="not-a-date")])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["t_offset_s"], 0.0)
