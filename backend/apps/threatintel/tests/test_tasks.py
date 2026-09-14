"""
Tests for the ingest task's retry decision.

Only the decision is covered here, not Celery's retry machinery. The question
worth guarding is which outcomes count as a local failure, because getting it
wrong in one direction re-polls forty publishers over a normal run, and in the
other leaves the feed a day stale after a momentary network drop.
"""

from django.test import SimpleTestCase

from apps.threatintel.tasks import is_total_failure


class TotalFailureTests(SimpleTestCase):
    """Which run outcomes indicate a problem on this side."""

    def test_every_feed_failing_is_a_local_problem(self):
        """
        Forty independent publishers do not go down together.

        This is the shape of a real run observed after the host lost DNS: all
        forty failed to resolve and the whole run finished in 0.12 seconds.
        """
        self.assertTrue(is_total_failure({"feedsOk": 0, "feedsFailed": 40}))

    def test_a_partial_failure_is_the_normal_case(self):
        """Nine subscriptions are permanently dead, so this must not retry."""
        self.assertFalse(is_total_failure({"feedsOk": 31, "feedsFailed": 8}))

    def test_a_single_surviving_feed_is_enough(self):
        """One feed answering proves the network is up, whatever the rest did."""
        self.assertFalse(is_total_failure({"feedsOk": 1, "feedsFailed": 39}))

    def test_feeds_that_returned_nothing_are_not_a_failure(self):
        """
        Quiet publishers are not an outage.

        A feed that parses but carries no items is reported as "empty", which
        counts as neither ok nor failed, so a run of only those must not retry.
        """
        self.assertFalse(is_total_failure({"feedsOk": 0, "feedsFailed": 0}))

    def test_a_skipped_run_does_not_retry(self):
        """
        Unconfigured storage will not fix itself on a second attempt.

        refresh_feed returns this shape when THREATINTEL_DIR is unset, and it
        carries no feed counts at all.
        """
        self.assertFalse(is_total_failure({"skipped": "THREATINTEL_DIR unset"}))

    def test_a_storage_error_does_not_retry(self):
        """
        The fetch worked; only the write failed, so re-fetching buys nothing.

        This shape comes back when write_latest raises, and it carries an item
        count but no feed counts.
        """
        self.assertFalse(is_total_failure({"error": "OSError: disk full", "itemCount": 294}))
