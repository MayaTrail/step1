"""
Management command that runs a threat feed ingest synchronously.

The same work is scheduled daily by Celery beat. Running it here is for the
cases where waiting for the schedule is not useful:

    populating the feed straight after the feature is first deployed,
    checking a feed URL that was just added or corrected in feeds.py,
    re-matching the window after a new emulation lands, so older posts pick up
        their correlation immediately instead of at the next daily run.

Must run where THREATINTEL_DIR is writable. In docker-compose that is the
worker container; the backend mounts the same volume read-only.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.threatintel.tasks import refresh_feed


class Command(BaseCommand):
    """Poll every enabled feed, correlate the window and write it to disk."""

    help = "Fetch all threat feed subscriptions and store the correlated result."

    def handle(self, *args: Any, **options: Any) -> None:
        """
        Run one ingest and report what it produced.

        Args:
            *args: Unused positional arguments.
            **options: Unused command options.

        Raises:
            CommandError: When storage is unconfigured or the write failed.
                Raising rather than printing gives a non-zero exit status, so a
                deployment script that calls this notices the failure.
        """
        result = refresh_feed()

        if "skipped" in result:
            raise CommandError(f"Ingest skipped: {result['skipped']}")
        if "error" in result:
            raise CommandError(f"Ingest failed: {result['error']}")

        report = result.get("report", [])
        failures = [row for row in report if row.get("status") == "error"]

        self.stdout.write(
            f"Fetched {result['fetchedThisRun']} item(s) from "
            f"{result['feedsOk']} of {len(report)} feeds "
            f"({result['feedsFailed']} failed), "
            f"{result['newSinceLastRun']} new, "
            f"{result['itemCount']} in window, "
            f"{result['relatedCount']} related to an emulation."
        )

        for row in failures:
            self.stdout.write(self.style.WARNING(f"  {row['feedTitle']}: {row['detail']}"))

        self.stdout.write(self.style.SUCCESS(f"Wrote {result['path']}"))
