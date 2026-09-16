"""
Export a real emulation run as a recording for the marketing site.

    python manage.py export_run_recording <run_id> --out ../website/.../run-recording.json

The site's run page ships a hand-authored simulation today, with an invented
run id and an invented fidelity score, on a page whose argument is "evidence you
can check". This produces the real thing.

The command refuses to write a file that still contains an account id, an ARN,
an access key id, an email or an IP. That check is a backstop - the recording is
built by allowlist, so a hit here means a bug in the builder, not a scrub that
missed - and it is deliberately fatal rather than a warning, because the
destination is a public website.
"""

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from apps.emulations.registry import get_emulation
from apps.emulations.run_recording import build_recording, find_leaks


class Command(BaseCommand):
    """Write one run out as a publishable JSON recording."""

    help = "Export an emulation run as a sanitised recording for the website."

    def add_arguments(self, parser):
        """Register command-line options."""
        parser.add_argument("run_id", help="UUID of the EmulationRun to export.")
        parser.add_argument("--out", help="Write here instead of stdout.")
        parser.add_argument(
            "--allow-no-events",
            action="store_true",
            help=(
                "Export even when no CloudTrail records were loaded. The "
                "recording will show the chain with an empty timeline."
            ),
        )

    def handle(self, *args, **options):
        """Build, verify and write the recording."""
        from apps.emulations.models import EmulationRun

        run = EmulationRun.objects.filter(id=options["run_id"]).first()
        if run is None:
            raise CommandError("No run with id %s." % options["run_id"])

        entry = get_emulation(run.emulation_type)
        if entry is None:
            raise CommandError(
                "Unknown emulation '%s'. Is EMULATIONS_BASE_DIR set?" % run.emulation_type
            )

        # The archive loader needs AWS credentials and the detections bucket.
        # When it cannot run, the recording is still useful as a chain.
        records = []
        if not run.started_at or not run.completed_at:
            self.stderr.write(
                self.style.WARNING(
                    "Run has no start/end timestamps, so there is no window to "
                    "read the archive for."
                )
            )
        else:
            try:
                from apps.emulations.detection_logs import read_records

                records = read_records(run.started_at, run.completed_at)
            except Exception as exc:  # noqa: BLE001 - absence is expected, not fatal
                self.stderr.write(
                    self.style.WARNING("Could not load CloudTrail records: %s" % exc)
                )

        if not records and not options["allow_no_events"]:
            raise CommandError(
                "No CloudTrail records for this run, so the recording would have "
                "an empty timeline. Pass --allow-no-events to export anyway."
            )

        recording = build_recording(run, entry, records)

        leaks = find_leaks(recording)
        if leaks:
            self.stderr.write(self.style.ERROR("Refusing to write: identifiers survived."))
            for leak in leaks[:20]:
                self.stderr.write("  " + leak)
            raise CommandError(
                "%d identifier(s) found. This is a bug in run_recording.py - the "
                "recording is built by allowlist and should not be able to carry "
                "these." % len(leaks)
            )

        payload = json.dumps(recording, indent=2, sort_keys=True)

        if options["out"]:
            path = Path(options["out"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(payload + "\n", encoding="utf-8")
            self.stdout.write(
                self.style.SUCCESS(
                    "Wrote %s (%d steps, %d events, %d rules)"
                    % (
                        path,
                        len(recording["chain"]),
                        recording["event_count"],
                        len(recording["detection_registry"]),
                    )
                )
            )
        else:
            self.stdout.write(payload)
