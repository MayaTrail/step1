"""
Upload the APT dossier library to S3.

    python manage.py sync_advisories <dir> --dry-run   # print what would be written
    python manage.py sync_advisories <dir>             # write it

Reads every `*.md` in the given directory, parses each into a card record, and
writes the documents plus one `index.json` under the advisory prefix. The index
is what `/api/threat-intel/advisories/` serves, so the API never parses markdown
on a request.

`--dry-run` is the default posture for a first run: this writes to a shared
bucket, and printing the keys first is cheaper than discovering a bad parse
after 33 objects have landed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError
from django.core.management.base import BaseCommand, CommandError

from apps.threatintel import advisories, dossier


class Command(BaseCommand):
    """Parse a directory of dossier markdown and publish it to S3."""

    help = "Upload APT dossier markdown and its index to the advisory prefix in S3."

    def add_arguments(self, parser) -> None:
        """
        Declare the command's arguments.

        Args:
            parser: argparse parser supplied by Django.
        """
        parser.add_argument(
            "source",
            type=str,
            help="Directory holding the dossier *.md files.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Parse and report what would be written without contacting S3.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        """
        Parse every dossier in the source directory and upload the library.

        Args:
            *args: Unused.
            **options: Parsed arguments — `source` and `dry_run`.

        Raises:
            CommandError: The directory is missing or empty, the bucket is
                unconfigured on a real run, or an upload failed.
        """
        source = Path(options["source"]).expanduser()
        dry_run: bool = options["dry_run"]

        if not source.is_dir():
            raise CommandError(f"Not a directory: {source}")

        files = sorted(source.glob("*.md"))
        if not files:
            raise CommandError(f"No *.md dossiers found in {source}")

        if not dry_run and not advisories.is_configured():
            raise CommandError(
                "THREATINTEL_BUCKET is unset — set it before syncing, or pass --dry-run."
            )

        entries, documents = self._parse(files)
        index = dossier.build_index(entries)

        if dry_run:
            self._report_dry_run(index)
            return

        # Read the library being replaced before writing, so the run can name
        # any document this sync leaves behind. Nothing here deletes: an object
        # dropped from the index is invisible to the API but still billed for,
        # and removing it is the operator's call, not this command's.
        previous = advisories.read_index() or {}

        written = 0
        try:
            for entry in index["advisories"]:
                advisories.put_object(entry["file"], documents[entry["file"]], "text/markdown")
                written += 1
            index_uri = advisories.write_index(index)
        except (ClientError, BotoCoreError) as exc:
            raise CommandError(
                f"Upload failed after {written} of {index['totalCount']} dossier(s): {exc}. "
                "The index was not written, so readers still see the previous library — "
                f"but {written} document(s) did land in the bucket and are now unreferenced. "
                "Re-running the command overwrites them."
            ) from exc

        self.stdout.write(
            self.style.SUCCESS(f"Uploaded {written} dossier(s) and wrote {index_uri}")
        )
        self._report_orphans(previous, index)

    def _parse(self, files: list[Path]) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
        """
        Parse each dossier into an index entry, keeping its encoded body.

        Reading in text mode is deliberate: it normalises CRLF to LF, so a
        library published from Windows is byte-identical to one published from
        CI. Without it, re-syncing from a different machine would rewrite every
        object with no change a reader could see.

        Args:
            files: Dossier paths, in name order.

        Returns:
            Tuple of (index entries, object name to UTF-8 encoded markdown with
            LF line endings).

        Raises:
            CommandError: A file could not be read, has an unusable name, or
                collides with another file's slug — any of which would publish
                a library that silently omits an actor.
        """
        entries: list[dict[str, Any]] = []
        documents: dict[str, bytes] = {}
        seen: dict[str, str] = {}

        for path in files:
            try:
                markdown = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise CommandError(f"Could not read {path.name}: {exc}") from exc

            entry = dossier.parse_dossier(path.stem, markdown)
            if not entry["id"]:
                raise CommandError(f"{path.name} has no usable id — rename it.")
            if entry["id"] in seen:
                raise CommandError(
                    f"{path.name} and {seen[entry['id']]} both slugify to '{entry['id']}' — rename one."
                )

            seen[entry["id"]] = path.name
            entries.append(entry)
            documents[entry["file"]] = markdown.encode("utf-8")

        return entries, documents

    def _report_orphans(self, previous: dict[str, Any], index: dict[str, Any]) -> None:
        """
        Name documents the previous library referenced and this one does not.

        A renamed or removed dossier leaves its old object in the bucket. The
        API stops serving it the moment the index no longer lists it, so this
        is housekeeping rather than a correctness problem — but it is invisible
        unless someone says so.

        Args:
            previous: The index this run replaced; {} when there was none.
            index: The index just written.
        """
        stale = {entry.get("file") for entry in previous.get("advisories", [])} - {
            entry["file"] for entry in index["advisories"]
        }
        stale.discard(None)
        if not stale:
            return

        self.stdout.write(
            self.style.WARNING(
                f"\n{len(stale)} object(s) from the previous library are no longer referenced. "
                "They are not served, and nothing here deletes them:"
            )
        )
        for file_name in sorted(stale):
            self.stdout.write(f"  {advisories.uri(file_name)}")

    def _report_dry_run(self, index: dict[str, Any]) -> None:
        """
        Print the keys and parsed metadata a real run would publish.

        Args:
            index: Payload from dossier.build_index.
        """
        self.stdout.write(f"Would write {index['totalCount']} dossier(s) + {advisories.INDEX_KEY}:\n")
        for entry in index["advisories"]:
            self.stdout.write(
                f"  {advisories.uri(entry['file'])}\n"
                f"      {entry['name']} ({entry['reference']})"
                f"  origin={entry['origin'] or '—'}"
                f"  techniques={entry['techniqueCount']}"
                f"  tactics={len(entry['tactics'])}"
                f"  cves={entry['cveCount']}"
            )
            if not entry["summary"]:
                self.stdout.write(self.style.WARNING("      no Intelligence Overview — card will have no summary"))
        self.stdout.write(f"\n  {advisories.uri(advisories.INDEX_KEY)}")
        self.stdout.write(self.style.WARNING("\nDry run — nothing was uploaded."))
