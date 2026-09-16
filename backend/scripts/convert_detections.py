#!/usr/bin/env python3
"""
Compile the shipped Sigma rules into a SIEM's query language.

    python backend/scripts/convert_detections.py --target splunk
    python backend/scripts/convert_detections.py --target splunk --out dist/splunk
    python backend/scripts/convert_detections.py --target splunk \
        --output-format savedsearches --out dist/splunk
    python backend/scripts/convert_detections.py --list-targets

Without --out the queries are printed, which is the quickest way to eyeball what
a customer would actually paste into their search bar. With --out one file is
written per emulation, so the result can be handed over or committed.

Deliberately Django-free, like validate_detections.py beside it: it imports only
apps.emulations.sigma_convert, so it needs no settings, database or AWS
credentials. Install the toolchain with:

    pip install -r backend/requirements-dev.txt

Exits 0 when every matched file compiled, 1 otherwise, so it can gate a job of
its own if the compile check in validate_detections.py is ever split out.
"""

from __future__ import annotations

import argparse
import glob
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT / "backend"))

from apps.emulations.sigma_convert import (  # noqa: E402
    TARGETS,
    BackendUnavailable,
    available_targets,
    convert,
)

DEFAULT_PATTERN = "emulations/*/detections/sigma_*.yml"

# One file per target holds every query for an emulation, named for the target's
# own convention so the artefact is droppable rather than needing a rename.
_EXTENSIONS = {"splunk": ".spl", "opensearch": ".lucene"}
_FORMAT_EXTENSIONS = {"savedsearches": ".conf", "dsl_lucene": ".json"}


def _emulation_of(path: str) -> str:
    """The emulation package a detection file belongs to."""
    return Path(path).parent.parent.name


def _extension(target: str, output_format: str) -> str:
    return _FORMAT_EXTENSIONS.get(output_format) or _EXTENSIONS.get(target, ".txt")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--target", help=f"one of: {', '.join(TARGETS)}")
    parser.add_argument("--output-format", default="default")
    parser.add_argument("--out", help="directory to write compiled queries into")
    parser.add_argument("--pattern", default=DEFAULT_PATTERN)
    parser.add_argument(
        "--list-targets", action="store_true", help="show targets and whether each is installed"
    )
    args = parser.parse_args()

    if args.list_targets:
        installed = set(available_targets())
        for name, target in TARGETS.items():
            mark = "installed" if name in installed else f"missing: pip install {target.install}"
            formats = ", ".join(target.output_formats)
            print(f"  {name:<12} {target.label:<38} [{formats}]  {mark}")
        return 0

    if not args.target:
        parser.error("--target is required (or use --list-targets)")
    if args.target not in TARGETS:
        parser.error(f"unknown target {args.target!r}; one of: {', '.join(TARGETS)}")
    if args.output_format not in TARGETS[args.target].output_formats:
        parser.error(
            f"{args.target} supports output formats: "
            f"{', '.join(TARGETS[args.target].output_formats)}"
        )

    paths = sorted(glob.glob(args.pattern, recursive=True))
    if not paths:
        print(f"No files matched: {args.pattern}")
        return 1

    out_dir = Path(args.out) if args.out else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    by_emulation: dict[str, list[str]] = {}
    compiled = skipped = failed = 0

    for path in paths:
        text = Path(path).read_text(encoding="utf-8")
        try:
            result = convert(text, args.target, output_format=args.output_format)
        except BackendUnavailable as exc:
            return int(bool(print(exc)) or 1)

        if not result.ok:
            failed += 1
            print(f"FAIL  {path}\n        {result.error}", file=sys.stderr)
            continue

        compiled += len(result.queries)
        skipped += len(result.skipped)

        lines = []
        for query in result.queries:
            if query.title:
                lines.append(f"# {query.title}")
            lines.append(query.query)
            lines.append("")
        for miss in result.skipped:
            lines.append(f"# SKIPPED  {miss.title}: {miss.reason}")
            lines.append("")

        if out_dir:
            by_emulation.setdefault(_emulation_of(path), []).extend(lines)
        else:
            print(f"### {path}")
            print("\n".join(lines))

    if out_dir:
        extension = _extension(args.target, args.output_format)
        for emulation, lines in sorted(by_emulation.items()):
            destination = out_dir / f"{emulation}{extension}"
            destination.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        print(f"Wrote {len(by_emulation)} file(s) to {out_dir}/")

    print(
        f"\n{compiled} quer(ies) compiled for {args.target} from {len(paths)} file(s); "
        f"{skipped} correlation(s) the backend cannot express; {failed} file(s) failed."
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
