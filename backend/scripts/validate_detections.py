#!/usr/bin/env python3
"""
Validate every Sigma detection rule shipped under emulations/.

Run locally or from CI:

    python backend/scripts/validate_detections.py
    python backend/scripts/validate_detections.py "emulations/aws_*/detections/*.yml"

Exits 0 when every rule passes and 1 on the first failure, so a CI job can gate
a pull request on it.

Deliberately free of Django. The two modules it imports (apps.emulations
.detections and apps.emulations.sigma_eval) depend only on the standard library
and PyYAML, so the job needs no settings module, no database and no SECRET_KEY.

Five checks, each covering a defect class seen in review:

  1. Structure. pySigma parses the file, resolves every correlation reference
     and parses every condition. Catches malformed ids, unknown levels,
     unnamespaced tags, correlations pointing at rules that do not exist,
     conditions naming selection blocks that were never defined, and the
     removed v1 pipe aggregation syntax.
  2. Rendering. parse_sigma yields the metadata the detection library needs.
     A rule that parses but renders blank is invisible in the product.
  3. Evaluability. Every non-correlation document runs under the in-process
     evaluator, so an unsupported field modifier fails here rather than
     halfway through a paid AI validation run.
  4. Unique ids across the corpus. pySigma checks id format, not collisions.
  5. Filenames. detections.py groups the trio by prefix and technique key; a
     misnamed file is silently dropped from the API response.
"""

from __future__ import annotations

import glob
import sys
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT / "backend"))

try:
    from sigma.collection import SigmaCollection
except ImportError:
    sys.exit("pySigma is required: pip install -r backend/requirements-dev.txt")

from apps.emulations.detections import parse_sigma, parse_sigma_documents
from apps.emulations.sigma_eval import is_evaluable

DEFAULT_PATTERN = "emulations/*/detections/sigma_*.yml"

# Mirrors apps/emulations/detections.py, which pairs the three file kinds of one
# technique by stripping these prefixes.
_VALID_PREFIXES = ("sigma_", "kql_", "detection_note_")

# Metadata the detection library cannot render without.
_REQUIRED_DISPLAY_FIELDS = ("title", "level", "logsource")


def check_structure(text: str) -> list[str]:
    """
    Validate one file with pySigma, including the two deferred stages.

    from_yaml alone accepts a correlation naming a rule that does not exist and
    a condition naming a missing selection block, because references resolve
    and conditions parse lazily. Both are forced here.
    """
    try:
        collection = SigmaCollection.from_yaml(text)
        collection.resolve_rule_references()
        for rule in collection.rules:
            detection = getattr(rule, "detection", None)
            if detection is None:
                continue
            for condition in detection.parsed_condition:
                condition.parse()
    except Exception as exc:
        return [f"{type(exc).__name__}: {str(exc).splitlines()[0]}"]
    return []


def check_rendering(text: str) -> list[str]:
    """Confirm parse_sigma yields the fields the detection detail page reads."""
    parsed = parse_sigma(text)
    if not parsed:
        return ["parse_sigma returned nothing, the detail page would render empty"]
    missing = [field for field in _REQUIRED_DISPLAY_FIELDS if not parsed.get(field)]
    return [f"parse_sigma yields no {field}" for field in missing]


def check_evaluability(text: str) -> list[str]:
    """
    Confirm every standalone document runs under the in-process evaluator.

    Correlation documents are skipped: they span many events and the evaluator
    judges one, so they are reported as not evaluable by design rather than as
    a defect. Documents a correlation references are covered here, because an
    unsupported modifier in a base rule still breaks the correlation.
    """
    problems = []
    for document in parse_sigma_documents(text):
        if document.get("correlation") or not document.get("detection"):
            continue
        evaluable, reason = is_evaluable(document)
        if not evaluable:
            title = document.get("title", "<untitled>")
            problems.append(f"'{title}' is not evaluable: {reason}")
    return problems


def check_filenames(paths: list[str]) -> list[str]:
    """Confirm sibling detection files follow the prefix naming convention."""
    problems = []
    for directory in sorted({str(Path(path).parent) for path in paths}):
        for sibling in sorted(Path(directory).iterdir()):
            if sibling.is_dir() or sibling.name.startswith("."):
                continue
            if sibling.name.upper() == "README.MD":
                continue
            if not sibling.name.startswith(_VALID_PREFIXES):
                problems.append(
                    f"{sibling}: name matches no known prefix "
                    f"{_VALID_PREFIXES}, so detections.py ignores it"
                )
    return problems


def main() -> int:
    """Run every check over the matched files and report a single verdict."""
    pattern = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PATTERN
    paths = sorted(glob.glob(pattern, recursive=True))
    if not paths:
        print(f"No files matched: {pattern}")
        return 1

    failures: list[str] = []
    rule_ids: Counter = Counter()

    for path in paths:
        text = Path(path).read_text(encoding="utf-8")
        problems = check_structure(text)
        # Rendering and evaluability read the parsed documents, so they are
        # only meaningful once the file is structurally sound.
        if not problems:
            problems = check_rendering(text) + check_evaluability(text)
            for document in parse_sigma_documents(text):
                if document.get("id"):
                    rule_ids[str(document["id"])] += 1

        documents = len(parse_sigma_documents(text))
        if problems:
            failures.extend(f"{path}: {problem}" for problem in problems)
            print(f"FAIL  {documents:2d} docs  {path}")
            for problem in problems:
                print(f"        {problem}")
        else:
            print(f"ok    {documents:2d} docs  {path}")

    for rule_id, count in sorted(rule_ids.items()):
        if count > 1:
            failures.append(f"rule id {rule_id} used {count} times across the corpus")

    failures.extend(check_filenames(paths))

    print()
    if failures:
        print(f"{len(failures)} problem(s) in {len(paths)} file(s):")
        for failure in failures:
            print(f"  x {failure}")
        return 1

    print(f"All {len(paths)} detection file(s) passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
