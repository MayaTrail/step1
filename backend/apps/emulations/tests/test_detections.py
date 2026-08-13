"""
Tests for detection rule parsing and the shipped rule corpus.

Two layers, mirroring test_readiness.py:

  * Unit tests for parse_sigma / parse_sigma_documents covering the
    multi-document shape, which is how every correlation-based rule ships.
  * A corpus test that folds the validation checks over every Sigma file the
    repository ships, so a rule that parses but cannot render or cannot be
    evaluated fails at PR time rather than as a blank detail page.

The corpus layer imports backend/scripts/validate_detections.py so the checks
have a single implementation and the local gate cannot drift from CI.

Two CI jobs share that implementation and install different dependencies:

  * backend-tests runs this module from requirements-test.txt, which has no
    pySigma. test_every_rule_passes_the_validator therefore SKIPS here by
    design, and the skip is expected in the job log.
  * validate-detections runs the script directly from requirements-dev.txt,
    which does have pySigma, and covers the structural checks in full plus
    corpus-wide id uniqueness and the filename convention.

To run the structural check locally alongside the rest of the suite, install
both files: pip install -r requirements-test.txt -r requirements-dev.txt
"""

import glob
import importlib.util
import os
from pathlib import Path

from django.test import SimpleTestCase

from apps.emulations.detections import parse_sigma, parse_sigma_documents

# backend/apps/emulations/tests/test_detections.py -> repo root is parents[4].
_REPO_ROOT = Path(__file__).resolve().parents[4]
_FALLBACK_EMULATIONS_DIR = _REPO_ROOT / "emulations"


def _resolve_emulations_dir() -> Path:
    """Prefer EMULATIONS_BASE_DIR (Docker); fall back to the repo emulations/ dir."""
    env_dir = os.environ.get("EMULATIONS_BASE_DIR", "")
    if env_dir and Path(env_dir).is_dir():
        return Path(env_dir)
    return _FALLBACK_EMULATIONS_DIR


_SIGMA_GLOB = str(_resolve_emulations_dir() / "*" / "detections" / "sigma_*.yml")

_SINGLE_DOCUMENT = """
title: Single rule
id: 11111111-1111-4111-8111-111111111111
level: high
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: 'CreateAccessKey'
  condition: selection
"""

_MULTI_DOCUMENT = """
title: Base rule
id: 22222222-2222-4222-8222-222222222222
name: base_rule
level: low
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: 'GetPasswordData'
  condition: selection
---
title: The real detection
id: 33333333-3333-4333-8333-333333333333
level: high
correlation:
  type: event_count
  rules:
    - base_rule
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gt: 3
"""


def _load_validator():
    """Import backend/scripts/validate_detections.py by path, or None if pySigma is absent."""
    if importlib.util.find_spec("sigma") is None:
        return None
    path = _REPO_ROOT / "backend" / "scripts" / "validate_detections.py"
    spec = importlib.util.spec_from_file_location("validate_detections", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ParseSigmaTests(SimpleTestCase):
    """parse_sigma flattens a rule file into the metadata the detail view reads."""

    def test_single_document_is_returned_unchanged(self):
        parsed = parse_sigma(_SINGLE_DOCUMENT)
        self.assertEqual(parsed["title"], "Single rule")
        self.assertEqual(parsed["level"], "high")

    def test_multi_document_does_not_return_empty(self):
        # yaml.safe_load raises on a multi-document stream. Returning {} here
        # blanked the severity, title and tags of 27 shipped rules.
        self.assertNotEqual(parse_sigma(_MULTI_DOCUMENT), {})

    def test_multi_document_takes_highest_severity(self):
        parsed = parse_sigma(_MULTI_DOCUMENT)
        self.assertEqual(parsed["level"], "high")
        self.assertEqual(parsed["title"], "The real detection")

    def test_missing_field_falls_back_to_another_document(self):
        # The correlation document carries no logsource of its own.
        self.assertEqual(
            parse_sigma(_MULTI_DOCUMENT)["logsource"],
            {"product": "aws", "service": "cloudtrail"},
        )

    def test_invalid_yaml_returns_empty(self):
        self.assertEqual(parse_sigma("title: [unclosed"), {})

    def test_documents_are_all_returned(self):
        self.assertEqual(len(parse_sigma_documents(_MULTI_DOCUMENT)), 2)
        self.assertEqual(len(parse_sigma_documents(_SINGLE_DOCUMENT)), 1)


class ShippedDetectionsTests(SimpleTestCase):
    """Every Sigma file in the repository is structurally sound and renderable."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.paths = sorted(glob.glob(_SIGMA_GLOB))
        cls.validator = _load_validator()

    def test_at_least_one_rule_discovered(self):
        self.assertGreater(
            len(self.paths),
            0,
            "No Sigma rules discovered, corpus validation would be meaningless",
        )

    def test_every_rule_renders(self):
        problems: list[str] = []
        for path in self.paths:
            text = Path(path).read_text(encoding="utf-8")
            parsed = parse_sigma(text)
            for field in ("title", "level", "logsource"):
                if not parsed.get(field):
                    problems.append(f"{path}: parse_sigma yields no {field}")

        self.assertEqual(
            problems,
            [],
            "Rule(s) would render with missing metadata:\n  - " + "\n  - ".join(problems),
        )

    def test_every_rule_passes_the_validator(self):
        if self.validator is None:
            self.skipTest(
                "no pySigma: expected under requirements-test.txt, where the "
                "validate-detections job covers this. Add requirements-dev.txt to run it here."
            )

        problems: list[str] = []
        for path in self.paths:
            text = Path(path).read_text(encoding="utf-8")
            structural = self.validator.check_structure(text)
            problems.extend(f"{path}: {problem}" for problem in structural)
            if not structural:
                problems.extend(
                    f"{path}: {problem}" for problem in self.validator.check_evaluability(text)
                )

        self.assertEqual(
            problems,
            [],
            "Rule(s) failed validation:\n  - " + "\n  - ".join(problems),
        )
