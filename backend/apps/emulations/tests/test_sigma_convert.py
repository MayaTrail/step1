"""
Tests for compiling Sigma rules into a customer's SIEM query language.

Mirrors the two layers of test_detections.py:

  * Unit tests for sigma_convert covering the fallback path, which is where the
    interesting behaviour lives. A file whose correlation a backend cannot
    express must still yield its base rules, and must say which rule it dropped
    and why.
  * A corpus test asserting every shipped rule compiles for every installed
    target, so a rule that stops compiling fails at PR time rather than in a
    customer's Splunk.

Like test_detections.py, these skip when the backends are absent. Two CI jobs
install different dependencies: backend-tests runs from requirements-test.txt,
which has neither pySigma nor the backends, so everything here skips by design;
validate-detections installs requirements-dev.txt and covers it in full.

    pip install -r requirements-test.txt -r requirements-dev.txt

runs the whole thing locally.
"""

import glob
import os
from pathlib import Path

from django.test import SimpleTestCase

from apps.emulations.sigma_convert import TARGETS, available_targets, convert

# backend/apps/emulations/tests/test_sigma_convert.py -> repo root is parents[4].
def _resolve_emulations_dir() -> Path:
    """
    Prefer EMULATIONS_BASE_DIR (what Docker sets); fall back to the repo dir.

    The container mounts the packages at /opt/emulations while the code lives at
    /app, so a path derived only from __file__ finds nothing there and every
    test that reads a shipped rule fails on a missing fixture rather than on
    anything it was written to check.
    """
    env_dir = os.environ.get("EMULATIONS_BASE_DIR", "")
    if env_dir and Path(env_dir).is_dir():
        return Path(env_dir)
    return Path(__file__).resolve().parents[4] / "emulations"


_SIGMA_GLOB = str(_resolve_emulations_dir() / "*" / "detections" / "sigma_*.yml")

_PLAIN_RULE = """
title: S3 bucket listing
id: 6f1a2b30-0000-4000-8000-000000000001
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 's3.amazonaws.com'
    eventName: 'ListBuckets'
  condition: selection
level: low
"""

# A base rule plus a correlation over it. temporal_ordered is the one type the
# Splunk backend does not implement and the OpenSearch backend, which supports
# no correlations at all, cannot express either.
_UNSUPPORTED_CORRELATION = """
title: IAM role created
id: 6f1a2b30-0000-4000-8000-000000000002
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: 'CreateRole'
  condition: selection
level: medium
---
title: Role created then immediately assumed
id: 6f1a2b30-0000-4000-8000-000000000003
status: experimental
correlation:
  type: temporal_ordered
  rules:
    - 6f1a2b30-0000-4000-8000-000000000002
  timespan: 10m
"""

# A correlation the Splunk backend *does* implement. It folds the base rule into
# its own query, so the compiled output is shorter than the base-only output.
# Isolating it by slicing on query count therefore reports a false negative;
# this file is the regression guard for that.
_FOLDING_CORRELATION = """
title: GetPasswordData called
id: 6f1a2b30-0000-4000-8000-000000000004
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: 'GetPasswordData'
  condition: selection
level: medium
---
title: GetPasswordData burst from one principal
id: 6f1a2b30-0000-4000-8000-000000000005
status: experimental
correlation:
  type: event_count
  rules:
    - 6f1a2b30-0000-4000-8000-000000000004
  group-by:
    - userIdentity.arn
  timespan: 10m
  condition:
    gt: 3
"""


def _installed(target):
    """Skip reason when a target's backend is not installed, else None."""
    if target in available_targets():
        return None
    return f"{TARGETS[target].install} is not installed; validate-detections covers this"


class ConvertUnitTests(SimpleTestCase):
    """Compiling one file, including the paths a backend cannot fully express."""

    def test_plain_rule_compiles_for_every_installed_target(self):
        targets = available_targets()
        if not targets:
            self.skipTest("no pySigma backends installed")
        for target in targets:
            with self.subTest(target=target):
                result = convert(_PLAIN_RULE, target)
                self.assertTrue(result.ok, result.error)
                self.assertEqual(len(result.queries), 1)
                self.assertIn("ListBuckets", result.queries[0].query)

    def test_query_carries_the_rule_title(self):
        if reason := _installed("splunk"):
            self.skipTest(reason)
        result = convert(_PLAIN_RULE, "splunk")
        self.assertEqual(result.queries[0].title, "S3 bucket listing")
        self.assertEqual(result.queries[0].rule_id, "6f1a2b30-0000-4000-8000-000000000001")

    def test_unsupported_correlation_is_skipped_not_fatal(self):
        # The base rule is the only coverage this target can offer, so losing
        # the whole file to one inexpressible correlation would be a regression.
        if reason := _installed("splunk"):
            self.skipTest(reason)
        result = convert(_UNSUPPORTED_CORRELATION, "splunk")
        self.assertTrue(result.ok, result.error)
        self.assertEqual([q.title for q in result.queries], ["IAM role created"])
        self.assertEqual(len(result.skipped), 1)
        self.assertEqual(result.skipped[0].title, "Role created then immediately assumed")
        self.assertIn("temporal_ordered", result.skipped[0].reason)

    def test_folding_correlation_is_not_reported_as_unsupported(self):
        # Regression: a correlation folds the base rules it references into its
        # own query, so the compiled output is *shorter* than the base-only
        # output. Isolating it positionally yielded an empty slice and reported
        # a supported correlation as inexpressible.
        if reason := _installed("splunk"):
            self.skipTest(reason)
        result = convert(_FOLDING_CORRELATION, "splunk")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.skipped, [])
        self.assertTrue(
            any("stats" in q.query for q in result.queries),
            "the event_count correlation should have produced an aggregating query",
        )

    def test_unknown_target_raises(self):
        with self.assertRaises(KeyError):
            convert(_PLAIN_RULE, "not-a-siem")

    def test_malformed_yaml_is_an_error_not_an_exception(self):
        if not available_targets():
            self.skipTest("no pySigma backends installed")
        result = convert("title: [unclosed", available_targets()[0])
        self.assertFalse(result.ok)
        self.assertIn("YAML", result.error)


class ShippedRulesCompileTests(SimpleTestCase):
    """Every rule the repository ships compiles for every installed target."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.paths = sorted(glob.glob(_SIGMA_GLOB))

    def test_every_shipped_rule_compiles(self):
        targets = available_targets()
        if not targets:
            self.skipTest(
                "no pySigma backends: expected under requirements-test.txt, where the "
                "validate-detections job covers this. Add requirements-dev.txt to run it here."
            )
        self.assertGreater(len(self.paths), 0, "no Sigma rules discovered")

        problems: list[str] = []
        for path in self.paths:
            text = Path(path).read_text(encoding="utf-8")
            for target in targets:
                result = convert(text, target)
                if not result.ok:
                    problems.append(f"{path} [{target}]: {result.error}")
                elif not result.queries:
                    problems.append(f"{path} [{target}]: compiled but produced no query")

        self.assertEqual(
            problems,
            [],
            "Rule(s) no longer compile:\n  - " + "\n  - ".join(problems),
        )
