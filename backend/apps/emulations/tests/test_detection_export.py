"""
Tests for compiling shipped Sigma rules into SIEM dialects.

The conversion itself belongs to pySigma; what is tested here is the bundling
around it - that nothing is dropped silently, that the two identifier spaces
stay separate, and that a run's verdicts select the right rules.

Tests needing a compiler backend skip when pySigma is absent, the same way
test_every_rule_passes_the_validator does.
"""

from __future__ import annotations

import unittest

from django.test import SimpleTestCase

from apps.emulations.detection_export import (
    ExportBundle,
    bundle_to_text,
    export_rules,
    rules_with_verdict,
    target_catalogue,
)
from apps.emulations.registry import get_emulation
from apps.emulations.sigma_convert import available_targets

HAVE_BACKEND = bool(available_targets())
AMBERSQUID = get_emulation("ambersquid")
HAVE_PACKAGES = AMBERSQUID is not None


class TargetCatalogueTests(SimpleTestCase):
    """What the deployment advertises."""

    def test_every_target_is_listed_with_an_installed_flag(self):
        """
        Targets are reported, not filtered.

        A UI that hides Splunk when the backend is missing leaves an operator
        unable to tell "unsupported" from "this server is misconfigured".
        """
        catalogue = target_catalogue()
        names = {t["name"] for t in catalogue}
        self.assertEqual(names, {"splunk", "opensearch"})
        for target in catalogue:
            self.assertIn("installed", target)
            self.assertIn("install", target)  # the pip name that fixes it
            self.assertTrue(target["label"])

    def test_wazuh_is_described_as_the_indexer(self):
        """
        The OpenSearch backend emits Lucene for the Wazuh *indexer*, not native
        Wazuh XML rules. Someone expecting <rule> blocks for ossec.conf must be
        able to see that from the label alone.
        """
        opensearch = next(t for t in target_catalogue() if t["name"] == "opensearch")
        self.assertIn("Indexer", opensearch["label"])


class RulesWithVerdictTests(SimpleTestCase):
    """Selecting a run's rules by verdict."""

    CHECK = {
        "status": "ok",
        "rules": [
            {"ruleId": "t1078", "verdict": "fired"},
            {"ruleId": "t1070", "verdict": "silent"},
            {"ruleId": "t1496", "verdict": "silent"},
            {"ruleId": "t1525", "verdict": "no_logs"},
        ],
    }

    def test_selects_only_the_requested_verdicts(self):
        """Silent is the default case the run result links to."""
        self.assertEqual(rules_with_verdict(self.CHECK, {"silent"}), ["t1070", "t1496"])

    def test_accepts_several_verdicts(self):
        """A caller may ask for more than one."""
        self.assertEqual(
            rules_with_verdict(self.CHECK, {"silent", "no_logs"}),
            ["t1070", "t1496", "t1525"],
        )

    def test_incomplete_check_yields_nothing(self):
        """
        A run whose detection check never completed has no verdicts to act on.

        Returning [] rather than guessing keeps the caller's 404 honest: there
        is nothing to export, as opposed to an empty export being correct.
        """
        self.assertEqual(rules_with_verdict(None, {"silent"}), [])
        self.assertEqual(rules_with_verdict({"status": "error"}, {"silent"}), [])
        self.assertEqual(rules_with_verdict({"status": "ok"}, {"silent"}), [])

    def test_ignores_rules_with_no_id(self):
        """A malformed entry is skipped rather than exported as an empty id."""
        check = {"status": "ok", "rules": [{"verdict": "silent"}, {"ruleId": "", "verdict": "silent"}]}
        self.assertEqual(rules_with_verdict(check, {"silent"}), [])


class BundleTextTests(SimpleTestCase):
    """The downloadable file."""

    def _bundle(self, **kw) -> ExportBundle:
        return ExportBundle(
            target="splunk",
            label="Splunk (SPL)",
            output_format="default",
            emulation_type="ambersquid",
            **kw,
        )

    def test_skipped_rules_are_named_in_the_file(self):
        """
        A bundle that quietly omitted rules would be worse than useless: the
        engineer deploys it believing they have coverage they do not have.
        """
        bundle = self._bundle(
            queries=[{"ruleId": "t1070", "sigmaId": "abc", "title": "T", "query": "q"}],
            skipped=[{"ruleId": "t1525", "sigmaId": "", "title": "S", "reason": "no correlation support"}],
        )
        text = bundle_to_text(bundle)
        self.assertIn("NOT INCLUDED", text)
        self.assertIn("t1525", text)
        self.assertIn("no correlation support", text)

    def test_missing_rules_are_named_in_the_file(self):
        """Asked-for rules the catalogue lacks are reported, not ignored."""
        text = bundle_to_text(self._bundle(missing=["t1496"]))
        self.assertIn("NOT FOUND", text)
        self.assertIn("t1496", text)

    def test_each_query_is_traceable_to_its_rule(self):
        """A query pasted into a SIEM must still say where it came from."""
        bundle = self._bundle(
            queries=[{"ruleId": "t1070", "sigmaId": "uuid-1", "title": "Logging disabled", "query": "index=x"}]
        )
        text = bundle_to_text(bundle)
        self.assertIn("Logging disabled", text)
        self.assertIn("t1070 / uuid-1", text)
        self.assertIn("index=x", text)

    def test_note_reaches_the_header(self):
        """The run export explains what the file is; that must survive."""
        text = bundle_to_text(self._bundle(), note="Rules this run judged silent.")
        self.assertIn("Rules this run judged silent.", text)


@unittest.skipUnless(HAVE_PACKAGES, "emulation packages not available")
@unittest.skipUnless(HAVE_BACKEND, "no pySigma backend installed")
class ExportRulesTests(SimpleTestCase):
    """Compiling real shipped rules."""

    def test_ambersquid_compiles_for_every_installed_target(self):
        """
        The shipped corpus must survive a real compile for each target we
        advertise. A rule that stops converting is a customer-visible break.
        """
        from apps.emulations.detections import list_detection_summaries

        rule_ids = [
            s["ruleId"]
            for s in list_detection_summaries(AMBERSQUID)
            if s.get("formats", {}).get("sigma")
        ]
        self.assertTrue(rule_ids, "ambersquid should ship Sigma rules")

        for target in available_targets():
            with self.subTest(target=target):
                bundle = export_rules(AMBERSQUID, rule_ids, target)
                self.assertEqual(bundle.missing, [])
                self.assertTrue(bundle.queries, f"{target} produced no queries")
                self.assertTrue(all(q["query"].strip() for q in bundle.queries))

    def test_unknown_rule_is_missing_not_skipped(self):
        """
        'The catalogue has no such rule' and 'this backend cannot express it'
        are different problems with different fixes, so they are different
        fields.
        """
        target = available_targets()[0]
        bundle = export_rules(AMBERSQUID, ["definitely-not-a-rule"], target)
        self.assertEqual(bundle.missing, ["definitely-not-a-rule"])
        self.assertEqual(bundle.skipped, [])
        self.assertEqual(bundle.queries, [])

    def test_identifiers_do_not_collide(self):
        """
        ruleId is the technique key the caller asked for; sigmaId is the rule
        document's own UUID. One file may hold several rules, so the requested
        id has to survive on every query it produced.
        """
        target = available_targets()[0]
        bundle = export_rules(AMBERSQUID, ["t1070"], target)
        self.assertTrue(bundle.queries)
        for query in bundle.queries:
            self.assertEqual(query["ruleId"], "t1070")
            self.assertNotEqual(query["sigmaId"], "t1070")


# Importing apps.emulations.urls pulls in apps.emulations.views, which imports
# apps.logs.models. That app is not in the minimal CI settings (the same reason
# config.ci_urls is empty), so these route tests can only run under the full
# settings. They skip in the fast CI job and run under config.settings.local.
from django.apps import apps as _django_apps  # noqa: E402

_ROUTES_IMPORTABLE = _django_apps.is_installed("apps.logs")


@unittest.skipUnless(_ROUTES_IMPORTABLE, "full app registry not loaded (CI settings)")
class ExportRouteResolutionTests(SimpleTestCase):
    """
    URL ordering, which is load-bearing here and easy to break silently.

    Three patterns overlap on this prefix, and a wrong order still resolves - to
    the wrong view, with a confusing 404. Checked against the app's own
    urlpatterns rather than the global resolver, because even under full
    settings the root urlconf reaches the whole runtime stack.
    """

    def _resolve(self, path: str):
        """Resolve a path against the emulations app's own patterns."""
        from django.urls import Resolver404, URLResolver
        from django.urls.resolvers import RegexPattern

        from apps.emulations import urls as emu_urls

        resolver = URLResolver(RegexPattern(r"^api/emulations/"), emu_urls.urlpatterns)
        try:
            return resolver.resolve(path)
        except Resolver404:
            return None

    def test_run_export_is_not_captured_by_the_emulation_route(self):
        """
        <str:emulation_type> matches a UUID perfectly well. Declared before the
        uuid route it swallows every run export, which then 404s with
        "unknown emulation <uuid>".
        """
        match = self._resolve(
            "api/emulations/c4313b27-51fa-4b5f-b6a0-01613d94028d/detections/export/"
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.url_name, "run-detection-export")

    def test_emulation_export_still_resolves(self):
        """The uuid route must not shadow a real emulation name."""
        match = self._resolve("api/emulations/ambersquid/detections/export/")
        self.assertIsNotNone(match)
        self.assertEqual(match.url_name, "emulation-detection-export")

    def test_export_is_not_parsed_as_a_rule_id(self):
        """<str:rule_id> would happily match the literal "export"."""
        match = self._resolve("api/emulations/ambersquid/detections/export/")
        self.assertIsNotNone(match)
        self.assertNotEqual(match.url_name, "emulation-detection-detail")

    def test_a_real_rule_id_still_resolves(self):
        """And the rule detail route must keep working."""
        match = self._resolve("api/emulations/ambersquid/detections/t1070/")
        self.assertIsNotNone(match)
        self.assertEqual(match.url_name, "emulation-detection-detail")
