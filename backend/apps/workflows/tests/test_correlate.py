"""
Tests for matching SIEM alerts to the detections an emulation expects.

The cases that matter are the ones that keep a verdict honest. This feature
grades a client's own detection engineering, so a wrong verdict in either
direction ends the conversation: claiming their SIEM missed something it caught
is an accusation, and claiming it caught something it did not is a false
assurance about their coverage.
"""

from django.test import SimpleTestCase

from apps.workflows.correlate import (
    FIRED,
    MATCH_EXACT,
    MATCH_TECHNIQUE,
    SILENT,
    match_alerts,
    normalise_technique,
)

SIGMA_ID = "d0c9c024-a07e-51cf-9a04-9a3196cfc77c"

RULES = [
    {
        "ruleId": "t1098.001",
        "title": "IAM access key created for another user",
        "severity": "high",
        "technique": {"id": "T1098.001", "name": "Additional Cloud Credentials"},
        "sigmaIds": [SIGMA_ID],
    },
    {
        "ruleId": "t1552.005",
        "title": "Instance metadata credential theft",
        "severity": "critical",
        "technique": {"id": "T1552.005", "name": "Cloud Instance Metadata API"},
        "sigmaIds": ["11111111-2222-3333-4444-555555555555"],
    },
]


def alert(**overrides):
    """
    Build a normalised alert for a test case.

    Args:
        **overrides: Fields to replace on the default alert.

    Returns:
        An alert dict of the shape ingest.parse_alert produces, plus an id.
    """
    base = {
        "id": "alert-1",
        "ruleId": "",
        "ruleName": "",
        "technique": "",
        "severity": "",
        "firedAt": None,
        "receivedAt": "2026-09-10T06:12:00Z",
    }
    base.update(overrides)
    return base


class TechniqueNormalisationTests(SimpleTestCase):
    """Reading an ATT&CK id out of whatever a SIEM happens to send."""

    def test_the_common_spellings_all_reduce_to_one_id(self):
        """No two SIEMs agree on this, so all the shapes must land together."""
        for value in ("T1098.001", "attack.t1098.001", "MITRE T1098.001", "t1098.001"):
            self.assertEqual(normalise_technique(value), "T1098.001", value)

    def test_a_parent_technique_keeps_its_shape(self):
        """A rule mapping the parent must not be turned into a sub-technique."""
        self.assertEqual(normalise_technique("attack.t1059"), "T1059")

    def test_text_naming_no_technique_yields_nothing(self):
        """Absence must be empty, not a guess."""
        self.assertEqual(normalise_technique("Suspicious login detected"), "")
        self.assertEqual(normalise_technique(None), "")


class ExactMatchTests(SimpleTestCase):
    """The tier that is an identity rather than an inference."""

    def test_an_alert_naming_our_sigma_id_fires_that_rule(self):
        """The client deployed MayaTrail's rules, so the id is definitive."""
        result = match_alerts(RULES, [alert(ruleId=SIGMA_ID.upper())])
        self.assertEqual(result["rules"][0]["verdict"], FIRED)
        self.assertEqual(result["rules"][0]["matchTier"], MATCH_EXACT)

    def test_only_the_named_rule_fires(self):
        """One alert must not mark unrelated detections as working."""
        result = match_alerts(RULES, [alert(ruleId=SIGMA_ID)])
        self.assertEqual(result["rules"][1]["verdict"], SILENT)


class TechniqueMatchTests(SimpleTestCase):
    """The tier for a client running their own detections."""

    def test_an_alert_tagged_with_the_technique_fires_the_rule(self):
        """Their rule, not ours, but it covers the technique we attacked."""
        result = match_alerts(RULES, [alert(technique="attack.t1552.005", ruleName="IMDS theft")])
        self.assertEqual(result["rules"][1]["verdict"], FIRED)
        self.assertEqual(result["rules"][1]["matchTier"], MATCH_TECHNIQUE)

    def test_a_technique_named_only_in_the_rule_name_is_found(self):
        """Many teams put the id in the title rather than in a tag."""
        result = match_alerts(RULES, [alert(ruleName="Detects T1098.001 abuse")])
        self.assertEqual(result["rules"][0]["verdict"], FIRED)

    def test_an_exact_match_outranks_a_technique_match(self):
        """
        One rule reached two ways is reported once, at its strongest tier.

        Otherwise a report would claim more evidence than it has.
        """
        result = match_alerts(RULES, [
            alert(id="a", technique="T1098.001"),
            alert(id="b", ruleId=SIGMA_ID),
        ])
        self.assertEqual(result["rules"][0]["matchTier"], MATCH_EXACT)
        self.assertEqual(result["rules"][0]["evidence"]["alertId"], "b")


class SilenceAndNoiseTests(SimpleTestCase):
    """What happens when alerts and expectations do not line up."""

    def test_no_alerts_leaves_every_rule_silent(self):
        """Silence is a real verdict here, distinct from never being exercised."""
        result = match_alerts(RULES, [])
        self.assertTrue(all(r["verdict"] == SILENT for r in result["rules"]))
        self.assertEqual(result["unmatched"], [])

    def test_an_unrelated_alert_is_reported_but_never_counted(self):
        """
        A client's SIEM also fires on real activity during the window.

        Showing it lets a reader judge; counting it would inflate their score
        with something that has nothing to do with the attack.
        """
        result = match_alerts(RULES, [alert(id="x", ruleName="Impossible travel")])
        self.assertTrue(all(r["verdict"] == SILENT for r in result["rules"]))
        self.assertEqual(len(result["unmatched"]), 1)
        self.assertEqual(result["unmatched"][0]["alertId"], "x")

    def test_a_matched_alert_is_not_also_reported_as_unattributed(self):
        """An alert belongs in one place, or the totals stop adding up."""
        result = match_alerts(RULES, [alert(id="y", ruleId=SIGMA_ID)])
        self.assertEqual(result["unmatched"], [])

    def test_every_verdict_carries_its_evidence(self):
        """A claim about someone's detections must be traceable to the alert."""
        result = match_alerts(RULES, [alert(id="z", ruleId=SIGMA_ID, ruleName="Ours")])
        evidence = result["rules"][0]["evidence"]
        self.assertEqual(evidence["alertId"], "z")
        self.assertEqual(evidence["ruleName"], "Ours")
        self.assertIsNone(result["rules"][1]["evidence"])
