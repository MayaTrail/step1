"""
Tests for guardrail-to-emulation matching.

The assertions worth having are about what the matcher refuses to claim. A
policy reported as blocking when a Condition actually decides tells a customer
they are protected on the strength of something nobody evaluated, and an
unanalysed emulation reported as "no policy applies" reads as "nothing can stop
this". Both are false assurance, which is the failure this feature exists to
avoid.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.guardrails.matching import (
    BLOCKS,
    BLOCKS_CONDITIONAL,
    BROAD,
    TARGETED,
    UNRELATED,
    action_matches,
    analyse,
    emulation_actions,
    match_policy,
)


def _policy(*statements):
    """Build a policy document around the given statements."""
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _deny(actions, condition=None):
    """A Deny statement, optionally conditional."""
    statement = {"Effect": "Deny", "Action": actions, "Resource": "*"}
    if condition:
        statement["Condition"] = condition
    return statement


ORG_CONDITION = {"StringNotEquals": {"aws:PrincipalOrgID": "o-example"}}


class ActionMatchTests(SimpleTestCase):
    """Wildcards and case, because IAM is generous about both."""

    def test_exact(self):
        self.assertTrue(action_matches("s3:PutObject", "s3:PutObject"))

    def test_case_insensitive(self):
        """IAM action names are not case sensitive; a corpus mixes them."""
        self.assertTrue(action_matches("S3:PUTOBJECT", "s3:PutObject"))

    def test_prefix_wildcard(self):
        self.assertTrue(action_matches("s3:Put*", "s3:PutBucketVersioning"))

    def test_service_wildcard(self):
        self.assertTrue(action_matches("s3:*", "s3:DeleteObjectVersion"))

    def test_a_different_service_does_not_match(self):
        self.assertFalse(action_matches("ec2:*", "s3:PutObject"))

    def test_a_narrower_pattern_does_not_match_a_wider_action(self):
        self.assertFalse(action_matches("s3:PutObjectAcl", "s3:PutObject"))


class PolicyVerdictTests(SimpleTestCase):
    """The three-valued verdict."""

    def test_unconditional_deny_blocks(self):
        result = match_policy(_policy(_deny("s3:PutBucketVersioning")), ["s3:PutBucketVersioning"])
        self.assertEqual(result["verdict"], BLOCKS)
        self.assertEqual(result["actions"], ["s3:PutBucketVersioning"])

    def test_a_condition_downgrades_to_conditional(self):
        """The customer's org decides, so we must not claim it blocks."""
        result = match_policy(
            _policy(_deny("s3:PutBucketVersioning", ORG_CONDITION)),
            ["s3:PutBucketVersioning"],
        )
        self.assertEqual(result["verdict"], BLOCKS_CONDITIONAL)
        self.assertEqual(result["conditionKeys"], ["aws:PrincipalOrgID"])

    def test_allow_is_never_protection(self):
        """Only a Deny prevents anything."""
        statement = {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}
        self.assertEqual(
            match_policy(_policy(statement), ["s3:PutObject"])["verdict"], UNRELATED
        )

    def test_not_action_is_skipped_rather_than_guessed(self):
        """
        A Deny on NotAction denies everything except what it lists. Reading the
        list as coverage would invert the policy's meaning.
        """
        statement = {"Effect": "Deny", "NotAction": "s3:GetObject", "Resource": "*"}
        self.assertEqual(
            match_policy(_policy(statement), ["s3:GetObject"])["verdict"], UNRELATED
        )

    def test_a_bare_star_is_not_reported(self):
        """True of every emulation, useful against none."""
        self.assertEqual(
            match_policy(_policy(_deny("*")), ["s3:PutObject"])["verdict"], UNRELATED
        )

    def test_unrelated_service(self):
        self.assertEqual(
            match_policy(_policy(_deny("ec2:RunInstances")), ["s3:PutObject"])["verdict"],
            UNRELATED,
        )

    def test_the_strongest_statement_wins(self):
        """An unconditional Deny anywhere beats a conditional one."""
        document = _policy(
            _deny("s3:PutObject", ORG_CONDITION),
            _deny("s3:PutBucketVersioning"),
        )
        result = match_policy(document, ["s3:PutObject", "s3:PutBucketVersioning"])
        self.assertEqual(result["verdict"], BLOCKS)
        self.assertEqual(result["actions"], ["s3:PutBucketVersioning", "s3:PutObject"])

    def test_a_single_statement_object_is_handled(self):
        """Some corpus policies carry one Statement dict rather than a list."""
        document = {"Statement": _deny("s3:PutObject")}
        self.assertEqual(match_policy(document, ["s3:PutObject"])["verdict"], BLOCKS)


class ScopeTests(SimpleTestCase):
    """
    Specificity, which decides ranking.

    A policy naming the action is a more precise answer than one that happened
    to include it through a service-wide wildcard.
    """

    def test_a_named_action_is_targeted(self):
        result = match_policy(_policy(_deny("s3:PutObject")), ["s3:PutObject"])
        self.assertEqual(result["scope"], TARGETED)

    def test_a_service_wildcard_is_broad(self):
        result = match_policy(_policy(_deny("s3:*")), ["s3:PutObject"])
        self.assertEqual(result["scope"], BROAD)

    def test_a_prefix_wildcard_is_still_targeted(self):
        """"s3:Put*" selects a family of actions, not the whole service."""
        result = match_policy(_policy(_deny("s3:Put*")), ["s3:PutObject"])
        self.assertEqual(result["scope"], TARGETED)

    def test_any_named_pattern_makes_the_policy_targeted(self):
        """A policy that names the action is targeted even alongside a wildcard."""
        document = _policy(_deny(["s3:*", "s3:PutObject"]))
        self.assertEqual(match_policy(document, ["s3:PutObject"])["scope"], TARGETED)


class EmulationActionTests(SimpleTestCase):
    """Reading actions off an attack path."""

    def test_collects_and_deduplicates(self):
        path = [
            {"phase": 1, "aws_actions": ["s3:GetObject", "sts:GetCallerIdentity"]},
            {"phase": 2, "aws_actions": ["s3:GetObject", "s3:ListBucket"]},
        ]
        self.assertEqual(
            emulation_actions(path),
            ["s3:GetObject", "s3:ListBucket", "sts:GetCallerIdentity"],
        )

    def test_an_unannotated_path_yields_nothing(self):
        self.assertEqual(emulation_actions([{"phase": 1, "techniques": []}]), [])


class AnalyseTests(SimpleTestCase):
    """The assembled payload."""

    def setUp(self):
        self.path = [
            {"phase": 1, "name": "Access", "aws_actions": ["s3:GetObject"]},
            {"phase": 5, "name": "Purge", "aws_actions": ["s3:PutBucketVersioning"]},
        ]
        self.catalogue = [
            {
                "id": "deny-versioning",
                "purpose": "Deny suspending bucket versioning",
                "type": "SCP",
                "source": {},
                "code": _policy(_deny("s3:PutBucketVersioning")),
            },
            {
                "id": "org-perimeter",
                "purpose": "Only allow requests from your org",
                "type": "RCP",
                "source": {},
                "code": _policy(_deny("s3:GetObject", ORG_CONDITION)),
            },
            {
                "id": "ec2-only",
                "purpose": "Deny expensive instances",
                "type": "SCP",
                "source": {},
                "code": _policy(_deny("ec2:RunInstances")),
            },
        ]

    def test_unrelated_policies_are_dropped(self):
        result = analyse(self.path, self.catalogue)
        self.assertEqual([p["id"] for p in result["policies"]], ["deny-versioning", "org-perimeter"])

    def test_blocking_policies_lead(self):
        """The rows somebody opened this for come first."""
        result = analyse(self.path, self.catalogue)
        self.assertEqual(result["policies"][0]["verdict"], BLOCKS)

    def test_a_targeted_policy_outranks_a_broad_one(self):
        """
        Sorting on the most actions matched put the policy naming codefinger's
        exact ransom mechanism last, behind perimeter policies that matched
        everything by denying "s3:*". Specificity is the signal.
        """
        catalogue = [
            {"id": "perimeter", "purpose": "p", "type": "RCP", "source": {},
             "code": _policy(_deny("s3:*", ORG_CONDITION))},
            {"id": "named", "purpose": "p", "type": "RCP", "source": {},
             "code": _policy(_deny("s3:PutBucketVersioning", ORG_CONDITION))},
        ]
        order = [p["id"] for p in analyse(self.path, catalogue)["policies"]]
        self.assertEqual(order, ["named", "perimeter"])

    def test_a_broad_match_asserts_no_phases(self):
        """
        A policy denying "s3:*" touches every phase of an S3 attack. Listing
        them restates the wildcard and reads as analysis it has not done.
        """
        catalogue = [{"id": "perimeter", "purpose": "p", "type": "RCP", "source": {},
                      "code": _policy(_deny("s3:*", ORG_CONDITION))}]
        result = analyse(self.path, catalogue)
        self.assertEqual(result["policies"][0]["scope"], BROAD)
        self.assertEqual(result["policies"][0]["phases"], [])

    def test_counts_separate_targeted_from_broad(self):
        """The page collapses broad matches into one row, so it needs the split."""
        counts = analyse(self.path, self.catalogue)["counts"]
        self.assertEqual(counts[TARGETED] + counts[BROAD], len(analyse(self.path, self.catalogue)["policies"]))

    def test_counts_separate_the_two_verdicts(self):
        counts = analyse(self.path, self.catalogue)["counts"]
        self.assertEqual(counts[BLOCKS], 1)
        self.assertEqual(counts[BLOCKS_CONDITIONAL], 1)

    def test_a_policy_names_the_phases_it_interrupts(self):
        result = analyse(self.path, self.catalogue)
        blocking = next(p for p in result["policies"] if p["id"] == "deny-versioning")
        self.assertEqual(blocking["phases"], [5])

    def test_phase_rows_only_credit_unconditional_blocks(self):
        """
        A conditional policy must not be listed as blocking a phase: whether it
        does depends on the reader's organisation.
        """
        rows = {row["phase"]: row for row in analyse(self.path, self.catalogue)["phases"]}
        self.assertEqual(rows[5]["blockedBy"], ["deny-versioning"])
        self.assertEqual(rows[1]["blockedBy"], [])

    def test_an_unannotated_emulation_is_not_analysed(self):
        """
        Not the same as "no policy applies". A reader shown an empty list would
        conclude nothing can stop this attack.
        """
        result = analyse([{"phase": 1, "techniques": []}], self.catalogue)
        self.assertFalse(result["analysed"])
        self.assertEqual(result["policies"], [])
        self.assertEqual(result["counts"][BLOCKS], 0)

    def test_malformed_policy_json_is_skipped_not_fatal(self):
        """One bad document in the corpus must not take the page down."""
        catalogue = self.catalogue + [{"id": "broken", "code": "{not json"}]
        result = analyse(self.path, catalogue)
        self.assertNotIn("broken", [p["id"] for p in result["policies"]])

    def test_a_json_string_body_is_parsed(self):
        """The registry hands policy bodies over as raw JSON text."""
        import json

        catalogue = [{
            "id": "as-text",
            "purpose": "x",
            "type": "SCP",
            "source": {},
            "code": json.dumps(_policy(_deny("s3:PutBucketVersioning"))),
        }]
        result = analyse(self.path, catalogue)
        self.assertEqual(result["policies"][0]["verdict"], BLOCKS)


class CodefingerCorpusTests(SimpleTestCase):
    """
    The one emulation annotated so far, against the real shipped catalogue.

    Guards the annotation as much as the matcher: if codefinger's aws_actions
    were dropped or misspelled, the analysis would quietly report nothing.
    """

    def setUp(self):
        from apps.emulations.registry import get_emulation
        from apps.guardrails.registry import list_guardrails

        entry = get_emulation("codefinger") or {}
        self.manifest = entry.get("manifest", entry) or {}
        self.result = analyse(self.manifest.get("attack_path") or [], list_guardrails())

    def test_codefinger_is_annotated(self):
        self.assertTrue(self.result["analysed"])
        self.assertIn("s3:PutBucketVersioning", self.result["actions"])

    def test_every_phase_declares_actions(self):
        for row in self.result["phases"]:
            self.assertTrue(row["actions"], f"phase {row['phase']} declares no actions")

    def test_the_real_catalogue_produces_a_verdict(self):
        """A shipped corpus that matched nothing would mean a broken matcher."""
        self.assertTrue(self.result["policies"])
